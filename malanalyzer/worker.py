import asyncio
import contextlib
import logging
import shutil
import signal
import uuid
from pathlib import Path

from pydantic import ValidationError

from malanalyzer.analyzer import OpenCodeAnalyzer
from malanalyzer.config import Settings
from malanalyzer.models import Job
from malanalyzer.process import ProcessError
from malanalyzer.store import Store

logger = logging.getLogger(__name__)


def safe_error(exc: BaseException) -> str:
    if isinstance(exc, BaseExceptionGroup):
        return safe_error(exc.exceptions[0])
    if isinstance(exc, ProcessError):
        return str(exc)
    if isinstance(exc, TimeoutError):
        return "Analysis timed out; check worker timeouts and model response latency."
    if isinstance(exc, ValidationError):
        return "The analysis did not produce a valid Markdown report."
    return "Analysis failed. Check Mistral credentials, model availability, OpenCode installation, and worker configuration."


class Worker:
    def __init__(self, settings: Settings, store: Store, analyzer=None):
        self.settings = settings
        self.store = store
        self.analyzer = analyzer or OpenCodeAnalyzer(settings)

    async def _heartbeat(self, job: Job, owner: str, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.settings.lease_seconds / 3)
            except TimeoutError:
                alive = await asyncio.to_thread(
                    self.store.heartbeat, job.id, owner, self.settings.lease_seconds,
                )
                if not alive:
                    raise RuntimeError("Analysis lease lost.") from None

    async def _analyze(self, job: Job, owner: str, run_dir: Path) -> None:
        sample = self.settings.root / "samples" / job.sha256
        async def progress(stage: str, activity: str, tool_calls: int):
            await asyncio.to_thread(self.store.progress, job.id, owner, stage, activity, tool_calls)
        result = await self.analyzer.analyze(sample, run_dir, on_progress=progress)
        await asyncio.to_thread(self.store.stage, job.id, owner, "publishing")
        await asyncio.to_thread(
            self.store.publish, job, owner, result, self.settings.opencode_model,
        )

    async def process(self, job: Job, owner: str) -> None:
        run_dir = self.settings.root / "runs" / f"{job.id}-{uuid.uuid4().hex}"
        run_dir.mkdir(mode=0o700)
        stop = asyncio.Event()
        try:
            async with asyncio.TaskGroup() as group:
                group.create_task(self._heartbeat(job, owner, stop))
                try:
                    await self._analyze(job, owner, run_dir)
                finally:
                    stop.set()
        except asyncio.CancelledError:
            # A graceful shutdown releases the job; a hard crash is recovered by lease expiry.
            await asyncio.to_thread(
                self.store.fail, job.id, owner, "Worker stopped during analysis.", self.settings.max_attempts,
            )
            raise
        except Exception as exc:
            # Model responses and provider errors can contain sample text or secrets.
            reason = safe_error(exc)
            logger.error("Analysis %s: %s", job.id, reason)
            await asyncio.to_thread(
                self.store.fail, job.id, owner,
                reason,
                self.settings.max_attempts,
            )
        finally:
            # Retain only transcripts; containers, extracted payloads and temporary HOME are removed.
            session = self.settings.root / "sessions" / run_dir.name
            for name in ("tools.jsonl", "opencode-events.jsonl"):
                if (run_dir / name).exists():
                    session.mkdir(mode=0o700, exist_ok=True)
                    await asyncio.to_thread(shutil.copyfile, run_dir / name, session / name)
            await asyncio.to_thread(shutil.rmtree, run_dir, True)

    async def run(self) -> None:
        owner = uuid.uuid4().hex
        while True:
            job = await asyncio.to_thread(
                self.store.claim, owner, self.settings.lease_seconds, self.settings.max_attempts,
            )
            if job:
                await self.process(job, owner)
            else:
                await asyncio.sleep(self.settings.poll_seconds)


async def serve() -> None:
    settings = Settings()
    settings.prepare()
    store = Store(settings.root)
    store.initialize()
    tasks = [asyncio.create_task(Worker(settings, store).run()) for _ in range(settings.worker_concurrency)]
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: [task.cancel() for task in tasks])
    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.gather(*tasks)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(serve())


if __name__ == "__main__":
    main()
