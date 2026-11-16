import asyncio
import json
import os
import signal
from pathlib import Path


class ProcessError(RuntimeError):
    pass


def failure_reason(stdout: bytes, stderr: bytes, code: int) -> str:
    """Extract only allowlisted error categories, never provider response text."""
    for line in stdout.decode("utf-8", "replace").splitlines():
        try:
            event = json.loads(line)
            if isinstance(event, dict) and event.get("type") == "error":
                data = event.get("error", {}).get("data", {})
                status = data.get("statusCode")
                if status in (401, 403):
                    return "Mistral authentication failed; check MISTRAL_API_KEY and account permissions."
                if status == 429:
                    return "Mistral rate limit or quota exceeded."
                if status == 400:
                    return "Mistral rejected the model request; check OPENCODE_MODEL compatibility and context limits."
        except (ValueError, AttributeError, TypeError):
            continue
    if b"Configuration is invalid" in stderr:
        return "OpenCode rejected its analysis configuration; use the documented OpenCode version."
    if b"No such image" in stderr or b"Unable to find image" in stderr:
        return "Analysis image is not built; run docker build -f sandbox/Dockerfile -t malanalyzer-tools:local ."
    if b"Cannot connect to the Docker daemon" in stderr or b"failed to connect to the docker API" in stderr:
        return "Docker daemon is unavailable; start Docker and check the worker's Docker context."
    return f"Analysis subprocess exited with code {code}."


async def run_bounded(
    command: list[str], *, cwd: Path, env: dict[str, str], timeout: int,
    output_limit: int = 4_000_000,
    input_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    """No shell; bound output and terminate the entire child process group on timeout."""
    process = await asyncio.create_subprocess_exec(
        *command, cwd=cwd, env=env, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, start_new_session=True,
        stdin=asyncio.subprocess.PIPE if input_data is not None else asyncio.subprocess.DEVNULL,
    )

    async def read(stream: asyncio.StreamReader) -> bytes:
        output = bytearray()
        while chunk := await stream.read(65536):
            output.extend(chunk)
            if len(output) > output_limit:
                raise ProcessError("Analysis subprocess exceeded its output limit.")
        return bytes(output)

    tasks = [asyncio.create_task(read(process.stdout)), asyncio.create_task(read(process.stderr))]
    if input_data is not None:
        async def write():
            try:
                process.stdin.write(input_data)
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                process.stdin.close()
        tasks.append(asyncio.create_task(write()))
    try:
        async with asyncio.timeout(timeout):
            results = await asyncio.gather(*tasks)
            stdout, stderr = results[:2]
            code = await process.wait()
        if code:
            # Provider errors can contain request data or credentials. Never return raw stderr.
            raise ProcessError(failure_reason(stdout, stderr, code))
        return stdout, stderr
    except BaseException:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


def base_environment() -> dict[str, str]:
    # Do not forward application credentials, cloud tokens, or the developer's shell environment.
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8", "NO_COLOR": "1",
    }
