import contextlib
import json
import os
import re
import shutil
import uuid
from pathlib import Path

from malanalyzer.config import Settings
from malanalyzer.process import ProcessError, base_environment, run_bounded


def docker_environment() -> dict[str, str]:
    # Docker may need the developer's selected daemon/context. These variables never enter
    # the analysis container, and the model cannot invoke the host Docker CLI directly.
    names = ("HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR")
    return base_environment() | {name: os.environ[name] for name in names if name in os.environ}


class SandboxClient:
    def __init__(self, binary: str, name: str, cwd: Path):
        if not re.fullmatch(r"malanalyzer-[a-f0-9]{32}", name):
            raise ValueError("Invalid analysis container name.")
        self.binary, self.name, self.cwd = binary, name, cwd

    async def docker(self, *arguments, timeout=30, **kwargs):
        return await run_bounded(
            [self.binary, *arguments], cwd=self.cwd, env=docker_environment(),
            timeout=timeout, **kwargs,
        )

    async def execute(self, kind: str, code: str, timeout: int) -> dict:
        output, _ = await self.exec(
            "python3", "/opt/malanalyzer/runner.py",
            timeout=timeout + 15,
            input_data=json.dumps({"kind": kind, "code": code, "timeout": timeout}).encode(),
            output_limit=650_000,
        )
        return json.loads(output)

    async def exec(self, *command, timeout=30, input_data=None, **kwargs):
        flags = ["-i"] if input_data is not None else []
        return await self.docker(
            "exec", *flags, self.name, *command, timeout=timeout, input_data=input_data, **kwargs,
        )

    async def read_report(self) -> str:
        # Read inside the container rather than copying an attacker-controlled symlink onto the host.
        output, _ = await self.exec(
            "python3", "-c",
            "import os,stat; p='/workspace/report.md'; s=os.lstat(p); "
            "assert stat.S_ISREG(s.st_mode) and 0 < s.st_size <= 600000; "
            "print(open(p, encoding='utf-8').read(), end='')",
            output_limit=650_000,
        )
        return output.decode("utf-8")


class AnalysisSandbox(SandboxClient):
    def __init__(self, settings: Settings, sample: Path, run_dir: Path):
        binary = shutil.which(settings.docker_binary)
        if not binary:
            raise ProcessError("Docker executable not found; install Docker and build the analysis image.")
        super().__init__(binary, f"malanalyzer-{uuid.uuid4().hex}", run_dir)
        self.settings, self.sample = settings, sample

    async def __aenter__(self):
        inputs = self.cwd / "input"
        inputs.mkdir(mode=0o755)
        shutil.copyfile(self.sample, inputs / "sample.bin")
        (inputs / "sample.bin").chmod(0o444)
        if "," in str(inputs):
            raise ProcessError("DATA_DIR must not contain commas for Docker bind mounts.")
        try:
            await self.docker(
                "create", "--name", self.name, "--pull=never", "--rm",
                "--label", "malanalyzer.analysis=true",
                "--network=none", "--read-only", "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true", "--pids-limit=128",
                "--memory", f"{self.settings.sandbox_memory_mb}m", "--cpus=2",
                "--user=65532:65532", "--workdir=/workspace",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m,mode=1777",
                "--tmpfs", "/workspace:rw,noexec,nosuid,size=256m,mode=1777",
                "--mount", f"type=bind,source={inputs},target=/input,readonly",
                self.settings.sandbox_image, "sleep",
                str(self.settings.analysis_timeout_seconds + self.settings.static_timeout_seconds + 120),
            )
            await self.docker("start", self.name)
        except BaseException:
            await self.close()
            raise
        return self

    async def collect(self) -> dict:
        output, _ = await self.exec(
            "python3", "-m", "malanalyzer.static_analysis", "/input/sample.bin",
            timeout=self.settings.static_timeout_seconds,
        )
        return json.loads(output)

    async def close(self):
        with contextlib.suppress(ProcessError, TimeoutError, OSError):
            await self.docker("rm", "-f", self.name, timeout=15)

    async def __aexit__(self, *_):
        await self.close()


def create_sandbox(settings: Settings, sample: Path, run_dir: Path):
    if settings.sandbox_backend == "kubernetes":
        from malanalyzer.kubernetes_sandbox import KubernetesSandbox

        return KubernetesSandbox(settings, sample, run_dir)
    return AnalysisSandbox(settings, sample, run_dir)
