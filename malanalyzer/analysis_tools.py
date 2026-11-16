"""MCP bridge: only these tools are exposed to the model; code runs inside Docker."""

import argparse
import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from malanalyzer.sandbox import SandboxClient


class InvestigationTools:
    def __init__(self, client: SandboxClient, audit: Path, max_calls: int, timeout: int, deadline: float = 0):
        self.client, self.audit = client, audit
        self.max_calls, self.timeout = max_calls, timeout
        self.deadline = deadline
        self.calls = 0
        self.successful_calls = 0
        self.lock = asyncio.Lock()

    def record(self, **event):
        with self.audit.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"timestamp": datetime.now(UTC).isoformat(), **event}) + "\n")

    async def execute(self, tool: str, code: str, description: str, kind="python", timeout=120) -> dict:
        async with self.lock:
            if self.calls >= self.max_calls:
                raise ValueError("Tool budget reached. Write your final report now with write_report.")
            if len(code) > 100_000:
                raise ValueError("Tool code is too long; split the investigation into smaller steps.")
            self.calls += 1
            call = self.calls
            self.record(status="started", tool=tool, call=call, description=description[:300], code=code)
            try:
                result = await self.client.execute(kind, code, min(max(timeout, 1), self.timeout))
            except Exception:
                self.record(status="failed", tool=tool, call=call, description=description[:300])
                raise RuntimeError("Analysis tool transport failed; the container may have stopped.") from None
            if result["exit_code"] == 0 and not result["timed_out"]:
                self.successful_calls += 1
            self.record(status="completed", tool=tool, call=call, description=description[:300], result=result)
            remaining = self.max_calls - self.calls
            result["remaining_tool_calls"] = remaining
            seconds = max(0, int(self.deadline - time.time())) if self.deadline else None
            result["seconds_remaining"] = seconds
            if remaining <= 5 or seconds is not None and seconds < 120:
                result["budget_notice"] = "Finish your investigation and write the Markdown report now."
            return result

    async def write_report(self, markdown: str) -> str:
        async with self.lock:
            if not self.successful_calls:
                raise ValueError("Investigate the sample with the tools before writing the report.")
            if not 200 <= len(markdown.strip()) <= 150_000:
                raise ValueError("Write a substantive Markdown report of 200 to 150000 characters.")
            # Keep report delivery separate from investigation budget and output truncation.
            code = (
                "from pathlib import Path; p=Path('/workspace/report.md'); "
                "p.unlink(missing_ok=True); p.write_text(" + repr(markdown.strip()) + ", encoding='utf-8')"
            )
            result = await self.client.execute("python", code, 10)
            if result["exit_code"] != 0:
                raise RuntimeError("Could not write the final report.")
            self.record(status="completed", tool="write_report", call=self.calls,
                        description="Final Markdown report written", report_characters=len(markdown))
            return "Final report saved to /workspace/report.md. You can now finish the session."


def make_server(tools: InvestigationTools) -> FastMCP:
    server = FastMCP("Malware analysis workspace")

    @server.tool()
    async def run_python(code: str, description: str, timeout: int = 120) -> dict:
        """Run Python for static investigation in the persistent offline workspace.
        Read /input/sample.bin; write scripts/artifacts under /workspace. Installed:
        pefile, elftools, capstone, unicorn, cryptography, Crypto (PyCryptodome).
        BinaryImage from malanalyzer.binary_tools handles PE/ELF VA mapping, disassembly,
        and xrefs. Variables do not persist between calls; files do. Never execute/import
        the sample. Use bounded Unicorn emulation with stubbed APIs for decoder routines.
        """
        return await tools.execute("run_python", code, description, timeout=timeout)

    @server.tool()
    async def run_command(command: str, description: str, timeout: int = 120) -> dict:
        """Run analysis commands in the offline container's persistent /workspace.
        Available: file, strings, objdump (multiarch), readelf, nm, xxd, grep, bash, python3.
        Can run analyst-authored Python scripts and inspect sample bytes, never detonate
        the sample. No network or package installation; all dependencies are preinstalled.
        """
        return await tools.execute("run_command", command, description, kind="shell", timeout=timeout)

    @server.tool()
    async def disassemble(address: str = "entry", size: int = 1024, count: int = 200) -> dict:
        """Disassemble PE/ELF code with Capstone. address is a VA (hex or decimal), or
        'entry'. Output includes resolved x86/x64 RIP-relative targets. No execution.
        For PE convert RVA to VA by adding ImageBase, not a section's base.
        """
        va = None if address == "entry" else int(address, 0)
        code = (
            "import json; from malanalyzer.binary_tools import BinaryImage; "
            f"b=BinaryImage(); print(json.dumps(list(b.disassemble({va!r}, {max(1, min(size, 65536))}, {max(1, min(count, 1000))}))))"
        )
        return await tools.execute("disassemble", code, f"Disassemble {address}")

    @server.tool()
    async def find_xrefs(address: str, end_address: str = "", limit: int = 200) -> dict:
        """Find x86/x64 references to a VA or half-open VA range in executable sections.
        Finds RIP-relative memory, direct call/jump immediates, and absolute references.
        Linear disassembly skips embedded data; computed/indirect references may be missed.
        """
        start = int(address, 0)
        end = int(end_address, 0) if end_address else start + 1
        code = (
            "import json; from malanalyzer.binary_tools import BinaryImage; "
            f"print(json.dumps(list(BinaryImage().xrefs({start}, {end}, {max(1, min(limit, 1000))}))))"
        )
        return await tools.execute("find_xrefs", code, f"Find references to {address}")

    @server.tool()
    async def write_report(markdown: str) -> str:
        """Save the final freeform Markdown report after completing the investigation.
        Include behavior, recovered configuration/indicators, evidence addresses, confidence,
        and unresolved questions as appropriate. No JSON envelope or IOC JSON is needed.
        This tool remains available even when the investigation-call budget is exhausted.
        """
        return await tools.write_report(markdown)

    return server


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--container", required=True)
    parser.add_argument("--binary", "--docker", dest="binary", required=True)
    parser.add_argument("--backend", choices=["docker", "kubernetes"], default="docker")
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--max-calls", type=int, default=150)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--deadline", type=float, default=0)
    args = parser.parse_args()
    if args.backend == "kubernetes":
        from malanalyzer.kubernetes_sandbox import KubernetesClient

        client = KubernetesClient(args.binary, args.container, args.audit.parent, args.namespace)
    else:
        client = SandboxClient(args.binary, args.container, args.audit.parent)
    make_server(InvestigationTools(client, args.audit, args.max_calls, args.timeout, args.deadline)).run(transport="stdio")


if __name__ == "__main__":
    main()
