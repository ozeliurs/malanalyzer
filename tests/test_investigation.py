import asyncio
import hashlib
import json
import os
import struct
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from malanalyzer.analysis_tools import InvestigationTools
from malanalyzer.binary_tools import BinaryImage
from malanalyzer.config import Settings
from malanalyzer.sandbox import AnalysisSandbox, SandboxClient, docker_environment
from scripts.smoke import encoded_elf


def test_binary_mapping_disassembly_xrefs_and_decoding(tmp_path):
    sample = tmp_path / "fixture.elf"
    sample.write_bytes(encoded_elf())
    image = BinaryImage(sample)
    assert image.entry == 0x401000
    assert image.va_to_offset(0x401040) == 0x140
    instructions = list(image.disassemble(count=6))
    assert instructions[0]["targets"] == ["0x401040"]
    assert instructions[2]["instruction"] == "xor byte ptr [rsi], 0x5a"
    assert list(image.xrefs(0x401040))[0]["va"] == "0x401000"
    assert bytes(value ^ 0x5A for value in image.read(0x401040, 29)) == b"https://example.test/decoded\0"
    with pytest.raises(ValueError, match="not backed"):
        image.va_to_offset(0x800000)


def test_pe_va_mapping_uses_image_base_and_scans_past_inline_data(tmp_path):
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<8sIIIIIIHHI", data, optional + 240, b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    # Invalid bytes before a RIP-relative LEA must not terminate the entire xref scan.
    data[0x200:0x20A] = b"\x06\x06\x06\x48\x8d\x05\x36\x00\x00\x00"
    path = tmp_path / "fixture.exe"
    path.write_bytes(data)
    image = BinaryImage(path)
    assert image.image_base == 0x140000000
    assert image.va_to_offset(0x140001040) == 0x240
    refs = list(image.xrefs(0x140001040))
    assert refs[0]["va"] == "0x140001003"


def test_tools_require_investigation_and_leave_report_delivery_available(tmp_path):
    class FakeClient:
        async def execute(self, kind, code, timeout):
            assert kind == "python"
            return {"exit_code": 0, "timed_out": False, "stdout": "observed bytes", "stderr": "", "truncated": False}

    async def checks():
        tools = InvestigationTools(FakeClient(), tmp_path / "tools.jsonl", max_calls=1, timeout=5)
        with pytest.raises(ValueError, match="Investigate"):
            await tools.write_report("# Title\n" + "report " * 40)
        await tools.execute("run_python", "print('observed bytes')", "Inspect sample bytes")
        with pytest.raises(ValueError, match="budget"):
            await tools.execute("run_python", "print('more')", "Another call")
        await tools.write_report("# Title\n" + "Evidence-backed findings. " * 20)
        entries = [json.loads(line) for line in (tmp_path / "tools.jsonl").read_text().splitlines()]
        assert entries[-1]["tool"] == "write_report"
        assert entries[0]["code"] == "print('observed bytes')"
        assert entries[1]["result"]["stdout"] == "observed bytes"
    asyncio.run(checks())


def test_container_name_cannot_inject_host_docker_arguments(tmp_path):
    with pytest.raises(ValueError):
        SandboxClient("docker", "--privileged", tmp_path)


@pytest.mark.sandbox
@pytest.mark.skipif(os.environ.get("RUN_SANDBOX_TESTS") != "1", reason="Set RUN_SANDBOX_TESTS=1 to test Docker/MCP integration")
def test_offline_sandbox_and_real_mcp_tool_round_trip(tmp_path):
    async def checks():
        sample = tmp_path / "fixture.elf"
        sample.write_bytes(encoded_elf())
        digest = hashlib.sha256(sample.read_bytes()).hexdigest()
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        settings = Settings(_env_file=None, data_dir=tmp_path)
        async with AnalysisSandbox(settings, sample, run_dir) as sandbox:
            assert (await sandbox.collect())["hashes"]["sha256"] == digest
            assert (await sandbox.execute("python", "import time; time.sleep(10)", 1))["timed_out"]
            huge = await sandbox.execute("python", "print('x' * 100000)", 5)
            assert huge["truncated"] and len(huge["stdout"]) == 48000
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "malanalyzer.analysis_tools", "--container", sandbox.name,
                      "--docker", sandbox.binary, "--audit", str(run_dir / "tools.jsonl")],
                env=docker_environment(),
            )
            async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
                await session.initialize()
                names = {tool.name for tool in (await session.list_tools()).tools}
                assert names == {"run_python", "run_command", "disassemble", "find_xrefs", "write_report"}
                output = await session.call_tool("run_python", {
                    "description": "Verify offline tool environment",
                    "code": "import os,socket,unicorn,Crypto; assert 'MISTRAL_API_KEY' not in os.environ; "
                            "s=socket.socket(); s.settimeout(0.5)\n"
                            "try: s.connect(('192.0.2.1',80)); raise AssertionError('Network was accessible')\n"
                            "except OSError: print('network blocked; credentials absent; libraries installed')",
                })
                assert not output.isError
                assert "network blocked" in output.content[0].text
                output = await session.call_tool("disassemble", {"address": "entry", "count": 6})
                assert not output.isError and "0x401040" in output.content[0].text
                blocked = await sandbox.execute("python", "open('/input/sample.bin','wb')", 5)
                assert blocked["exit_code"] != 0
                report = "# Verified decoder\n\n" + "The XOR decoding loop and target address were observed in the sample. " * 5
                saved = await session.call_tool("write_report", {"markdown": report})
                assert not saved.isError
                assert await sandbox.read_report() == report.strip()
        assert hashlib.sha256(sample.read_bytes()).hexdigest() == digest
    asyncio.run(checks())
