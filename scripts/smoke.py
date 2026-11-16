"""Real OpenCode/Mistral tool investigation of an inert, encoded ELF fixture."""

import argparse
import json
import shutil
import struct
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from malanalyzer.app import create_app
from malanalyzer.config import Settings


def encoded_elf():
    """A synthetic decoder with a hidden URL; no network calls or OS interaction."""
    plaintext = b"https://example.test/decoded\0"
    data = bytearray(0x200)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    data[16:64] = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 0, 0x80, 0, 64, 0, 0, 64, 2, 0)
    data[0xC0:0x100] = struct.pack("<IIQQQQIIQQ", 0, 1, 6, 0x401000, 0x100, 0x100, 0, 0, 16, 0)
    code = b"\x48\x8d\x35\x39\x00\x00\x00\xb9" + struct.pack("<I", len(plaintext)) + b"\x80\x36\x5a\x48\xff\xc6\xe2\xf8\xc3"
    data[0x100:0x100 + len(code)] = code
    data[0x140:0x140 + len(plaintext)] = bytes(value ^ 0x5A for value in plaintext)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", type=Path, help="Keep the generated report and tool transcripts in this directory")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="malanalyzer-smoke-") as directory:
        config = Settings(data_dir=Path(directory), embedded_worker=True, max_attempts=1, analysis_timeout_seconds=300)
        with TestClient(create_app(config)) as client:
            response = client.post(
                "/api/samples", headers={"X-API-Key": config.upload_api_key.get_secret_value()},
                files={"file": ("inert_decoder.elf", encoded_elf())},
            )
            response.raise_for_status()
            job_id = response.json()["id"]
            deadline = time.monotonic() + config.analysis_timeout_seconds + config.static_timeout_seconds + 30
            last_activity = None
            while time.monotonic() < deadline:
                job = client.get(f"/api/analyses/{job_id}").json()
                if job["activity"] != last_activity:
                    last_activity = job["activity"]
                    print(f"[{job['tool_calls']} tools] {last_activity}", flush=True)
                if job["status"] == "failed":
                    raise RuntimeError(job["error"])
                if job["status"] == "completed":
                    report = client.get(f"/api/reports/{job_id}").json()
                    normalized = report["report_markdown"].replace("[.]", ".")
                    assert report["iocs"] == [], "IOC JSON generation should be deferred."
                    assert job["tool_calls"] >= 2
                    assert client.get(job["report_url"]).status_code == 200
                    # Logs are copied by worker cleanup just after atomic publication.
                    for _ in range(50):
                        audits = list((config.root / "sessions").glob("*/tools.jsonl"))
                        if audits:
                            break
                        time.sleep(0.05)
                    entries = [json.loads(line) for line in audits[0].read_text().splitlines()]
                    if args.keep:
                        args.keep.mkdir(parents=True, exist_ok=True)
                        (args.keep / "report.md").write_text(report["report_markdown"])
                        shutil.copytree(config.root / "sessions", args.keep / "sessions", dirs_exist_ok=True)
                    assert "example.test" in normalized and "decoded" in normalized, "The agent did not recover the hidden URL."
                    assert any(entry["tool"] == "disassemble" or "objdump" in entry.get("code", "") or "disasm" in entry.get("code", "") for entry in entries)
                    print(f"PASS: upload → sandboxed disassembly/decoding → {config.opencode_model} → published Markdown ({job['tool_calls']} tool calls).")
                    return
                time.sleep(1)
            raise TimeoutError("Live analysis did not complete.")


if __name__ == "__main__":
    main()
