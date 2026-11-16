import asyncio
import hashlib
import json
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from malanalyzer.analyzer import (
    OpenCodeAnalyzer,
    bounded_evidence,
    opencode_config,
    parse_events,
    report_result,
)
from malanalyzer.app import create_app, render_markdown
from malanalyzer.config import Settings
from malanalyzer.models import IOC, AnalysisResult
from malanalyzer.process import ProcessError, base_environment, run_bounded
from malanalyzer.static_analysis import collect
from malanalyzer.store import Store


def result(**overrides):
    return AnalysisResult.model_validate({
        "title": "Static sample analysis", "summary": "A test sample with a literal URL.",
        "family": None, "family_confidence": "unknown",
        "report_markdown": "# Findings\nLiteral URL only; no network activity was observed.\n\n<script>alert(1)</script>\n\n[endpoint](https://example.test)\n\n![tracking](https://example.test/pixel)",
        "iocs": [], **overrides,
    })


def settings(tmp_path, **overrides):
    return Settings(_env_file=None, data_dir=tmp_path, embedded_worker=False, **overrides)


class FakeAnalyzer:
    async def analyze(self, sample, run_dir, on_progress=None):
        evidence = collect(sample)
        assert evidence["source_preview"].startswith("# inert fixture")
        if on_progress:
            await on_progress("ai_analysis", "Disassembling and decoding strings", 3)
        return result()


def wait_for_job(client, job_id):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        job = client.get(f"/api/analyses/{job_id}").json()
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.05)
    pytest.fail("Analysis did not finish")


def test_upload_analyze_publish_and_download(tmp_path):
    config = Settings(_env_file=None, data_dir=tmp_path, embedded_worker=True, poll_seconds=0.05)
    sample = b'# inert fixture\nurl = "https://example.test/control"\n'
    with TestClient(create_app(config, FakeAnalyzer())) as client:
        response = client.post("/api/samples", files={"file": ("../../sample.py", sample)})
        assert response.status_code == 202
        job = response.json()
        assert job["filename"] == "sample.py"
        assert job["sha256"] == hashlib.sha256(sample).hexdigest()
        finished = wait_for_job(client, job["id"])
        assert finished["status"] == "completed", finished
        report = client.get(f"/api/reports/{job['id']}").json()
        assert report["family"] is None
        iocs = client.get(f"/api/reports/{job['id']}/iocs").json()
        assert iocs == []
        assert finished["tool_calls"] == 3
        assert client.get(f"/api/reports/{job['id']}/markdown").text.startswith("# Findings")
        assert client.get("/api/reports?q=" + job["sha256"]).json()["total"] == 1
        assert client.get("/api/reports?q=no-such-family").json()["total"] == 0
        for url in ("/", "/reports", finished["report_url"], "/docs", "/openapi.json"):
            assert client.get(url).status_code == 200
        page = client.get(finished["report_url"])
        assert "<script>alert" not in page.text
        assert '<a href="https://example.test' not in page.text
        assert '<img ' not in page.text
        assert "Download IOCs" not in page.text
        assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
        assert client.get("/samples/" + job["sha256"]).status_code == 404
        assert not list((tmp_path / "runs").iterdir())


def test_validation_auth_and_upload_bounds(tmp_path):
    with TestClient(create_app(settings(tmp_path, upload_api_key="upload-secret", max_upload_mb=1))) as client:
        assert client.post("/api/samples", files={"file": ("x", b"abc")}).status_code == 401
        headers = {"X-API-Key": "upload-secret"}
        assert client.post("/api/samples", headers=headers, files={"file": ("x", b"")}).status_code == 400
        assert client.post("/api/samples", headers=headers, files={"file": ("x", b"x" * (1024 ** 2 + 1))}).status_code == 413
        assert not list((tmp_path / "incoming").iterdir())
        assert not list((tmp_path / "samples").iterdir())
        assert client.get("/api/analyses/missing").status_code == 404
        assert client.get("/api/reports/missing/iocs").status_code == 404
        assert client.get("/api/reports?limit=101").status_code == 422
        assert client.get("/reports?page=0").status_code == 422


def test_duplicate_uploads_share_blob(tmp_path):
    with TestClient(create_app(settings(tmp_path))) as client:
        one = client.post("/api/samples", files={"file": ("one", b"same bytes")}).json()
        two = client.post("/api/samples", files={"file": ("two", b"same bytes")}).json()
        assert one["id"] != two["id"]
        assert one["sha256"] == two["sha256"]
        assert len(list((tmp_path / "samples").iterdir())) == 1
        assert client.get("/api/reports").json()["total"] == 0


def test_failures_retry_and_never_publish_secrets(tmp_path):
    class BrokenAnalyzer:
        async def analyze(self, *_, **kwargs):
            raise RuntimeError("provider-secret-and-sample-content")

    config = Settings(_env_file=None, data_dir=tmp_path, embedded_worker=True, max_attempts=2, poll_seconds=0.05)
    with TestClient(create_app(config, BrokenAnalyzer())) as client:
        job = client.post("/api/samples", files={"file": ("x", b"harmless test data")}).json()
        job = wait_for_job(client, job["id"])
        assert job["status"] == "failed"
        assert job["attempts"] == 2
        assert "provider-secret" not in json.dumps(job)
        assert client.get("/api/reports").json()["total"] == 0


def test_queue_claim_is_atomic_and_lease_recovery_fences_old_owner(tmp_path):
    store = Store(tmp_path)
    store.initialize()
    job = store.create_job("a" * 64, "sample", 10)
    with ThreadPoolExecutor(max_workers=6) as pool:
        claims = list(pool.map(lambda n: store.claim(f"worker-{n}", 90, 2), range(6)))
    assert sum(claim is not None for claim in claims) == 1
    with store.connect() as db:
        old_owner = db.execute("SELECT owner FROM jobs WHERE id=?", (job.id,)).fetchone()[0]
        db.execute("UPDATE jobs SET lease_until=0 WHERE id=?", (job.id,))
    recovered = store.claim("new-owner", 90, 2)
    assert recovered.attempts == 2
    assert not store.publish(job, old_owner, result(), "test")
    assert store.publish(job, "new-owner", result(), "test")
    assert store.get_job(job.id).status == "completed"
    assert store.get_report(job.id).title == "Static sample analysis"


def test_expired_final_attempt_becomes_failed(tmp_path):
    store = Store(tmp_path)
    store.initialize()
    job = store.create_job("b" * 64, "x", 1)
    store.claim("owner", 90, 1)
    with store.connect() as db:
        db.execute("UPDATE jobs SET lease_until=0 WHERE id=?", (job.id,))
    assert store.claim("next-owner", 90, 1) is None
    assert store.get_job(job.id).status == "failed"


def test_existing_database_upgrade_preserves_legacy_reports_and_iocs(tmp_path):
    store = Store(tmp_path)
    store.initialize()
    job = store.create_job("c" * 64, "legacy.exe", 10)
    store.claim("old-worker", 90, 2)
    legacy = result(iocs=[{"ioc": "legacy.test", "type": "domain", "description": "Existing legacy finding"}])
    assert store.publish(job, "old-worker", legacy, "old-model")
    with store.connect() as db:
        db.execute("ALTER TABLE jobs DROP COLUMN tool_calls")
        db.execute("ALTER TABLE jobs DROP COLUMN activity")
    store.initialize()
    assert store.get_job(job.id).tool_calls == 0
    assert store.get_job(job.id).activity is None
    assert store.get_report(job.id).iocs[0].ioc == "legacy.test"
    assert store.get_report(job.id).report_markdown == legacy.report_markdown


def test_static_evidence_utf16_and_invalid_executable(tmp_path):
    path = tmp_path / "sample"
    path.write_bytes(b"MZ invalid\x00" + b"https://example.test/a\x00" + "192.0.2.42\0HKCU\\Software\\Test".encode("utf-16-le"))
    evidence = collect(path)
    assert any("parser failed" in warning for warning in evidence["limitations"])
    values = {(ioc["type"], ioc["ioc"]) for ioc in evidence["candidate_iocs"]}
    assert ("url", "https://example.test/a") in values
    assert ("ipv4", "192.0.2.42") in values
    assert ("registry_key", "HKCU\\Software\\Test") in values
    assert evidence["hashes"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_minimal_elf_metadata_and_entry_disassembly(tmp_path):
    # A synthetic x86-64 ELF with one executable section; never executed.
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 0, 0x80, 0, 64, 0, 0, 64, 2, 0)
    data = bytearray(0x110)
    data[:64] = ident + header
    data[0xC0:0x100] = struct.pack("<IIQQQQIIQQ", 0, 1, 6, 0x401000, 0x100, 2, 0, 0, 16, 0)
    data[0x100:0x102] = b"\x90\xc3"
    path = tmp_path / "fixture.elf"
    path.write_bytes(data)
    executable = collect(path)["executable"]
    assert executable["format"] == "ELF"
    assert executable["architecture"] == "x86"
    assert executable["entry_disassembly"][0]["instruction"] == "nop"


def test_minimal_pe_metadata_and_entry_disassembly(tmp_path):
    # Synthetic PE32 with one section containing nop/ret; never executed.
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 224, 0x102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<8sIIIIIIHHI", data, optional + 224, b".text\0\0\0", 2, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    data[0x200:0x202] = b"\x90\xc3"
    path = tmp_path / "fixture.exe"
    path.write_bytes(data)
    executable = collect(path)["executable"]
    assert executable["format"] == "PE"
    assert executable["bits"] == 32
    assert executable["entry_disassembly"][0]["instruction"] == "nop"


def test_context_budget_and_report_only_investigation(tmp_path, monkeypatch):
    path = tmp_path / "sample"
    path.write_bytes(b"https://example.test/static\n")
    evidence = collect(path)
    evidence["strings"] = [{"text": "x" * 1000}] * 1000
    bounded = bounded_evidence(evidence, budget=10_000)
    assert len(json.dumps(bounded)) <= 10_000
    assert len(evidence["strings"]) == 1000
    assert "candidate_iocs" not in bounded
    assert any("initial bounded" in warning for warning in bounded["limitations"])

    class FakeSandbox:
        name = "malanalyzer-" + "a" * 32
        binary = "/fake/docker"
        def __init__(self, *_):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *_):
            pass
        async def collect(self):
            return evidence
        async def read_report(self):
            return "# Recovered configuration\n\n" + "Found https://example.test/static using tool-assisted byte inspection. " * 5

    async def fake_run(command, **kwargs):
        assert "--pure" in command
        assert "MISTRAL_API_KEY" in kwargs["env"]
        assert "UPLOAD_API_KEY" not in kwargs["env"]
        config = json.loads((tmp_path / "opencode.json").read_text())
        assert config["permission"] == {"*": "deny", "analysis_*": "allow"}
        assert config["mcp"]["analysis"]["type"] == "local"
        assert "MISTRAL_API_KEY" not in config["mcp"]["analysis"]["environment"]
        (tmp_path / "tools.jsonl").write_text(json.dumps({"tool": "write_report", "status": "completed", "call": 3}) + "\n")
        return (
            b'{"type":"text","part":{"text":"Report saved."}}\n'
            b'{"type":"step_finish","part":{"id":"turn-1","cost":0.025,"tokens":{"input":100,"output":20}}}',
            b"",
        )

    monkeypatch.setattr("malanalyzer.analyzer.run_bounded", fake_run)
    monkeypatch.setattr("malanalyzer.analyzer.shutil.which", lambda _: "/fake/opencode")
    monkeypatch.setattr("malanalyzer.analyzer.create_sandbox", FakeSandbox)
    config = settings(tmp_path, mistral_api_key="fake-key")
    output = asyncio.run(OpenCodeAnalyzer(config).analyze(path, tmp_path))
    assert "https://example.test/static" in output.report_markdown
    assert output.iocs == []
    assert output.title == "Recovered configuration"
    assert "## Analysis cost" in output.report_markdown
    assert "**$0.025000 USD**" in output.report_markdown
    assert opencode_config(config.opencode_model, FakeSandbox(), config, tmp_path / "tools.jsonl")["agent"]["static-analyst"]["steps"] == 120


def test_chunked_upload_request_limit(tmp_path):
    boundary = "test-boundary"
    def chunks():
        yield f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="large"\r\n\r\n'.encode()
        for _ in range(20):
            yield b"x" * 65536
        yield f"\r\n--{boundary}--\r\n".encode()
    with TestClient(create_app(settings(tmp_path, max_upload_mb=1))) as client:
        response = client.post("/api/samples", content=chunks(), headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        assert response.status_code == 413
        assert not list((tmp_path / "samples").iterdir())


def test_markdown_report_and_event_parsing():
    events = b'startup log\n{"type":"text","part":{"text":"intermediate commentary"}}'
    assert len(parse_events(events)) == 1
    with pytest.raises(ValueError):
        report_result("No substantive report")
    with pytest.raises(ValueError):
        parse_events(b"no events")
    with pytest.raises(ValueError):
        parse_events(b'{"type":"error","error":{"message":"secret"}}')
    with pytest.raises(ValidationError):
        IOC(ioc="x", type="invented_type", description="x")
    report = report_result("# A sample report\n\n**Summary:** decoded `configuration`. " + "Evidence-backed findings. " * 10)
    assert report.title == "A sample report"
    assert report.summary.startswith("Summary: decoded configuration.")
    assert not report.iocs


def test_markdown_never_embeds_active_content():
    html = render_markdown('[C2](https://example.test) ![x](https://example.test/x) <iframe src="https://example.test"></iframe>')
    assert "<a " not in html
    assert "<img " not in html
    assert "<iframe " not in html


def test_process_timeout_and_output_limits(tmp_path):
    async def checks():
        with pytest.raises(TimeoutError):
            await run_bounded([sys.executable, "-c", "import time; time.sleep(10)"], cwd=tmp_path, env=base_environment(), timeout=1)
        with pytest.raises(ProcessError):
            await run_bounded([sys.executable, "-c", "print('x' * 10000)"], cwd=tmp_path, env=base_environment(), timeout=5, output_limit=100)
    asyncio.run(checks())
