import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from malanalyzer.models import AnalysisResult, Job, Report, ReportSummary


def now() -> str:
    return datetime.now(UTC).isoformat()


class Store:
    """SQLite-backed queue with expiring leases and atomic report publication."""

    def __init__(self, root: Path):
        self.path = root / "malanalyzer.sqlite3"

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, filename TEXT NOT NULL,
                    size INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
                    stage TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    error TEXT, owner TEXT, lease_until REAL
                );
                CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status, created_at);
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY REFERENCES jobs(id), sha256 TEXT NOT NULL,
                    filename TEXT NOT NULL, size INTEGER NOT NULL, title TEXT NOT NULL,
                    summary TEXT NOT NULL, family TEXT, family_confidence TEXT NOT NULL,
                    published_at TEXT NOT NULL, model TEXT NOT NULL,
                    report_markdown TEXT NOT NULL, iocs TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS reports_published ON reports(published_at DESC);
            """)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(jobs)")}
            for name, declaration in (("tool_calls", "INTEGER NOT NULL DEFAULT 0"), ("activity", "TEXT")):
                if name not in columns:
                    db.execute(f"ALTER TABLE jobs ADD COLUMN {name} {declaration}")

    def create_job(self, sha256: str, filename: str, size: int) -> Job:
        job_id, timestamp = uuid.uuid4().hex, now()
        with self.connect() as db:
            db.execute(
                "INSERT INTO jobs(id, sha256, filename, size, created_at, updated_at) VALUES(?,?,?,?,?,?)",
                (job_id, sha256, filename, size, timestamp, timestamp),
            )
        return self.get_job(job_id)

    def get_job(self, job_id: str) -> Job | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            return None
        return Job(
            **{key: row[key] for key in Job.model_fields if key != "report_url"},
            report_url=f"/reports/{row['id']}" if row["status"] == "completed" else None,
        )

    def claim(self, owner: str, lease_seconds: int, max_attempts: int) -> Job | None:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """UPDATE jobs SET status='failed', stage='failed', error=?, updated_at=?,
                   owner=NULL, lease_until=NULL
                   WHERE status='running' AND lease_until < ? AND attempts >= ?""",
                ("Worker stopped before analysis completed; retry limit reached.", now(), time.time(), max_attempts),
            )
            row = db.execute(
                """SELECT id FROM jobs WHERE attempts < ? AND
                   (status='queued' OR (status='running' AND lease_until < ?))
                   ORDER BY created_at LIMIT 1""",
                (max_attempts, time.time()),
            ).fetchone()
            if row is None:
                return None
            db.execute(
                """UPDATE jobs SET status='running', stage='static_analysis', attempts=attempts+1,
                   owner=?, lease_until=?, updated_at=?, error=NULL WHERE id=?""",
                (owner, time.time() + lease_seconds, now(), row["id"]),
            )
        return self.get_job(row["id"])

    def heartbeat(self, job_id: str, owner: str, lease_seconds: int) -> bool:
        with self.connect() as db:
            return db.execute(
                "UPDATE jobs SET lease_until=? WHERE id=? AND owner=? AND status='running'",
                (time.time() + lease_seconds, job_id, owner),
            ).rowcount == 1

    def stage(self, job_id: str, owner: str, stage: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE jobs SET stage=?, updated_at=? WHERE id=? AND owner=? AND status='running'",
                (stage, now(), job_id, owner),
            )

    def progress(self, job_id: str, owner: str, stage: str, activity: str, tool_calls: int) -> None:
        with self.connect() as db:
            db.execute(
                """UPDATE jobs SET stage=?, activity=?, tool_calls=?, updated_at=?
                   WHERE id=? AND owner=? AND status='running'""",
                (stage, activity[:300], tool_calls, now(), job_id, owner),
            )

    def fail(self, job_id: str, owner: str, error: str, max_attempts: int) -> None:
        with self.connect() as db:
            db.execute(
                """UPDATE jobs SET status=CASE WHEN attempts < ? THEN 'queued' ELSE 'failed' END,
                   stage=CASE WHEN attempts < ? THEN 'retry_queued' ELSE 'failed' END,
                   error=?, owner=NULL, lease_until=NULL, updated_at=?
                   WHERE id=? AND owner=? AND status='running'""",
                (max_attempts, max_attempts, error, now(), job_id, owner),
            )

    def publish(self, job: Job, owner: str, result: AnalysisResult, model: str) -> bool:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id FROM jobs WHERE id=? AND owner=? AND status='running' AND lease_until > ?",
                (job.id, owner, time.time()),
            ).fetchone()
            if row is None:
                return False
            timestamp = now()
            db.execute(
                "INSERT INTO reports VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    job.id, job.sha256, job.filename, job.size, result.title, result.summary,
                    result.family, result.family_confidence, timestamp, model,
                    result.report_markdown, json.dumps([ioc.model_dump() for ioc in result.iocs]),
                ),
            )
            db.execute(
                """UPDATE jobs SET status='completed', stage='published', updated_at=?,
                   owner=NULL, lease_until=NULL, error=NULL WHERE id=?""",
                (timestamp, job.id),
            )
        return True

    def list_reports(self, limit: int = 20, offset: int = 0, search: str = "") -> tuple[list[ReportSummary], int]:
        where = "WHERE instr(lower(title || ' ' || coalesce(family, '') || ' ' || sha256), lower(?)) > 0"
        columns = ",".join(ReportSummary.model_fields)
        with self.connect() as db:
            total = db.execute(f"SELECT count(*) FROM reports {where}", (search,)).fetchone()[0]
            rows = db.execute(
                f"SELECT {columns} FROM reports {where} ORDER BY published_at DESC LIMIT ? OFFSET ?",
                (search, limit, offset),
            ).fetchall()
        return [ReportSummary(**dict(row)) for row in rows], total

    def get_report(self, report_id: str) -> Report | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["iocs"] = json.loads(data["iocs"])
        return Report(**data)
