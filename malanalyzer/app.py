import asyncio
import hashlib
import hmac
import os
import re
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import bleach
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markdown_it import MarkdownIt

from malanalyzer.config import Settings
from malanalyzer.middleware import UploadLimitMiddleware
from malanalyzer.models import IOC, Job, Report, ReportSummary
from malanalyzer.store import Store
from malanalyzer.worker import Worker

PACKAGE = Path(__file__).parent
templates = Jinja2Templates(directory=PACKAGE / "templates")
markdown = MarkdownIt("commonmark", {"html": False}).enable("table")


def render_markdown(content: str) -> str:
    return bleach.clean(
        markdown.render(content),
        tags={"p", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "code", "blockquote",
              "ul", "ol", "li", "strong", "em", "hr", "br", "table", "thead", "tbody", "tr", "th", "td"},
        attributes={}, strip=True,
    )


def safe_filename(filename: str | None) -> str:
    name = (filename or "sample").replace("\\", "/").rsplit("/", 1)[-1]
    return re.sub(r"[\x00-\x1f\x7f]", "_", name)[:200] or "sample"


def create_app(settings: Settings | None = None, analyzer=None) -> FastAPI:
    config = settings or Settings()
    store = Store(config.root)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        config.prepare()
        store.initialize()
        tasks = []
        if config.embedded_worker:
            tasks = [asyncio.create_task(Worker(config, store, analyzer).run()) for _ in range(config.worker_concurrency)]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    app = FastAPI(title="Malanalyzer", version="0.1.0", lifespan=lifespan)
    app.state.store = store
    app.state.settings = config
    app.add_middleware(UploadLimitMiddleware, max_bytes=config.max_upload_mb * 1024 * 1024 + 65536)
    app.mount("/static", StaticFiles(directory=PACKAGE / "static"), name="static")

    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'none'; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        ) if not request.url.path.startswith(("/docs", "/redoc")) else "frame-ancestors 'none'"
        return response

    def authorize_upload(x_api_key: Annotated[str | None, Header()] = None):
        expected = config.upload_api_key.get_secret_value()
        if expected and not hmac.compare_digest((x_api_key or "").encode(), expected.encode()):
            raise HTTPException(status_code=401, detail="A valid X-API-Key header is required.")

    @app.get("/health")
    def health():
        return {"status": "ok", "analysis_configured": bool(config.mistral_api_key.get_secret_value())}

    @app.post("/api/samples", response_model=Job, status_code=202, dependencies=[Depends(authorize_upload)])
    async def upload(file: UploadFile):
        incoming = config.root / "incoming" / uuid.uuid4().hex
        digest, size = hashlib.sha256(), 0
        try:
            # Random server-owned name, no execute permission, bounded streaming read.
            with incoming.open("xb") as target:
                os.chmod(incoming, 0o600)
                while chunk := await file.read(1024 * 1024):
                    size += len(chunk)
                    if size > config.max_upload_mb * 1024 * 1024:
                        raise HTTPException(413, f"Sample exceeds {config.max_upload_mb} MiB.")
                    digest.update(chunk)
                    target.write(chunk)
            if size == 0:
                raise HTTPException(400, "The sample is empty.")
            sha256 = digest.hexdigest()
            destination = config.root / "samples" / sha256
            # Atomic content-addressed placement; identical concurrent uploads share one blob.
            try:
                os.link(incoming, destination)
            except FileExistsError:
                pass
            job = await asyncio.to_thread(store.create_job, sha256, safe_filename(file.filename), size)
            return job
        finally:
            incoming.unlink(missing_ok=True)
            await file.close()

    @app.get("/api/analyses/{job_id}", response_model=Job)
    def get_job(job_id: str):
        job = store.get_job(job_id)
        if job is None:
            raise HTTPException(404, "Analysis not found.")
        return job

    @app.get("/api/reports")
    def reports_api(
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        offset: Annotated[int, Query(ge=0)] = 0,
        q: Annotated[str, Query(max_length=200)] = "",
    ) -> dict[str, list[ReportSummary] | int]:
        items, total = store.list_reports(limit, offset, q)
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def find_report(report_id: str) -> Report:
        report = store.get_report(report_id)
        if report is None:
            raise HTTPException(404, "Report not found.")
        return report

    @app.get("/api/reports/{report_id}", response_model=Report)
    def report_api(report_id: str):
        return find_report(report_id)

    @app.get("/api/reports/{report_id}/iocs", response_model=list[IOC])
    def iocs_api(report_id: str):
        return find_report(report_id).iocs

    @app.get("/api/reports/{report_id}/markdown", response_class=Response)
    def markdown_api(report_id: str):
        return Response(
            find_report(report_id).report_markdown,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{report_id}.md"'},
        )

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        reports, _ = store.list_reports(6)
        return templates.TemplateResponse(request, "index.html", {
            "reports": reports, "max_upload_mb": config.max_upload_mb,
            "requires_key": bool(config.upload_api_key.get_secret_value()),
        })

    @app.get("/reports", response_class=HTMLResponse)
    def reports_page(
        request: Request,
        q: Annotated[str, Query(max_length=200)] = "",
        page: Annotated[int, Query(ge=1)] = 1,
    ):
        reports, total = store.list_reports(20, (page - 1) * 20, q)
        return templates.TemplateResponse(request, "reports.html", {
            "reports": reports, "total": total, "q": q, "page": page,
        })

    @app.get("/reports/{report_id}", response_class=HTMLResponse)
    def report_page(request: Request, report_id: str):
        report = find_report(report_id)
        return templates.TemplateResponse(request, "report.html", {
            "report": report, "rendered_markdown": render_markdown(report.report_markdown),
        })

    return app


app = create_app()
