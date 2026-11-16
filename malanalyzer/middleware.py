from fastapi import HTTPException
from starlette.responses import JSONResponse


class UploadLimitMiddleware:
    """Limit multipart traffic before FastAPI spools the request's file to disk."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/api/samples" or scope["method"] != "POST":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            return await JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)(scope, receive, send)
        if declared > self.max_bytes:
            return await JSONResponse({"detail": "Upload request is too large."}, status_code=413)(scope, receive, send)
        total = 0

        async def bounded_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    raise HTTPException(413, "Upload request is too large.")
            return message

        await self.app(scope, bounded_receive, send)
