from __future__ import annotations

import hmac
import os
import tempfile
from pathlib import Path
from typing import Iterator

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

# Base directory for all stored files.
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "./data")).resolve()
# Uploads are denied unless this is explicitly set to true.
UPLOAD_ENABLED = os.getenv("UPLOAD_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
UPLOAD_USERNAME = os.getenv("UPLOAD_USERNAME", "uploader")
UPLOAD_PASSWORD = os.getenv("UPLOAD_PASSWORD", "")
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
ALLOW_OVERWRITE = os.getenv("ALLOW_OVERWRITE", "false").lower() in {"1", "true", "yes", "on"}

basic_auth = HTTPBasic(auto_error=False)

app = FastAPI(title="Secure File Server", docs_url=None, redoc_url=None)


@app.on_event("startup")
def startup() -> None:
    STORAGE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


def secure_path(relative_path: str) -> Path:
    if not relative_path or "\\" in relative_path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    candidate = (STORAGE_DIR / relative_path).resolve()
    try:
        candidate.relative_to(STORAGE_DIR)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found") from exc

    return candidate


def require_upload_auth(credentials: HTTPBasicCredentials | None = Depends(basic_auth)) -> None:
    if not UPLOAD_ENABLED:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Uploads are disabled")

    if not UPLOAD_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Upload password not configured",
        )

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )

    username_ok = hmac.compare_digest(credentials.username, UPLOAD_USERNAME)
    password_ok = hmac.compare_digest(credentials.password, UPLOAD_PASSWORD)
    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


def iter_chunks(upload: UploadFile, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
    while True:
        chunk = upload.file.read(chunk_size)
        if not chunk:
            break
        yield chunk


@app.get("/")
def health() -> JSONResponse:
    return JSONResponse(
        {
            "service": "secure-file-server",
            "download_endpoint": "/files/{filename}",
            "upload_endpoint": "/upload",
            "upload_enabled": UPLOAD_ENABLED,
        }
    )


@app.get("/files/{file_path:path}")
def download_file(file_path: str):
    target = secure_path(file_path)
    if not target.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    return FileResponse(path=target)


@app.post("/upload")
def upload_file(
    file: UploadFile = File(...),
    _: None = Depends(require_upload_auth),
) -> JSONResponse:
    safe_name = Path(file.filename or "").name
    if not safe_name or safe_name in {".", ".."}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")
    if safe_name != (file.filename or ""):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")

    target = secure_path(safe_name)
    if target.exists() and not ALLOW_OVERWRITE:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="File already exists")

    total_size = 0
    fd, tmp_path = tempfile.mkstemp(prefix="upload-", dir=str(STORAGE_DIR))

    try:
        with os.fdopen(fd, "wb") as tmp_file:
            for chunk in iter_chunks(file):
                total_size += len(chunk)
                if total_size > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds limit of {MAX_UPLOAD_BYTES} bytes",
                    )
                tmp_file.write(chunk)

        os.replace(tmp_path, target)
        os.chmod(target, 0o600)
    except HTTPException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
    except Exception as exc:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Upload failed") from exc
    finally:
        file.file.close()

    return JSONResponse(
        {
            "filename": safe_name,
            "bytes": total_size,
            "message": "Upload successful",
        },
        status_code=status.HTTP_201_CREATED,
    )
