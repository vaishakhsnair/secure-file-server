from __future__ import annotations

import hashlib
import hmac
import html
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials


def bool_from_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


# Base directory for all stored files.
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", "./data")).resolve()
# Uploads are denied unless this is explicitly set to true.
UPLOAD_ENABLED = bool_from_env("UPLOAD_ENABLED", False)
UPLOAD_USERNAME = os.getenv("UPLOAD_USERNAME", "uploader")
UPLOAD_PASSWORD = os.getenv("UPLOAD_PASSWORD", "")
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
ALLOW_OVERWRITE = bool_from_env("ALLOW_OVERWRITE", False)

GUI_USERNAME = os.getenv("GUI_USERNAME", UPLOAD_USERNAME)
GUI_PASSWORD = os.getenv("GUI_PASSWORD", UPLOAD_PASSWORD)
GUI_SESSION_SECRET = os.getenv("GUI_SESSION_SECRET", "")
GUI_SESSION_TTL_SECONDS = int(os.getenv("GUI_SESSION_TTL_SECONDS", "28800"))
GUI_COOKIE_NAME = "gui_session"
GUI_COOKIE_SECURE = bool_from_env("GUI_COOKIE_SECURE", False)

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


def validate_upload_name(original_name: str) -> str:
    safe_name = Path(original_name or "").name
    if not safe_name or safe_name in {".", ".."}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")
    if safe_name != (original_name or ""):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid filename")
    return safe_name


def store_uploaded_file(file: UploadFile, safe_name: str) -> int:
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

    return total_size


def create_gui_session_token(username: str) -> str:
    if not GUI_SESSION_SECRET:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="GUI session secret not configured")

    issued = str(int(time.time()))
    payload = f"{username}:{issued}"
    sig = hmac.new(GUI_SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_gui_session_token(token: str) -> bool:
    if not token or not GUI_SESSION_SECRET:
        return False

    parts = token.split(":")
    if len(parts) != 3:
        return False

    username, issued_at, provided_sig = parts
    if username != GUI_USERNAME:
        return False

    if not issued_at.isdigit():
        return False

    issued = int(issued_at)
    if int(time.time()) - issued > GUI_SESSION_TTL_SECONDS:
        return False

    payload = f"{username}:{issued_at}"
    expected_sig = hmac.new(GUI_SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(provided_sig, expected_sig)


def require_gui_auth(request: Request) -> None:
    token = request.cookies.get(GUI_COOKIE_NAME, "")
    if not verify_gui_session_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def html_page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(
        f"""
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{html.escape(title)}</title>
  <style>
    :root {{ --bg: #0f172a; --card: #111827; --line: #374151; --fg: #e5e7eb; --muted: #9ca3af; --ok: #16a34a; --err: #dc2626; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; background: linear-gradient(180deg, #0f172a 0%, #111827 100%); color: var(--fg); }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
    .card {{ background: rgba(17, 24, 39, 0.95); border: 1px solid var(--line); border-radius: 14px; padding: 16px; margin-bottom: 14px; }}
    h1 {{ margin: 0 0 12px 0; font-size: 24px; }}
    p {{ margin: 8px 0; color: var(--muted); }}
    .row {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
    input[type=text], input[type=password], input[type=file] {{ background: #030712; color: var(--fg); border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; min-width: 220px; }}
    button {{ background: #0ea5e9; border: 0; color: white; border-radius: 8px; padding: 8px 10px; cursor: pointer; }}
    button.danger {{ background: var(--err); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: middle; }}
    th {{ color: var(--muted); font-weight: 600; }}
    code {{ color: #93c5fd; }}
    .msg-ok {{ color: #86efac; }}
    .msg-err {{ color: #fca5a5; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    a {{ color: #7dd3fc; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <div class=\"wrap\">{body}</div>
</body>
</html>
"""
    )


def list_file_rows(request: Request) -> str:
    rows: list[str] = []
    for file_path in sorted(STORAGE_DIR.rglob("*")):
        if not file_path.is_file():
            continue

        rel = file_path.relative_to(STORAGE_DIR).as_posix()
        stat = file_path.stat()
        modified = datetime.fromtimestamp(stat.st_mtime, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        download_path = f"/files/{quote(rel)}"
        base_url = str(request.base_url).rstrip("/")
        full_url = f"{base_url}{download_path}"

        rows.append(
            """
<tr>
  <td class=\"mono\">{rel}</td>
  <td>{size}</td>
  <td>{modified}</td>
  <td><a href=\"{dl}\" target=\"_blank\" rel=\"noopener noreferrer\">Download</a></td>
  <td class=\"mono\">{full}</td>
  <td>
    <form method=\"post\" action=\"/gui/rename\" class=\"row\">
      <input type=\"hidden\" name=\"path\" value=\"{rel}\">
      <input type=\"text\" name=\"new_name\" placeholder=\"new-name.ext\" required>
      <button type=\"submit\">Rename</button>
    </form>
  </td>
  <td>
    <form method=\"post\" action=\"/gui/delete\" onsubmit=\"return confirm('Delete this file?');\">
      <input type=\"hidden\" name=\"path\" value=\"{rel}\">
      <button class=\"danger\" type=\"submit\">Delete</button>
    </form>
  </td>
</tr>
""".format(
                rel=html.escape(rel),
                size=stat.st_size,
                modified=html.escape(modified),
                dl=html.escape(download_path),
                full=html.escape(full_url),
            )
        )

    if not rows:
        return '<tr><td colspan="7">No files found in storage.</td></tr>'
    return "".join(rows)


def gui_redirect(message: str = "", error: bool = False) -> RedirectResponse:
    key = "error" if error else "message"
    dest = "/gui"
    if message:
        dest = f"/gui?{key}={quote(message)}"
    return RedirectResponse(url=dest, status_code=status.HTTP_303_SEE_OTHER)


def validate_new_name(name: str) -> str:
    cleaned = Path(name).name
    if not cleaned or cleaned in {".", ".."} or cleaned != name or "/" in cleaned or "\\" in cleaned:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid new filename")
    return cleaned


@app.get("/")
def health() -> JSONResponse:
    return JSONResponse(
        {
            "service": "secure-file-server",
            "download_endpoint": "/files/{filename}",
            "upload_endpoint": "/upload",
            "gui_endpoint": "/gui",
            "upload_enabled": UPLOAD_ENABLED,
        }
    )


@app.get("/files/{file_path:path}")
def download_file(file_path: str):
    target = secure_path(file_path)
    if not target.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    return FileResponse(path=target, filename=target.name)


@app.post("/upload")
def upload_file(
    file: UploadFile = File(...),
    _: None = Depends(require_upload_auth),
) -> JSONResponse:
    safe_name = validate_upload_name(file.filename or "")
    total_size = store_uploaded_file(file, safe_name)

    return JSONResponse(
        {
            "filename": safe_name,
            "bytes": total_size,
            "message": "Upload successful",
        },
        status_code=status.HTTP_201_CREATED,
    )


@app.get("/gui/login")
def gui_login_page(message: str = "") -> HTMLResponse:
    msg_block = ""
    if message:
        msg_block = f'<p class="msg-err">{html.escape(message)}</p>'

    if not GUI_PASSWORD:
        return html_page(
            "GUI Login",
            f"""
<div class=\"card\">
  <h1>GUI Login Disabled</h1>
  <p class=\"msg-err\">Set <code>GUI_PASSWORD</code> (or <code>UPLOAD_PASSWORD</code>) to enable login.</p>
</div>
""",
        )

    return html_page(
        "GUI Login",
        f"""
<div class=\"card\">
  <h1>File Manager Login</h1>
  <p>Authenticate to view files and perform rename/delete operations.</p>
  {msg_block}
  <form method=\"post\" action=\"/gui/login\" class=\"row\">
    <input type=\"text\" name=\"username\" placeholder=\"Username\" required>
    <input type=\"password\" name=\"password\" placeholder=\"Password\" required>
    <button type=\"submit\">Login</button>
  </form>
</div>
""",
    )


@app.post("/gui/login")
def gui_login(username: str = Form(...), password: str = Form(...)) -> RedirectResponse:
    if not GUI_PASSWORD or not GUI_SESSION_SECRET:
        return RedirectResponse(
            url="/gui/login?message=Set%20GUI_PASSWORD%20and%20GUI_SESSION_SECRET",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    username_ok = hmac.compare_digest(username, GUI_USERNAME)
    password_ok = hmac.compare_digest(password, GUI_PASSWORD)
    if not (username_ok and password_ok):
        return RedirectResponse(url="/gui/login?message=Invalid%20credentials", status_code=status.HTTP_303_SEE_OTHER)

    token = create_gui_session_token(username)
    response = RedirectResponse(url="/gui", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=GUI_COOKIE_NAME,
        value=token,
        max_age=GUI_SESSION_TTL_SECONDS,
        httponly=True,
        secure=GUI_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/gui/logout")
def gui_logout() -> RedirectResponse:
    response = RedirectResponse(url="/gui/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key=GUI_COOKIE_NAME, path="/")
    return response


@app.get("/gui")
def gui_home(request: Request, message: str = "", error: str = "") -> HTMLResponse:
    if not verify_gui_session_token(request.cookies.get(GUI_COOKIE_NAME, "")):
        return RedirectResponse(url="/gui/login", status_code=status.HTTP_303_SEE_OTHER)

    message_html = ""
    if message:
        message_html = f'<p class="msg-ok">{html.escape(message)}</p>'
    if error:
        message_html = f'{message_html}<p class="msg-err">{html.escape(error)}</p>'

    return html_page(
        "File Manager",
        f"""
<div class=\"card\">
  <div class=\"row\" style=\"justify-content: space-between;\">
    <h1>File Manager</h1>
    <form method=\"post\" action=\"/gui/logout\"><button type=\"submit\">Logout</button></form>
  </div>
  <p>Public file links are visible below. Upload, rename, and delete require this authenticated session.</p>
  {message_html}
</div>
<div class=\"card\">
  <h1>Upload File</h1>
  <form method=\"post\" action=\"/gui/upload\" enctype=\"multipart/form-data\" class=\"row\">
    <input type=\"file\" name=\"file\" required>
    <button type=\"submit\">Upload</button>
  </form>
  <p>Max size: <code>{MAX_UPLOAD_BYTES}</code> bytes. Overwrite: <code>{str(ALLOW_OVERWRITE).lower()}</code></p>
</div>
<div class=\"card\">
  <table>
    <thead>
      <tr>
        <th>Path</th>
        <th>Bytes</th>
        <th>Modified</th>
        <th>Open</th>
        <th>Public Link</th>
        <th>Rename</th>
        <th>Delete</th>
      </tr>
    </thead>
    <tbody>
      {list_file_rows(request)}
    </tbody>
  </table>
</div>
""",
    )


@app.post("/gui/rename")
def gui_rename(
    request: Request,
    path: str = Form(...),
    new_name: str = Form(...),
) -> RedirectResponse:
    require_gui_auth(request)

    src = secure_path(path)
    if not src.is_file():
        return gui_redirect("File not found", error=True)

    safe_new_name = validate_new_name(new_name)
    dest = src.with_name(safe_new_name)

    if dest.exists():
        return gui_redirect("Target filename already exists", error=True)

    try:
        os.replace(src, dest)
    except Exception:
        return gui_redirect("Rename failed", error=True)

    return gui_redirect("File renamed")


@app.post("/gui/upload")
def gui_upload(request: Request, file: UploadFile = File(...)) -> RedirectResponse:
    require_gui_auth(request)

    try:
        safe_name = validate_upload_name(file.filename or "")
        store_uploaded_file(file, safe_name)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_400_BAD_REQUEST:
            return gui_redirect("Invalid filename", error=True)
        if exc.status_code == status.HTTP_409_CONFLICT:
            return gui_redirect("File already exists", error=True)
        if exc.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE:
            return gui_redirect(f"File too large (limit {MAX_UPLOAD_BYTES} bytes)", error=True)
        return gui_redirect("Upload failed", error=True)

    return gui_redirect("File uploaded")


@app.post("/gui/delete")
def gui_delete(request: Request, path: str = Form(...)) -> RedirectResponse:
    require_gui_auth(request)

    target = secure_path(path)
    if not target.is_file():
        return gui_redirect("File not found", error=True)

    try:
        target.unlink()
    except Exception:
        return gui_redirect("Delete failed", error=True)

    return gui_redirect("File deleted")
