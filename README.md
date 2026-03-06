# Secure File Server

Simple file server with:
- Public file download (`GET /files/<name>`)
- Password-protected upload (`POST /upload` with HTTP Basic auth)
- Authenticated web GUI (`/gui`) for file browsing and management
- Uploads denied by default (`UPLOAD_ENABLED=false`)

## Security controls
- Uploads are default-deny until explicitly enabled.
- Upload requires username + password.
- Constant-time credential comparison.
- Path traversal protection for all file paths.
- Upload filename sanitization.
- Max upload size limit.
- Atomic writes (`temp file` -> `os.replace`).
- Overwrite protection by default.
- Signed, expiring GUI session cookies.
- Security headers (`nosniff`, `DENY`, etc.).

## Run
```bash
cd secure-file-server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
set -a && source .env && set +a
uvicorn app:app --host 0.0.0.0 --port 8080
```

## Run With Docker Compose
```bash
cd secure-file-server
cp .env.example .env
# set a strong GUI_SESSION_SECRET and GUI_PASSWORD in .env
docker compose up --build -d
```

Stop:
```bash
docker compose down
```

Logs:
```bash
docker compose logs -f
```

## Use
Public download:
```bash
curl -O http://localhost:8080/files/example.txt
```

Password-protected upload (only works when `UPLOAD_ENABLED=true`):
```bash
curl -u uploader:change-me -F "file=@./example.txt" http://localhost:8080/upload
```

Unauthenticated upload is blocked:
```bash
curl -F "file=@./example.txt" http://localhost:8080/upload
# -> HTTP 401
```

## Web GUI
- Login page: `GET /gui/login`
- File manager: `GET /gui`
- Authenticated actions in GUI:
  - View all files
  - Upload files
  - Open public download links
  - Rename files
  - Delete files

Default GUI credentials use `GUI_USERNAME`/`GUI_PASSWORD`.
If these are not set, they fall back to `UPLOAD_USERNAME`/`UPLOAD_PASSWORD`.

Required for GUI login:
- `GUI_SESSION_SECRET` must be set (used to sign session cookies).
- `GUI_PASSWORD` (or `UPLOAD_PASSWORD`) must be set.

Note:
- API upload (`POST /upload`) still follows `UPLOAD_ENABLED`.
- GUI upload is allowed for authenticated GUI users.
