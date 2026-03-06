# Secure File Server

Simple file server with:
- Public file download (`GET /files/<name>`)
- Password-protected upload (`POST /upload` with HTTP Basic auth)
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
# update .env with a strong UPLOAD_PASSWORD before enabling uploads
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
