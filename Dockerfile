FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup --system app \
    && adduser --system --ingroup app --home /nonexistent app \
    && mkdir -p /srv/data \
    && chown -R app:app /srv/data

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY --chown=app:app app.py /app/app.py

USER app

EXPOSE 8080

ENV STORAGE_DIR=/srv/data
ENV UPLOAD_ENABLED=false
ENV UPLOAD_USERNAME=uploader
ENV UPLOAD_PASSWORD=
ENV MAX_UPLOAD_BYTES=10485760
ENV ALLOW_OVERWRITE=false

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
