# Build context is the repository root, so the static UI ships in the image too
# and is served same-origin with the scan API. No CORS, no mixed content.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

COPY server/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY server/app ./app
# Every page at the repo root, so adding a guide needs no Dockerfile change.
COPY *.html ./static/

# Run unprivileged. The scanner only makes outbound requests; it needs no write
# access to its own code.
RUN useradd --create-home --shell /usr/sbin/nologin mapper \
 && chown -R mapper:mapper /srv
USER mapper

ENV STATIC_DIR=/srv/static

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/healthz', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
