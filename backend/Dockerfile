# Backend image: FastAPI + uvicorn, non-root, with tshark for PCAP parsing and
# Semgrep (installed via requirements.txt) for the Defense code-review engine.
FROM python:3.12-slim AS base

# tshark enables the PCAP ingestion feature; set INSTALL_TSHARK=false to slim the image.
ARG INSTALL_TSHARK=true
# Semgrep runs fully offline against the bundled local ruleset: no version check,
# no metrics upload. The CLI flags set the same, these are belt-and-suspenders.
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates \
    && if [ "$INSTALL_TSHARK" = "true" ]; then \
         DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark; \
       fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# Semgrep in its OWN venv so its dependency tree never collides with the app's
# pinned pydantic. Only the launcher is exposed on PATH; the app calls it via
# subprocess. Keep the pin in sync with the engine and CI.
ARG SEMGREP_VERSION=1.184.0
RUN python -m venv /opt/semgrep-venv \
    && /opt/semgrep-venv/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep \
    && semgrep --version

COPY app ./app

# Run as an unprivileged user; data dir is a mounted volume owned by this user.
RUN useradd -u 10001 -m appuser && mkdir -p /data && chown -R appuser:appuser /data /app
USER appuser

ENV ADCC_DATA_DIR=/data \
    ADCC_DB_PATH=/data/adcc.db \
    ADCC_UPLOAD_DIR=/data/uploads \
    ADCC_PCAP_DIR=/data/pcaps \
    ADCC_ENVIRONMENT=production

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
