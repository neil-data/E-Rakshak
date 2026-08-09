# ingestion/Dockerfile
#
# Build context is the repository root (see docker-compose.yml) so that
# `from ingestion.india_scam_triage import ...` — an already-established
# package-qualified import in gateway.py — resolves the same way here as
# it does when run directly from the repo root during local dev.

FROM python:3.11-slim

WORKDIR /app

COPY ingestion/requirements.txt ingestion/requirements.txt
RUN pip install --no-cache-dir -r ingestion/requirements.txt

COPY ingestion ingestion

ENV PYTHONPATH=/app
EXPOSE 8001

CMD ["uvicorn", "ingestion.gateway:app", "--host", "0.0.0.0", "--port", "8001"]
