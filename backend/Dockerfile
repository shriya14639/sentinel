FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    SENTINEL_DB_PATH=/data/sentinel.db

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY anomaly_detection /app/anomaly_detection
COPY pipeline /app/pipeline
COPY genai_explanation /app/genai_explanation
COPY data/simulation /app/data/simulation

RUN mkdir -p /data && chown -R 10001:10001 /app /data
USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
