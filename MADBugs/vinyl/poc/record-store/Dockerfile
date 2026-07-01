FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ ./templates/
COPY static/ ./static/

EXPOSE 8000
# waitress with a single thread so submitted reviews accumulate in a single
# in-process list. Keeps HTTP/1.1 connections alive for Varnish's backend pool
# (gunicorn's sync worker closes after every response, which would prevent
# the smuggle from replaying into the next victim bereq).
ENV PYTHONUNBUFFERED=1
# 32 threads so an attacker's hung smuggles (waiting on body bytes that never
# arrive) don't starve out legitimate traffic. Realistic for a small shop —
# most production WSGI stacks run 8-64 workers/threads.
CMD ["python3", "-u", "-c", "from app import app; import logging; logging.basicConfig(level=logging.INFO); import waitress; waitress.serve(app, host='0.0.0.0', port=8000, threads=128, channel_timeout=10)"]
