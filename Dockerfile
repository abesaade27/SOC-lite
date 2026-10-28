FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server /app/server
COPY dashboard /app/dashboard

ENV HOST=0.0.0.0
ENV PORT=8000
ENV DB_PATH=/data/soc_lite.db

VOLUME ["/data"]

EXPOSE 8000

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
