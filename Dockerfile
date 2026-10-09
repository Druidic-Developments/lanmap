FROM python:3.12-slim

# nmap: discovery + port/service scans. iproute2: `ip route` autodetect and `ss` for local ports.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap iproute2 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY lanmap ./lanmap

ENV LANMAP_DB=/data/lanmap.db \
    LANMAP_PORT=8080 \
    PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8080

CMD ["python", "-m", "lanmap"]
