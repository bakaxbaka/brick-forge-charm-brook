FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libgmp-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app
CMD ["python", "-u", "/app/scan_nonce_reuse.py", "--start", "210000", "--end", "220000", "--output", "/results/nonce_reuse.json"]
