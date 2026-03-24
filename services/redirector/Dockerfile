FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        iptables \
        iproute2 \
        net-tools \
        libpcap-dev \
        procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY notifier.py .

CMD ["python", "-u", "app.py"]
