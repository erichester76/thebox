FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        arp-scan \
        net-tools \
        iputils-ping \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py device_classifier.py train_classifier.py ./

# Build the RF device-type classifier model at image build time so it is
# available in /app/models/device_classifier.pkl when the container starts.
# The training script embeds a representative synthetic dataset and can be
# augmented with the fingerbank open-source database — see train_classifier.py.
RUN python train_classifier.py

CMD ["python", "-u", "app.py"]
