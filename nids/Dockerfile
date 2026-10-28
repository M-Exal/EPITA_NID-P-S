FROM python:3.10-slim

# iptables et tcpdump sont requis pour la capture Scapy et le blocage NIPS
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    iptables \
    libpcap-dev \
    gcc \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["python", "nids.py"]
