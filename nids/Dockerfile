# NIDS — image Docker
# Basée sur python-slim ; tcpdump/libpcap sont nécessaires à Scapy pour sniffer.
FROM python:3.12-slim

# Dépendances système pour la capture de paquets (libpcap).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code du NIDS.
COPY config.py crypto_utils.py alerting.py detectors.py nids.py ./

# Dossier des données (alertes, pcap, clé) — monté en volume.
RUN mkdir -p /app/data
VOLUME ["/app/data"]

# Capture en continu ; l'arrêt (docker stop) déclenche le rapport chiffré.
ENTRYPOINT ["python3", "nids.py"]
