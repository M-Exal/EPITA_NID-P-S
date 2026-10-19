# Analysis — image Docker de l'analyse des logs du honeypot Cowrie.
# pandas + matplotlib (backend Agg : aucune interface graphique nécessaire).
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyze.py .

# data/ est monté à /data par docker-compose.yml.
ENTRYPOINT ["python3", "analyze.py"]
CMD ["--log", "/data/cowrie/log/cowrie.json", "--out", "/data/analysis"]
