FROM python:3.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY dashboard/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboard/ /app/
COPY pentest/ /app/pentest/
COPY scripts/ /app/scripts/

EXPOSE 5050
ENV PYTHONUNBUFFERED=1
ENV PORT=5050

CMD ["python", "app.py"]
