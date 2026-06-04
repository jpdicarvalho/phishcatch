FROM python:3.10-slim

WORKDIR /app

# Atualiza os pacotes do Linux e instala a ferramenta whois
RUN apt-get update && apt-get install -y whois && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY phishcatch.py .

ENTRYPOINT ["python", "phishcatch.py"]