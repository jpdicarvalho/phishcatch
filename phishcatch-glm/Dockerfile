FROM python:3.11-alpine

# Install whois and build tools for aiodns
RUN apk add --no-cache whois bind-tools build-base

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "phishcatch.py"]
