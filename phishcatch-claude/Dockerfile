# ─── PhishCatch v2.0 ──────────────────────────────────────────
# Lean, reproducible container for the security analysis tool
# ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install OS-level networking and WHOIS utilities required at runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        whois \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY phishcatch.py .
COPY test_phishcatch.py .

# Create a non-root user for security best practices
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

# Default entrypoint runs PhishCatch
ENTRYPOINT ["python", "phishcatch.py"]
