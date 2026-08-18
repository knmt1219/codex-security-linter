# Multi-stage optimized Dockerfile for Codex Security Linter
FROM python:3.11-slim

LABEL maintainer="Hồ Minh Tuấn <minhtuanho120912@gmail.com>"
LABEL org.opencontainers.image.title="Codex Security Linter"
LABEL org.opencontainers.image.description="Automated AI-powered security linter & vulnerability auditor for Git repositories and Pull Requests"
LABEL org.opencontainers.image.version="2.2.0"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install git for local diff operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY scanner.py .
COPY .codex-security.yml .

ENTRYPOINT ["python", "/app/scanner.py"]
CMD ["--local"]
