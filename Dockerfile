# Multi-stage optimized Dockerfile for PR Security Linter
FROM python:3.11-slim

LABEL maintainer="Hồ Minh Tuấn <minhtuanho120912@gmail.com>"
LABEL org.opencontainers.image.title="PR Security Linter"
LABEL org.opencontainers.image.description="Fast, lightweight security linter & secret scanner for Git pull requests and local repositories"
LABEL org.opencontainers.image.version="0.9.0"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Install git for git diff operations
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies and package
COPY requirements.txt pyproject.toml README.md ./
COPY pr_security_linter ./pr_security_linter
COPY codex_security_linter ./codex_security_linter
COPY benchmarks ./benchmarks
COPY scanner.py .
COPY .pr-security.yml .

RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -e .

ENTRYPOINT ["pr-security-linter"]
CMD ["--local"]
