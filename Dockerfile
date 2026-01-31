# Multi-stage Dockerfile for snitch-stitch CLI tool

FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy package definition
COPY pyproject.toml ./

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/snitch-stitch /usr/local/bin/snitch-stitch

# Copy source code
COPY src/ ./src/

# Create non-root user
RUN useradd -m -u 1000 snitchuser && \
    chown -R snitchuser:snitchuser /app

USER snitchuser

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Entry point
ENTRYPOINT ["snitch-stitch"]
CMD ["--help"]
