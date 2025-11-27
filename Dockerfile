# ACDI Platform Docker Configuration
# IFG Quantum Holdings

FROM python:3.11-slim

# Install system dependencies including nmap
RUN apt-get update && apt-get install -y \
    nmap \
    openssl \
    libssl-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create necessary directories
RUN mkdir -p /app/data /app/logs

# Set Python path
ENV PYTHONPATH=/app/src

# Default port (Railway will override with $PORT)
ENV PORT=8000

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/v1/health || exit 1

# Run the API - use shell form to expand $PORT
CMD uvicorn src.api.main:app --host 0.0.0.0 --port ${PORT}
