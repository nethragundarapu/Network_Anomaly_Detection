# ========================================================
# SENTINEL AI // PRODUCTION DOCKERFILE
# Multi-stage optimized, secure non-root container image
# ========================================================

FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies into wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# Final Runtime Stage
FROM python:3.12-slim AS runner

WORKDIR /app

# Create non-root user for cybersecurity compliance
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

# Copy dependencies from builder
COPY --from=builder /root/.local /home/sentinel/.local
ENV PATH=/home/sentinel/.local/bin:$PATH

# Copy application files
COPY . .

# Ensure correct permissions
RUN chown -R sentinel:sentinel /app
USER sentinel

# Expose Web Application port (FastAPI SOC Web App)
EXPOSE 8000

# Healthcheck probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

# Default command: Launch Flagship Web App
CMD ["python", "-m", "uvicorn", "webapp.server:app", "--host", "0.0.0.0", "--port", "8000"]
