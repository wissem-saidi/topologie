# Build stage
FROM python:3.11-slim as builder

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    nmap \
    netcat && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    nmap \
    netcat && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -u 1001 appuser

COPY --from=builder /opt/venv /opt/venv
COPY . .

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH"
ENV FLASK_APP=app.py

# Application permissions
RUN chmod +x entrypoint.sh && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 5000
ENTRYPOINT ["./entrypoint.sh"]