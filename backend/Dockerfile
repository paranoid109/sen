# Multi-stage / hardened Dockerfile for SentinelX FastAPI Backend (Python 3.13)
FROM python:3.13-slim

# Prevent Python from writing bytecode and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app:/app/backend"

WORKDIR /app

# Install security updates and build requirements
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Install pinned Python dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r ./backend/requirements.txt

# Copy source code and contracts
COPY backend/ ./backend/
COPY contracts/ ./contracts/
COPY modules/ ./modules/
COPY scripts/ ./scripts/
COPY pyproject.toml ./
COPY alembic.ini ./

# Create a non-privileged user and switch to it (Law 3 / Security Model)
RUN useradd -m -u 10001 sentinelx && \
    chown -R sentinelx:sentinelx /app
USER sentinelx

# Healthcheck against FastAPI /health probe
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

# Law 5: Explicitly run with --workers 1 to enforce single-process modular monolith invariants
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
