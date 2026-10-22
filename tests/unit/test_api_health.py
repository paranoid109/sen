"""Unit tests for FastAPI Application Entrypoint, Health Check, and Middlewares."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check_endpoint(client: AsyncClient):
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == "SentinelX"
    assert "version" in data


@pytest.mark.asyncio
async def test_request_size_limit_middleware(client: AsyncClient):
    # Send request with content-length exceeding 1MB (1,048,576 bytes)
    headers = {"content-length": str(1_048_577)}
    response = await client.post("/health", headers=headers, content=b"payload")
    assert response.status_code == 413
    assert "Payload exceeds maximum allowed size" in response.text
