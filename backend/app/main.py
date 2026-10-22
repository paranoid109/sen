"""SentinelX FastAPI Application Entrypoint.

Configures CORS, payload size limiters, health checks, lifecycle database initialization,
and in-process dispatcher shutdown draining.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.api.v1 import api_v1_router
from backend.app.core.config import settings
from backend.app.core.database import close_db, init_db
from backend.app.core.dispatcher import dispatcher

logger = logging.getLogger("sentinelx.api")


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Enforces request payload size limits to mitigate volumetric Denial-of-Service."""

    def __init__(self, app: FastAPI, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_bytes:
            return JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={
                    "detail": f"Payload exceeds maximum allowed size of {self.max_bytes} bytes"
                },
            )
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Manages application startup and graceful shutdown."""
    logger.info("Initializing SentinelX Core Platform (%s mode)...", settings.APP_ENV)
    await init_db()
    yield
    logger.info("Draining in-process dispatcher tasks before shutdown...")
    await dispatcher.drain(timeout=5.0)
    await close_db()
    logger.info("SentinelX Platform shutdown complete.")


app = FastAPI(
    title=settings.APP_NAME,
    description="Autonomous AI-Assisted Cybersecurity Detection & Incident Response Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# Middleware configuration
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.MAX_REQUEST_BODY_BYTES)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["System"])
async def health_check() -> dict[str, str]:
    """Liveness and readiness health check probe."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "env": settings.APP_ENV,
        "version": "1.0.0",
    }


# Mount API v1 Routers
app.include_router(api_v1_router)
