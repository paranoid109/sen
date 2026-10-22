"""Unit tests for Core Security Utilities: Bcrypt, PyJWT, and API Keys."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi import HTTPException

from backend.app.core.security import (
    create_access_token,
    decode_access_token,
    hash_api_key,
    hash_password,
    verify_password,
)


def test_password_hashing_and_verification():
    raw_pwd = "SuperSecretPassword123!"
    hashed = hash_password(raw_pwd)

    assert hashed != raw_pwd
    assert verify_password(raw_pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_password_longer_than_72_bytes_safe():
    long_pwd = "A" * 100
    hashed = hash_password(long_pwd)

    assert verify_password(long_pwd, hashed) is True
    # Due to explicit 72-byte truncation, first 72 'A's verify
    assert verify_password("A" * 72, hashed) is True
    assert verify_password("B" * 100, hashed) is False


def test_jwt_create_and_decode():
    payload = {"sub": "user-uuid-1234", "role": "Analyst"}
    token = create_access_token(payload)

    decoded = decode_access_token(token)
    assert decoded["sub"] == "user-uuid-1234"
    assert decoded["role"] == "Analyst"
    assert "exp" in decoded
    assert "iat" in decoded


def test_expired_jwt_raises_http_401():
    payload = {"sub": "user-uuid-1234", "role": "Analyst"}
    token = create_access_token(payload, expires_delta=timedelta(seconds=-10))

    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(token)
    assert exc_info.value.status_code == 401
    assert "Token has expired" in exc_info.value.detail


def test_api_key_hashing_deterministic():
    key = "sen_ingest_test_secret_key"
    hash1 = hash_api_key(key)
    hash2 = hash_api_key(key)

    assert len(hash1) == 64
    assert hash1 == hash2
    assert hash1 != hash_api_key("different_key")
