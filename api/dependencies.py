from __future__ import annotations

from collections import defaultdict, deque
from threading import Lock
import hmac
import os
import time
from typing import DefaultDict

from fastapi import Depends, HTTPException, Request, WebSocket
from fastapi.security import APIKeyHeader

from config import config

config.validate_runtime_requirements()

API_KEY = config.api.api_key
OPERATOR_API_KEY = os.getenv("OPERATOR_API_KEY", "").strip()
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)

_rate_limit_buckets: DefaultDict[str, deque[float]] = defaultdict(deque)
_rate_limit_lock = Lock()


_TRUSTED_PROXIES = {
    ip.strip()
    for ip in os.getenv("TRUSTED_PROXY_IPS", "").split(",")
    if ip.strip()
}
_MAX_TRACKED_IPS = 50_000


def verify_api_key(api_key: str = Depends(api_key_header)) -> str:
    if not hmac.compare_digest(api_key, API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API key.")
    return api_key


def verify_operator_api_key(api_key: str = Depends(api_key_header)) -> str:
    operator_key = OPERATOR_API_KEY or API_KEY
    if not hmac.compare_digest(api_key, operator_key):
        raise HTTPException(status_code=403, detail="Operator API key required.")
    return api_key


async def authorize_websocket(websocket: WebSocket) -> bool:
    """Authenticate browser WebSockets before accepting them."""
    origin = websocket.headers.get("origin")
    allowed_origins = {
        value.strip()
        for value in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:8000").split(",")
        if value.strip()
    }
    if origin and "*" not in allowed_origins and origin not in allowed_origins:
        await websocket.close(code=1008, reason="Origin not allowed")
        return False

    supplied_key = websocket.query_params.get("api_key", "")
    if not supplied_key or not hmac.compare_digest(supplied_key, API_KEY):
        await websocket.close(code=1008, reason="Authentication required")
        return False
    return True


def get_client_ip(request: Request) -> str:
    real_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and _TRUSTED_PROXIES and real_ip in _TRUSTED_PROXIES:
        return forwarded.split(",")[0].strip()
    return real_ip


def is_rate_limited(client_ip: str) -> bool:
    now = time.time()
    cutoff = now - config.api.rate_limit_window_seconds
    with _rate_limit_lock:
        # Evict oldest entry if memory cap reached
        if client_ip not in _rate_limit_buckets and len(_rate_limit_buckets) >= _MAX_TRACKED_IPS:
            oldest_ip = next(iter(_rate_limit_buckets))
            del _rate_limit_buckets[oldest_ip]
        bucket = _rate_limit_buckets[client_ip]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= config.api.rate_limit_requests:
            return True
        bucket.append(now)
        return False


def reset_rate_limits() -> None:
    with _rate_limit_lock:
        _rate_limit_buckets.clear()


def rate_limit_stats() -> dict:
    with _rate_limit_lock:
        active_clients = len(_rate_limit_buckets)
        current_depth = sum(len(bucket) for bucket in _rate_limit_buckets.values())
    return {
        "active_clients": active_clients,
        "tracked_requests": current_depth,
        "window_seconds": config.api.rate_limit_window_seconds,
        "requests_per_window": config.api.rate_limit_requests,
    }
