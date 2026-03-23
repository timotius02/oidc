import time
from collections import defaultdict
from dataclasses import dataclass, field

from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response


@dataclass
class RateLimitBucket:
    """Sliding window rate limit bucket."""

    timestamps: list[float] = field(default_factory=list)


class RateLimitStore:
    """In-memory rate limit store with automatic cleanup."""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._buckets: dict[str, RateLimitBucket] = defaultdict(RateLimitBucket)
        self._last_cleanup: float = time.time()
        self._cleanup_interval: int = 300  # Clean up every 5 minutes

    def _cleanup(self) -> None:
        """Remove expired entries to prevent memory leaks."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        cutoff = now - self.window_seconds
        expired_keys = []
        for key, bucket in self._buckets.items():
            bucket.timestamps = [ts for ts in bucket.timestamps if ts > cutoff]
            if not bucket.timestamps:
                expired_keys.append(key)

        for key in expired_keys:
            del self._buckets[key]

        self._last_cleanup = now

    def check_and_increment(self, key: str, limit: int) -> tuple[bool, int, int]:
        """
        Check if request is within rate limit and increment counter.

        Args:
            key: Unique identifier (e.g., IP address or client_id)
            limit: Maximum requests allowed in the window

        Returns:
            Tuple of (allowed, remaining, retry_after_seconds)
        """
        self._cleanup()

        now = time.time()
        bucket = self._buckets[key]

        # Remove timestamps outside the window
        cutoff = now - self.window_seconds
        bucket.timestamps = [ts for ts in bucket.timestamps if ts > cutoff]

        current_count = len(bucket.timestamps)

        if current_count >= limit:
            oldest = min(bucket.timestamps) if bucket.timestamps else now
            retry_after = int(oldest + self.window_seconds - now) + 1
            return False, 0, retry_after

        bucket.timestamps.append(now)
        remaining = limit - current_count - 1
        return True, remaining, 0


# Global store
_rate_limit_store = RateLimitStore()


def get_client_ip(request: Request) -> str:
    """Extract client IP, respecting X-Forwarded-For for proxied requests."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using sliding window algorithm.

    Applies rate limits per client IP address.
    Configurable limits for different endpoint patterns.
    """

    def __init__(
        self,
        app,
        default_limit: int = 100,
        window_seconds: int = 60,
        endpoint_limits: dict[str, int] | None = None,
    ):
        super().__init__(app)
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.endpoint_limits = endpoint_limits or {
            "/oauth/token": 30,
            "/oauth/revoke": 30,
            "/auth/login": 10,
            "/auth/register": 5,
        }
        # Update the global store's window
        _rate_limit_store.window_seconds = window_seconds

    def _get_limit_for_path(self, path: str) -> int:
        """Get rate limit for a specific path."""
        for endpoint, limit in self.endpoint_limits.items():
            if path.startswith(endpoint):
                return limit
        return self.default_limit

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        client_ip = get_client_ip(request)
        path = request.url.path
        limit = self._get_limit_for_path(path)

        # Create a unique key per IP + endpoint
        key = f"{client_ip}:{path}"
        allowed, remaining, retry_after = _rate_limit_store.check_and_increment(
            key, limit
        )

        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)

        # Add rate limit headers to all responses
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response
