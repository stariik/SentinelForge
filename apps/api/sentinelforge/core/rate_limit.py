"""In-process sliding-window rate limiter for authentication endpoints.

Deliberately dependency-free. A library (slowapi/limits) would add a dependency and
module-level global state that makes tests order-dependent, in exchange for features
this project does not use.

**Scope limit, stated honestly:** counters live in this process. Under multiple API
workers an attacker gets `attempts * worker_count` before throttling bites. That is the
one place in SentinelForge where Redis would be genuinely warranted — a shared counter
store — and it is why the dependency is absent today rather than added speculatively.
The per-account lockout in `services/auth.py` is database-backed and therefore *is*
shared across workers, so the two controls together degrade gracefully.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowRateLimiter:
    def __init__(self, *, max_attempts: int, window_seconds: float) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        hits = self._hits[key]
        cutoff = now - self.window_seconds
        while hits and hits[0] <= cutoff:
            hits.popleft()
        return hits

    def check(self, key: str, *, now: float | None = None) -> bool:
        """Record an attempt. Returns True if allowed, False if the window is full."""
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._prune(key, now)
            if len(hits) >= self.max_attempts:
                return False
            hits.append(now)
            return True

    def retry_after(self, key: str, *, now: float | None = None) -> int:
        """Seconds until the oldest attempt ages out of the window."""
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._prune(key, now)
            if not hits:
                return 0
            return max(0, int(self.window_seconds - (now - hits[0])) + 1)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


_login_limiter: SlidingWindowRateLimiter | None = None


def get_login_limiter() -> SlidingWindowRateLimiter:
    global _login_limiter
    if _login_limiter is None:
        from sentinelforge.core.config import get_settings

        settings = get_settings()
        _login_limiter = SlidingWindowRateLimiter(
            max_attempts=settings.login_rate_limit_attempts,
            window_seconds=settings.login_rate_limit_window_seconds,
        )
    return _login_limiter


def reset_login_limiter() -> None:
    """Test hook — keeps limiter state from leaking between test cases."""
    global _login_limiter
    _login_limiter = None
