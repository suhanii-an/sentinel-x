"""In-process fixed-window rate limiter.

Deliberately simple.  A single-node modular monolith does not need Redis to
enforce a per-client budget, and pretending otherwise would be exactly the kind
of architecture-for-show this project avoids.  The limitation is documented:
counters are per-process, so a multi-worker deployment gets N x the configured
budget.  ``docs/deployment.md`` explains when to move this to Redis.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict


class FixedWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int, int]:
        """Return ``(allowed, remaining, retry_after_seconds)``."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            bucket = self._hits[key]
            # Drop expired hits in place.
            bucket[:] = [t for t in bucket if t > cutoff]
            if len(bucket) >= self.limit:
                retry_after = max(1, int(self.window - (now - bucket[0])))
                return False, 0, retry_after
            bucket.append(now)
            return True, self.limit - len(bucket), 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
