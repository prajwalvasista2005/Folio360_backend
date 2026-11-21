"""Thread-safe process-local sliding-window IP rate limiter (Stage 3A)."""

from collections import OrderedDict, deque
import math
import threading
import time
from typing import Callable


class SlidingWindowRateLimiter:
    """Bounded in-memory sliding-window rate limiter keyed by (bucket, client_ip)."""

    def __init__(
        self,
        *,
        max_keys: int = 50_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_keys <= 0:
            raise ValueError("max_keys must be positive")
        self._max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()

    def check_and_record(
        self,
        bucket: str,
        client_ip: str,
        *,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, int]:
        """
        Check whether a request is allowed under (limit, window_seconds) and record it if allowed.

        Returns (allowed, retry_after_seconds).
        """
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("limit and window_seconds must be positive")

        now = self._clock()
        cutoff = now - window_seconds
        key = (bucket, client_ip)

        with self._lock:
            dq = self._buckets.get(key)
            if dq is None:
                dq = deque()
                self._buckets[key] = dq
            else:
                self._buckets.move_to_end(key)

            while dq and dq[0] <= cutoff:
                dq.popleft()

            if len(dq) >= limit:
                oldest = dq[0]
                retry_after = max(1, math.ceil(window_seconds - (now - oldest)))
                return False, retry_after

            dq.append(now)

            while len(self._buckets) > self._max_keys:
                self._buckets.popitem(last=False)

            return True, 0

    def clear(self) -> None:
        """Reset all tracked rate-limit buckets."""
        with self._lock:
            self._buckets.clear()
