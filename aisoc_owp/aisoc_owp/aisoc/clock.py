import time


class Clock:
    """Injectable clock so expiry / replay behaviour is testable."""

    def __init__(self, fixed=None):
        self._fixed = fixed

    def now(self) -> int:
        return self._fixed if self._fixed is not None else int(time.time())

    def advance(self, seconds: int):
        assert self._fixed is not None, "advance() only on a fixed clock"
        self._fixed += seconds
