"""
Bounds layer for the Dark Factory pattern.

Bounds define the *domain* within which an implementation is guaranteed
to satisfy its spec.  Outside the bounds, behaviour is explicitly
undefined - the factory makes no promises.

This module also provides clamping and saturation strategies for handling
values that would escape the bounds.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable


class OverflowStrategy(Enum):
    """What to do when a result would exceed the bounds."""

    CLAMP = auto()       # Saturate at lo/hi
    WRAP = auto()        # Modular wrap-around (like C unsigned)
    ERROR = auto()       # Raise an OverflowError


class DivisionByZeroStrategy(Enum):
    """What to do on division by zero."""

    ERROR = auto()       # Raise ZeroDivisionError
    RETURN_ZERO = auto() # Return 0 (total function)
    RETURN_MAX = auto()  # Return hi (saturate to "infinity")


@dataclass(frozen=True)
class Bounds:
    """
    An integer domain [lo, hi] with explicit overflow semantics.

    This is the core constraint that the dark factory enforces:
    every output is guaranteed to live in [lo, hi].
    """

    lo: int
    hi: int
    overflow: OverflowStrategy = OverflowStrategy.CLAMP
    div_zero: DivisionByZeroStrategy = DivisionByZeroStrategy.ERROR

    def __post_init__(self):
        if self.lo > self.hi:
            raise ValueError(f"lo ({self.lo}) must be <= hi ({self.hi})")

    @property
    def width(self) -> int:
        """Total number of representable values."""
        return self.hi - self.lo + 1

    def contains(self, value: int) -> bool:
        return self.lo <= value <= self.hi

    def apply(self, raw: int) -> int:
        """Apply the overflow strategy to bring a raw result into bounds."""
        if self.lo <= raw <= self.hi:
            return raw

        if self.overflow == OverflowStrategy.CLAMP:
            return max(self.lo, min(self.hi, raw))

        if self.overflow == OverflowStrategy.WRAP:
            return self.lo + (raw - self.lo) % self.width

        # ERROR
        raise OverflowError(
            f"Result {raw} is outside bounds [{self.lo}, {self.hi}]"
        )

    def handle_div_zero(self) -> int:
        """Return the value to use for division by zero, or raise."""
        if self.div_zero == DivisionByZeroStrategy.ERROR:
            raise ZeroDivisionError("division by zero")
        if self.div_zero == DivisionByZeroStrategy.RETURN_ZERO:
            return 0
        return self.hi  # RETURN_MAX


# ---------------------------------------------------------------------------
# Common bounds presets
# ---------------------------------------------------------------------------

INT8 = Bounds(lo=-128, hi=127)
INT16 = Bounds(lo=-32_768, hi=32_767)
INT32 = Bounds(lo=-(2**31), hi=2**31 - 1)
UINT8 = Bounds(lo=0, hi=255)
UINT16 = Bounds(lo=0, hi=65_535)
PERCENT = Bounds(lo=0, hi=100)

# Small bounds useful for exhaustive verification
TINY = Bounds(lo=-8, hi=7)
SMALL = Bounds(lo=-128, hi=127)
