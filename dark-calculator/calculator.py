"""
Implementation layer for the Dark Factory pattern.

This module contains the actual arithmetic implementations.
Each operation is a plain function that:
  1. Performs the raw computation
  2. Applies the bounds to guarantee the result is in-domain

The implementations are intentionally simple.  The interesting part
is that the factory *proves* they satisfy their specs before handing
them out.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from bounds import Bounds


@dataclass(frozen=True)
class BoundedCalculator:
    """
    A calculator whose every operation is guaranteed to produce
    results within the configured bounds.
    """

    bounds: Bounds

    # -- core operations --------------------------------------------------

    def add(self, a: int, b: int) -> int:
        return self.bounds.apply(a + b)

    def sub(self, a: int, b: int) -> int:
        return self.bounds.apply(a - b)

    def mul(self, a: int, b: int) -> int:
        return self.bounds.apply(a * b)

    def div(self, a: int, b: int) -> int:
        if b == 0:
            return self.bounds.handle_div_zero()
        # Truncate toward zero (Python's // floors, so use int())
        raw = int(a / b)
        return self.bounds.apply(raw)

    # -- convenience ------------------------------------------------------

    def neg(self, a: int) -> int:
        return self.sub(0, a)

    def abs(self, a: int) -> int:
        return a if a >= 0 else self.neg(a)

    def pow(self, base: int, exp: int) -> int:
        """Bounded exponentiation (exp >= 0 only)."""
        if exp < 0:
            raise ValueError("negative exponents not supported")
        result = 1
        for _ in range(exp):
            result = self.mul(result, base)
        return result
