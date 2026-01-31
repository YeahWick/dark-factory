"""Bounded calculator implementation.

Every operation validates inputs, performs the arithmetic, and applies
overflow handling before returning.  Decision branches are annotated
with their spec branch-IDs (see spec.py BranchSpec) so white-box tests
can trace coverage back to the specification.
"""
from __future__ import annotations

from dataclasses import dataclass

from spec import Bounds, OverflowMode, DivZeroMode


@dataclass(frozen=True)
class Calculator:
    bounds: Bounds
    overflow_mode: OverflowMode = OverflowMode.CLAMP
    div_zero_mode: DivZeroMode = DivZeroMode.ERROR

    # -- internal helpers ---------------------------------------------------

    def _validate(self, *values: int) -> None:
        """Reject inputs outside bounds.

        Branches: INPUT-VALID, INPUT-INVALID-A, INPUT-INVALID-B
        """
        for v in values:
            if not self.bounds.contains(v):                       # INPUT-INVALID-*
                raise ValueError(
                    f"{v} is outside bounds [{self.bounds.lo}, {self.bounds.hi}]"
                )
        # (falls through) INPUT-VALID

    def _apply_overflow(self, raw: int) -> int:
        """Map a raw arithmetic result into bounds.

        Branches: OVF-IN-BOUNDS, OVF-CLAMP-HI, OVF-CLAMP-LO, OVF-WRAP,
                  OVF-ERROR
        """
        if self.bounds.contains(raw):                             # OVF-IN-BOUNDS
            return raw

        if self.overflow_mode == OverflowMode.CLAMP:
            if raw > self.bounds.hi:                              # OVF-CLAMP-HI
                return self.bounds.hi
            return self.bounds.lo                                 # OVF-CLAMP-LO

        if self.overflow_mode == OverflowMode.WRAP:               # OVF-WRAP
            return self.bounds.wrap(raw)

        # OverflowMode.ERROR                                      # OVF-ERROR
        raise OverflowError(
            f"{raw} is outside bounds [{self.bounds.lo}, {self.bounds.hi}]"
        )

    # -- public operations --------------------------------------------------

    def add(self, a: int, b: int) -> int:
        """Addition with overflow handling."""
        self._validate(a, b)
        return self._apply_overflow(a + b)

    def sub(self, a: int, b: int) -> int:
        """Subtraction with overflow handling."""
        self._validate(a, b)
        return self._apply_overflow(a - b)

    def mul(self, a: int, b: int) -> int:
        """Multiplication with overflow handling."""
        self._validate(a, b)
        return self._apply_overflow(a * b)

    def div(self, a: int, b: int) -> int:
        """Integer division (truncating toward zero) with overflow handling.

        Branches: DIV-NORMAL, DIV-ZERO-ERROR, DIV-ZERO-RETURN, DIV-TRUNCATE
        """
        self._validate(a, b)

        if b == 0:
            if self.div_zero_mode == DivZeroMode.ERROR:           # DIV-ZERO-ERROR
                raise ZeroDivisionError("division by zero")
            return 0                                              # DIV-ZERO-RETURN

        # Truncating division toward zero.                        # DIV-NORMAL
        # Python's divmod rounds toward -inf; adjust when the
        # mathematical quotient is negative with a remainder.
        q, r = divmod(a, b)
        if r != 0 and (a < 0) != (b < 0):                        # DIV-TRUNCATE
            q += 1

        return self._apply_overflow(q)
