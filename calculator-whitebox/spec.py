"""Formal specification for the bounded calculator.

Each operation is specified as a collection of:
- preconditions: what inputs must satisfy before the operation
- postconditions: what the output must satisfy given valid inputs
- error conditions: what inputs must cause specific exceptions
- algebraic properties: mathematical relationships that must hold

The spec is machine-readable.  Validation tools iterate over it to
auto-generate conformance tests and search for counterexamples.

Layers
------
Bounds          domain constraints and overflow semantics
OperationSpec   per-operation contract (pre/post/error/properties)
BranchSpec      every decision point that white-box tests must cover
CalculatorSpec  the full contract for a configured calculator
build_spec()    constructs a CalculatorSpec for a given configuration
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable


# ---------------------------------------------------------------------------
# Configuration enums
# ---------------------------------------------------------------------------

class OverflowMode(Enum):
    CLAMP = auto()
    WRAP = auto()
    ERROR = auto()


class DivZeroMode(Enum):
    ERROR = auto()
    ZERO = auto()


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Bounds:
    """Inclusive integer interval [lo, hi]."""

    lo: int
    hi: int

    def __post_init__(self) -> None:
        if self.lo > self.hi:
            raise ValueError(f"lo ({self.lo}) must be <= hi ({self.hi})")

    def contains(self, v: int) -> bool:
        return self.lo <= v <= self.hi

    @property
    def width(self) -> int:
        return self.hi - self.lo + 1

    def all_values(self) -> range:
        return range(self.lo, self.hi + 1)

    def clamp(self, v: int) -> int:
        return max(self.lo, min(self.hi, v))

    def wrap(self, v: int) -> int:
        return self.lo + (v - self.lo) % self.width


# ---------------------------------------------------------------------------
# Spec building blocks
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Precondition:
    name: str
    description: str
    check: Callable[..., bool]


@dataclass(frozen=True)
class Postcondition:
    name: str
    description: str
    check: Callable[..., bool]


@dataclass(frozen=True)
class ErrorCondition:
    name: str
    description: str
    trigger: Callable[..., bool]
    exception: type


@dataclass(frozen=True)
class AlgebraicProperty:
    name: str
    description: str
    arity: int          # how many free input values the check needs
    check: Callable[..., bool]


@dataclass(frozen=True)
class OperationSpec:
    name: str
    preconditions: list[Precondition]
    postconditions: list[Postcondition]
    error_conditions: list[ErrorCondition]
    properties: list[AlgebraicProperty]


@dataclass(frozen=True)
class BranchSpec:
    """A decision point in the implementation that must be exercised."""

    id: str
    description: str
    condition: str      # human-readable boolean expression
    operation: str      # which operation / helper this belongs to


@dataclass(frozen=True)
class CalculatorSpec:
    """Complete contract for a configured calculator."""

    bounds: Bounds
    overflow_mode: OverflowMode
    div_zero_mode: DivZeroMode
    operations: dict[str, OperationSpec]
    branches: list[BranchSpec]

    @property
    def all_properties(self) -> list[tuple[str, AlgebraicProperty]]:
        out: list[tuple[str, AlgebraicProperty]] = []
        for name, op in self.operations.items():
            for prop in op.properties:
                out.append((name, prop))
        return out

    @property
    def all_postconditions(self) -> list[tuple[str, Postcondition]]:
        out: list[tuple[str, Postcondition]] = []
        for name, op in self.operations.items():
            for post in op.postconditions:
                out.append((name, post))
        return out


# ---------------------------------------------------------------------------
# Helpers used inside the spec predicates
# ---------------------------------------------------------------------------

def truncdiv(a: int, b: int) -> int:
    """Integer division truncating toward zero (not floor division).

    Python's ``//`` rounds toward negative infinity.  Most calculators
    and languages (C, Java, Rust) truncate toward zero instead.
    """
    q, r = divmod(a, b)
    # divmod rounds toward -inf; adjust when the result is negative
    # and there is a remainder.
    if r != 0 and (a < 0) != (b < 0):
        q += 1
    return q


# ---------------------------------------------------------------------------
# Spec builder
# ---------------------------------------------------------------------------

def build_spec(
    bounds: Bounds,
    overflow_mode: OverflowMode = OverflowMode.CLAMP,
    div_zero_mode: DivZeroMode = DivZeroMode.ERROR,
) -> CalculatorSpec:
    """Construct the full calculator specification for a configuration."""

    # -- overflow helper used in postconditions --
    def _apply(raw: int) -> int:
        if overflow_mode == OverflowMode.CLAMP:
            return bounds.clamp(raw)
        if overflow_mode == OverflowMode.WRAP:
            return bounds.wrap(raw)
        return raw  # ERROR mode: value is returned as-is by spec;
                     # the error condition handles out-of-bounds.

    # ------------------------------------------------------------------ add
    add_spec = OperationSpec(
        name="add",
        preconditions=[
            Precondition(
                "inputs_in_bounds",
                "Both inputs within bounds",
                lambda a, b: bounds.contains(a) and bounds.contains(b),
            ),
        ],
        postconditions=[
            Postcondition(
                "result_in_bounds",
                "Result is within bounds",
                lambda a, b, result: bounds.contains(result),
            ),
            Postcondition(
                "result_correct",
                "Result equals overflow-adjusted sum",
                lambda a, b, result: result == _apply(a + b),
            ),
        ],
        error_conditions=[
            ErrorCondition(
                "overflow_error",
                "OverflowError when sum out of bounds in ERROR mode",
                lambda a, b: (
                    overflow_mode == OverflowMode.ERROR
                    and not bounds.contains(a + b)
                ),
                OverflowError,
            ),
        ],
        properties=[
            AlgebraicProperty(
                "closure", "Result always in bounds", 2,
                lambda calc, a, b: bounds.contains(calc.add(a, b)),
            ),
            AlgebraicProperty(
                "commutativity", "add(a, b) == add(b, a)", 2,
                lambda calc, a, b: calc.add(a, b) == calc.add(b, a),
            ),
            AlgebraicProperty(
                "identity", "add(a, 0) == a when 0 in bounds", 2,
                lambda calc, a, _: (
                    calc.add(a, 0) == a if bounds.contains(0) else True
                ),
            ),
        ],
    )

    # ------------------------------------------------------------------ sub
    sub_spec = OperationSpec(
        name="sub",
        preconditions=[
            Precondition(
                "inputs_in_bounds",
                "Both inputs within bounds",
                lambda a, b: bounds.contains(a) and bounds.contains(b),
            ),
        ],
        postconditions=[
            Postcondition(
                "result_in_bounds",
                "Result is within bounds",
                lambda a, b, result: bounds.contains(result),
            ),
            Postcondition(
                "result_correct",
                "Result equals overflow-adjusted difference",
                lambda a, b, result: result == _apply(a - b),
            ),
        ],
        error_conditions=[
            ErrorCondition(
                "overflow_error",
                "OverflowError when difference out of bounds in ERROR mode",
                lambda a, b: (
                    overflow_mode == OverflowMode.ERROR
                    and not bounds.contains(a - b)
                ),
                OverflowError,
            ),
        ],
        properties=[
            AlgebraicProperty(
                "closure", "Result always in bounds", 2,
                lambda calc, a, b: bounds.contains(calc.sub(a, b)),
            ),
            AlgebraicProperty(
                "identity", "sub(a, 0) == a when 0 in bounds", 2,
                lambda calc, a, _: (
                    calc.sub(a, 0) == a if bounds.contains(0) else True
                ),
            ),
            AlgebraicProperty(
                "self_inverse", "sub(a, a) == 0 when 0 in bounds", 1,
                lambda calc, a: (
                    calc.sub(a, a) == 0 if bounds.contains(0) else True
                ),
            ),
        ],
    )

    # ------------------------------------------------------------------ mul
    mul_spec = OperationSpec(
        name="mul",
        preconditions=[
            Precondition(
                "inputs_in_bounds",
                "Both inputs within bounds",
                lambda a, b: bounds.contains(a) and bounds.contains(b),
            ),
        ],
        postconditions=[
            Postcondition(
                "result_in_bounds",
                "Result is within bounds",
                lambda a, b, result: bounds.contains(result),
            ),
            Postcondition(
                "result_correct",
                "Result equals overflow-adjusted product",
                lambda a, b, result: result == _apply(a * b),
            ),
        ],
        error_conditions=[
            ErrorCondition(
                "overflow_error",
                "OverflowError when product out of bounds in ERROR mode",
                lambda a, b: (
                    overflow_mode == OverflowMode.ERROR
                    and not bounds.contains(a * b)
                ),
                OverflowError,
            ),
        ],
        properties=[
            AlgebraicProperty(
                "closure", "Result always in bounds", 2,
                lambda calc, a, b: bounds.contains(calc.mul(a, b)),
            ),
            AlgebraicProperty(
                "commutativity", "mul(a, b) == mul(b, a)", 2,
                lambda calc, a, b: calc.mul(a, b) == calc.mul(b, a),
            ),
            AlgebraicProperty(
                "identity", "mul(a, 1) == a when 1 in bounds", 2,
                lambda calc, a, _: (
                    calc.mul(a, 1) == a if bounds.contains(1) else True
                ),
            ),
            AlgebraicProperty(
                "zero", "mul(a, 0) == 0 when 0 in bounds", 2,
                lambda calc, a, _: (
                    calc.mul(a, 0) == 0 if bounds.contains(0) else True
                ),
            ),
        ],
    )

    # ------------------------------------------------------------------ div
    div_spec = OperationSpec(
        name="div",
        preconditions=[
            Precondition(
                "inputs_in_bounds",
                "Both inputs within bounds",
                lambda a, b: bounds.contains(a) and bounds.contains(b),
            ),
        ],
        postconditions=[
            Postcondition(
                "result_in_bounds",
                "Result is within bounds (when no error)",
                lambda a, b, result: bounds.contains(result),
            ),
            Postcondition(
                "result_correct",
                "Result equals overflow-adjusted truncating quotient (or 0 on div-by-zero ZERO mode)",
                lambda a, b, result: (
                    result == 0 if b == 0
                    else result == _apply(truncdiv(a, b))
                ),
            ),
        ],
        error_conditions=[
            ErrorCondition(
                "div_by_zero_error",
                "ZeroDivisionError when divisor is zero in ERROR mode",
                lambda a, b: b == 0 and div_zero_mode == DivZeroMode.ERROR,
                ZeroDivisionError,
            ),
            ErrorCondition(
                "overflow_error",
                "OverflowError when quotient out of bounds in ERROR mode",
                lambda a, b: (
                    b != 0
                    and overflow_mode == OverflowMode.ERROR
                    and not bounds.contains(truncdiv(a, b))
                ),
                OverflowError,
            ),
        ],
        properties=[
            AlgebraicProperty(
                "closure", "Result always in bounds (when no error)", 2,
                lambda calc, a, b: b == 0 or bounds.contains(calc.div(a, b)),
            ),
            AlgebraicProperty(
                "identity", "div(a, 1) == a when 1 in bounds", 2,
                lambda calc, a, _: (
                    calc.div(a, 1) == a if bounds.contains(1) else True
                ),
            ),
            AlgebraicProperty(
                "self", "div(a, a) == 1 for a != 0 when 1 in bounds", 1,
                lambda calc, a: (
                    a == 0 or calc.div(a, a) == 1
                    if bounds.contains(1) else True
                ),
            ),
            AlgebraicProperty(
                "zero_numerator",
                "div(0, b) == 0 for b != 0 when 0 in bounds", 1,
                lambda calc, b: (
                    b == 0 or calc.div(0, b) == 0
                    if bounds.contains(0) else True
                ),
            ),
        ],
    )

    # -------------------------------------------------------------- branches
    branches = [
        # Overflow handling (_apply_overflow)
        BranchSpec(
            "OVF-CLAMP-HI",
            "Result above hi, clamped to hi",
            "raw > bounds.hi and mode == CLAMP",
            "overflow",
        ),
        BranchSpec(
            "OVF-CLAMP-LO",
            "Result below lo, clamped to lo",
            "raw < bounds.lo and mode == CLAMP",
            "overflow",
        ),
        BranchSpec(
            "OVF-IN-BOUNDS",
            "Result within bounds, no adjustment",
            "bounds.lo <= raw <= bounds.hi",
            "overflow",
        ),
        BranchSpec(
            "OVF-WRAP",
            "Result wrapped via modular arithmetic",
            "raw out of bounds and mode == WRAP",
            "overflow",
        ),
        BranchSpec(
            "OVF-ERROR",
            "OverflowError raised",
            "raw out of bounds and mode == ERROR",
            "overflow",
        ),
        # Division specifics
        BranchSpec(
            "DIV-NORMAL",
            "Normal division (b != 0)",
            "b != 0",
            "div",
        ),
        BranchSpec(
            "DIV-ZERO-ERROR",
            "ZeroDivisionError on b == 0",
            "b == 0 and div_zero_mode == ERROR",
            "div",
        ),
        BranchSpec(
            "DIV-ZERO-RETURN",
            "Return 0 on b == 0",
            "b == 0 and div_zero_mode == ZERO",
            "div",
        ),
        BranchSpec(
            "DIV-TRUNCATE",
            "Truncation toward zero differs from floor division",
            "a % b != 0 and signs differ",
            "div",
        ),
        # Input validation
        BranchSpec(
            "INPUT-VALID",
            "Both inputs within bounds",
            "bounds.contains(a) and bounds.contains(b)",
            "validation",
        ),
        BranchSpec(
            "INPUT-INVALID-A",
            "First input out of bounds",
            "not bounds.contains(a)",
            "validation",
        ),
        BranchSpec(
            "INPUT-INVALID-B",
            "Second input out of bounds",
            "not bounds.contains(b)",
            "validation",
        ),
    ]

    return CalculatorSpec(
        bounds=bounds,
        overflow_mode=overflow_mode,
        div_zero_mode=div_zero_mode,
        operations={
            "add": add_spec,
            "sub": sub_spec,
            "mul": mul_spec,
            "div": div_spec,
        },
        branches=branches,
    )
