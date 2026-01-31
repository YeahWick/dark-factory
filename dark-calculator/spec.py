"""
Specification layer for the Dark Factory pattern.

A Spec defines the *contract* an implementation must satisfy.
It is purely declarative - it says WHAT must be true, not HOW.

Each spec is a named property with:
  - a human-readable description
  - a callable predicate that returns True if the property holds
  - the bounds under which the property is guaranteed
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from bounds import Bounds


# ---------------------------------------------------------------------------
# Core spec primitives
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Property:
    """A single verifiable property of an implementation."""

    name: str
    description: str
    predicate: Callable[..., bool]
    bounds: Bounds

    def check(self, *args: Any) -> bool:
        """Evaluate the property predicate with the given arguments."""
        return self.predicate(*args)


@dataclass
class Spec:
    """An ordered collection of properties that together form a contract."""

    name: str
    properties: list[Property] = field(default_factory=list)

    def add(self, prop: Property) -> None:
        self.properties.append(prop)

    def __iter__(self):
        return iter(self.properties)

    def __len__(self):
        return len(self.properties)


# ---------------------------------------------------------------------------
# Calculator operation protocol - what an implementation must look like
# ---------------------------------------------------------------------------

class CalculatorOp(Protocol):
    """Protocol that any calculator operation must satisfy."""

    def __call__(self, a: int, b: int) -> int: ...


# ---------------------------------------------------------------------------
# Spec builders for arithmetic operations
# ---------------------------------------------------------------------------

def addition_spec(bounds: Bounds) -> Spec:
    """Build the full specification for bounded integer addition."""
    lo, hi = bounds.lo, bounds.hi

    spec = Spec(name="addition")

    spec.add(Property(
        name="closure",
        description="Result stays within bounds",
        predicate=lambda add, a, b: lo <= add(a, b) <= hi,
        bounds=bounds,
    ))

    spec.add(Property(
        name="commutativity",
        description="a + b == b + a",
        predicate=lambda add, a, b: add(a, b) == add(b, a),
        bounds=bounds,
    ))

    spec.add(Property(
        name="identity",
        description="a + 0 == a",
        predicate=lambda add, a: add(a, 0) == a,
        bounds=bounds,
    ))

    spec.add(Property(
        name="associativity",
        description="(a + b) + c == a + (b + c)  [when raw intermediates stay in bounds]",
        predicate=lambda add, a, b, c: (
            # Only assert when neither intermediate overflows
            not (lo <= a + b <= hi) or
            not (lo <= b + c <= hi) or
            add(add(a, b), c) == add(a, add(b, c))
        ),
        bounds=bounds,
    ))

    return spec


def subtraction_spec(bounds: Bounds) -> Spec:
    """Build the full specification for bounded integer subtraction."""
    lo, hi = bounds.lo, bounds.hi

    spec = Spec(name="subtraction")

    spec.add(Property(
        name="closure",
        description="Result stays within bounds",
        predicate=lambda sub, a, b: lo <= sub(a, b) <= hi,
        bounds=bounds,
    ))

    spec.add(Property(
        name="identity",
        description="a - 0 == a",
        predicate=lambda sub, a: sub(a, 0) == a,
        bounds=bounds,
    ))

    spec.add(Property(
        name="self_inverse",
        description="a - a == 0",
        predicate=lambda sub, a: sub(a, a) == 0,
        bounds=bounds,
    ))

    return spec


def multiplication_spec(bounds: Bounds) -> Spec:
    """Build the full specification for bounded integer multiplication."""
    lo, hi = bounds.lo, bounds.hi

    spec = Spec(name="multiplication")

    spec.add(Property(
        name="closure",
        description="Result stays within bounds",
        predicate=lambda mul, a, b: lo <= mul(a, b) <= hi,
        bounds=bounds,
    ))

    spec.add(Property(
        name="commutativity",
        description="a * b == b * a",
        predicate=lambda mul, a, b: mul(a, b) == mul(b, a),
        bounds=bounds,
    ))

    spec.add(Property(
        name="identity",
        description="a * 1 == a",
        predicate=lambda mul, a: mul(a, 1) == a,
        bounds=bounds,
    ))

    spec.add(Property(
        name="zero",
        description="a * 0 == 0",
        predicate=lambda mul, a: mul(a, 0) == 0,
        bounds=bounds,
    ))

    return spec


def division_spec(bounds: Bounds) -> Spec:
    """Build the full specification for bounded integer division."""
    lo, hi = bounds.lo, bounds.hi

    spec = Spec(name="division")

    spec.add(Property(
        name="closure",
        description="Result stays within bounds",
        predicate=lambda div, a, b: lo <= div(a, b) <= hi,
        bounds=bounds,
    ))

    spec.add(Property(
        name="identity",
        description="a / 1 == a",
        predicate=lambda div, a: div(a, 1) == a,
        bounds=bounds,
    ))

    spec.add(Property(
        name="self",
        description="a / a == 1  (for a != 0)",
        predicate=lambda div, a: div(a, a) == 1,
        bounds=bounds,
    ))

    spec.add(Property(
        name="zero_numerator",
        description="0 / b == 0  (for b != 0)",
        predicate=lambda div, b: div(0, b) == 0,
        bounds=bounds,
    ))

    return spec
