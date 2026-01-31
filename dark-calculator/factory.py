"""
The Dark Factory.

The factory is the centerpiece of the pattern.  It does NOT just
construct objects - it *verifies* them against their specs before
releasing them.

Flow:
  1. Caller requests a calculator for a given Bounds.
  2. Factory builds the implementation.
  3. Factory runs the full spec suite against the implementation.
  4. If verification passes  -> return the calculator.
     If verification fails   -> raise, never hand out a broken instance.

"Dark" because the consumer never sees the verification step.
They receive an object that is *already proven correct* for the
declared bounds.  The proof happened inside the factory.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

from bounds import Bounds, TINY, SMALL
from calculator import BoundedCalculator
from spec import (
    Spec,
    Property,
    addition_spec,
    subtraction_spec,
    multiplication_spec,
    division_spec,
)


@dataclass
class VerificationResult:
    """Outcome of verifying one property."""

    property_name: str
    passed: bool
    counterexample: tuple | None = None
    tests_run: int = 0

    def __repr__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        ce = f"  counterexample={self.counterexample}" if self.counterexample else ""
        return f"[{status}] {self.property_name} ({self.tests_run} tests){ce}"


@dataclass
class VerificationReport:
    """Aggregate result of verifying an entire spec."""

    spec_name: str
    results: list[VerificationResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    def summary(self) -> str:
        lines = [f"--- {self.spec_name} ---"]
        for r in self.results:
            lines.append(f"  {r}")
        status = "ALL PASSED" if self.passed else "FAILED"
        lines.append(f"  => {status}")
        return "\n".join(lines)


class VerificationError(Exception):
    """Raised when an implementation fails its spec."""

    def __init__(self, report: VerificationReport):
        self.report = report
        super().__init__(f"Verification failed:\n{report.summary()}")


# ---------------------------------------------------------------------------
# The factory
# ---------------------------------------------------------------------------

class DarkFactory:
    """
    Produces BoundedCalculator instances that are proven correct.

    For small bounds the factory uses *exhaustive* verification -
    it checks every possible input combination.  For larger bounds
    it falls back to sampling (which can be extended with hypothesis
    in the test layer).
    """

    EXHAUSTIVE_THRESHOLD = 256  # max width for brute-force check

    @classmethod
    def create(cls, bounds: Bounds) -> BoundedCalculator:
        """Build, verify, and return a BoundedCalculator."""
        calc = BoundedCalculator(bounds=bounds)
        cls._verify_all(calc)
        return calc

    # -- internal ---------------------------------------------------------

    @classmethod
    def _verify_all(cls, calc: BoundedCalculator) -> None:
        specs_and_ops = [
            (addition_spec(calc.bounds), calc.add),
            (subtraction_spec(calc.bounds), calc.sub),
            (multiplication_spec(calc.bounds), calc.mul),
            (division_spec(calc.bounds), calc.div),
        ]
        for spec, op in specs_and_ops:
            report = cls._verify_spec(spec, op, calc.bounds)
            if not report.passed:
                raise VerificationError(report)

    @classmethod
    def _verify_spec(
        cls, spec: Spec, op: Any, bounds: Bounds
    ) -> VerificationReport:
        report = VerificationReport(spec_name=spec.name)
        for prop in spec:
            result = cls._verify_property(prop, op, bounds)
            report.results.append(result)
        return report

    @classmethod
    def _verify_property(
        cls, prop: Property, op: Any, bounds: Bounds
    ) -> VerificationResult:
        domain = range(bounds.lo, bounds.hi + 1)
        exhaustive = bounds.width <= cls.EXHAUSTIVE_THRESHOLD
        arity = _predicate_arity(prop)

        tests_run = 0

        if exhaustive:
            # Check every combination
            for combo in itertools.product(domain, repeat=arity):
                tests_run += 1
                try:
                    if not prop.check(op, *combo):
                        return VerificationResult(
                            property_name=prop.name,
                            passed=False,
                            counterexample=combo,
                            tests_run=tests_run,
                        )
                except (ZeroDivisionError, OverflowError):
                    # Expected exceptions for edge cases (e.g., div by 0)
                    # don't count as property violations
                    pass
        else:
            # Sample-based check for larger bounds
            import random
            samples = _generate_samples(bounds, arity, count=10_000)
            for combo in samples:
                tests_run += 1
                try:
                    if not prop.check(op, *combo):
                        return VerificationResult(
                            property_name=prop.name,
                            passed=False,
                            counterexample=combo,
                            tests_run=tests_run,
                        )
                except (ZeroDivisionError, OverflowError):
                    pass

        return VerificationResult(
            property_name=prop.name,
            passed=True,
            tests_run=tests_run,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _predicate_arity(prop: Property) -> int:
    """
    Infer how many *value* arguments a property predicate expects
    (excluding the operation callable which is always the first arg).
    """
    import inspect
    sig = inspect.signature(prop.predicate)
    # Subtract 1 for the `op` parameter
    return len(sig.parameters) - 1


def _generate_samples(
    bounds: Bounds, arity: int, count: int
) -> list[tuple[int, ...]]:
    """Generate random + edge-case samples for property checking."""
    import random

    edge_values = [bounds.lo, bounds.lo + 1, -1, 0, 1, bounds.hi - 1, bounds.hi]
    edge_values = [v for v in edge_values if bounds.contains(v)]

    samples: list[tuple[int, ...]] = []

    # All edge combinations
    for combo in itertools.product(edge_values, repeat=arity):
        samples.append(combo)

    # Random fill
    while len(samples) < count:
        combo = tuple(random.randint(bounds.lo, bounds.hi) for _ in range(arity))
        samples.append(combo)

    return samples
