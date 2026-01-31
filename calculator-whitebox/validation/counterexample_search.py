"""Counterexample search — discovers gaps in implementation or tests.

This module runs independently of the test suite.  It systematically
searches for:

1. Postcondition violations: inputs where the implementation doesn't
   match the spec's expected output.
2. Error condition violations: inputs that should raise but don't (or
   raise the wrong exception).
3. Property violations: algebraic relationships that fail for some
   input combination.

Run directly::

    cd calculator-whitebox
    python -m validation.counterexample_search
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field

sys.path.insert(0, ".")

from calculator import Calculator
from spec import Bounds, OverflowMode, DivZeroMode, build_spec, CalculatorSpec


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Counterexample:
    category: str
    operation: str
    inputs: tuple
    expected: str
    actual: str
    description: str


@dataclass
class SearchReport:
    counterexamples: list[Counterexample] = field(default_factory=list)
    checks_run: int = 0

    @property
    def passed(self) -> bool:
        return len(self.counterexamples) == 0

    def summary(self) -> str:
        lines = [
            "Counterexample Search Report",
            "=" * 40,
            f"Total checks: {self.checks_run}",
            f"Counterexamples found: {len(self.counterexamples)}",
        ]
        if self.counterexamples:
            lines.append("")
            for i, cx in enumerate(self.counterexamples, 1):
                lines.append(f"  [{i}] {cx.category} / {cx.operation}")
                lines.append(f"      Inputs:   {cx.inputs}")
                lines.append(f"      Expected: {cx.expected}")
                lines.append(f"      Actual:   {cx.actual}")
                lines.append(f"      {cx.description}")
        else:
            lines.append("\nNo counterexamples found — all checks passed.")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Search functions
# ---------------------------------------------------------------------------

def search_postcondition_violations(
    calc: Calculator,
    spec: CalculatorSpec,
) -> tuple[list[Counterexample], int]:
    """Exhaustively verify postconditions for every input pair."""
    cxs: list[Counterexample] = []
    checks = 0

    for op_name, op_spec in spec.operations.items():
        op = getattr(calc, op_name)
        for a in spec.bounds.all_values():
            for b in spec.bounds.all_values():
                # Skip inputs that are supposed to error
                should_error = any(
                    ec.trigger(a, b)
                    for ec in op_spec.error_conditions
                    if ec.exception is not None
                )
                if should_error:
                    checks += 1
                    continue

                try:
                    result = op(a, b)
                except Exception as e:
                    cxs.append(Counterexample(
                        category="unexpected_error",
                        operation=op_name,
                        inputs=(a, b),
                        expected="no error",
                        actual=f"{type(e).__name__}: {e}",
                        description="Operation raised an unexpected exception",
                    ))
                    checks += 1
                    continue

                for post in op_spec.postconditions:
                    if not post.check(a, b, result):
                        cxs.append(Counterexample(
                            category="postcondition_violation",
                            operation=op_name,
                            inputs=(a, b),
                            expected=post.description,
                            actual=f"result={result}",
                            description=f"Postcondition '{post.name}' violated",
                        ))
                checks += 1

    return cxs, checks


def search_error_condition_violations(
    calc: Calculator,
    spec: CalculatorSpec,
) -> tuple[list[Counterexample], int]:
    """Verify every error condition triggers the right exception."""
    cxs: list[Counterexample] = []
    checks = 0

    for op_name, op_spec in spec.operations.items():
        op = getattr(calc, op_name)
        for a in spec.bounds.all_values():
            for b in spec.bounds.all_values():
                for ec in op_spec.error_conditions:
                    if ec.exception is None:
                        continue  # non-error sentinel
                    if not ec.trigger(a, b):
                        continue
                    checks += 1
                    try:
                        result = op(a, b)
                        cxs.append(Counterexample(
                            category="missing_error",
                            operation=op_name,
                            inputs=(a, b),
                            expected=f"{ec.exception.__name__}",
                            actual=f"result={result}",
                            description=(
                                f"Error condition '{ec.name}' should have "
                                f"triggered but didn't"
                            ),
                        ))
                    except ec.exception:
                        pass  # expected
                    except Exception as e:
                        cxs.append(Counterexample(
                            category="wrong_error",
                            operation=op_name,
                            inputs=(a, b),
                            expected=f"{ec.exception.__name__}",
                            actual=f"{type(e).__name__}: {e}",
                            description=(
                                f"Wrong exception type for '{ec.name}'"
                            ),
                        ))

    return cxs, checks


def search_property_violations(
    calc: Calculator,
    spec: CalculatorSpec,
) -> tuple[list[Counterexample], int]:
    """Exhaustively check every algebraic property."""
    cxs: list[Counterexample] = []
    checks = 0

    for op_name, prop in spec.all_properties:
        if prop.arity == 2:
            for a in spec.bounds.all_values():
                for b in spec.bounds.all_values():
                    checks += 1
                    try:
                        if not prop.check(calc, a, b):
                            cxs.append(Counterexample(
                                category="property_violation",
                                operation=op_name,
                                inputs=(a, b),
                                expected=prop.description,
                                actual="property does not hold",
                                description=f"Property '{prop.name}' violated",
                            ))
                    except (ZeroDivisionError, OverflowError, ValueError):
                        pass
        elif prop.arity == 1:
            for a in spec.bounds.all_values():
                checks += 1
                try:
                    if not prop.check(calc, a):
                        cxs.append(Counterexample(
                            category="property_violation",
                            operation=op_name,
                            inputs=(a,),
                            expected=prop.description,
                            actual="property does not hold",
                            description=f"Property '{prop.name}' violated",
                        ))
                except (ZeroDivisionError, OverflowError, ValueError):
                    pass

    return cxs, checks


# ---------------------------------------------------------------------------
# Top-level runner
# ---------------------------------------------------------------------------

def run_search(
    bounds: Bounds,
    overflow_mode: OverflowMode,
    div_zero_mode: DivZeroMode,
) -> SearchReport:
    """Run complete counterexample search for one configuration."""
    calc = Calculator(bounds, overflow_mode, div_zero_mode)
    spec = build_spec(bounds, overflow_mode, div_zero_mode)
    report = SearchReport()

    for search_fn in (
        search_postcondition_violations,
        search_error_condition_violations,
        search_property_violations,
    ):
        cxs, checks = search_fn(calc, spec)
        report.counterexamples.extend(cxs)
        report.checks_run += checks

    return report


def main() -> None:
    """Run counterexample search across several configurations."""
    configs = [
        ("CLAMP / ERROR  [-8, 7]",
         Bounds(-8, 7), OverflowMode.CLAMP, DivZeroMode.ERROR),
        ("WRAP  / ERROR  [-8, 7]",
         Bounds(-8, 7), OverflowMode.WRAP, DivZeroMode.ERROR),
        ("ERROR / ERROR  [-8, 7]",
         Bounds(-8, 7), OverflowMode.ERROR, DivZeroMode.ERROR),
        ("CLAMP / ZERO   [-8, 7]",
         Bounds(-8, 7), OverflowMode.CLAMP, DivZeroMode.ZERO),
        ("CLAMP / ERROR  [0, 15]",
         Bounds(0, 15), OverflowMode.CLAMP, DivZeroMode.ERROR),
    ]

    all_passed = True
    for name, bounds, ovf, dz in configs:
        print(f"\n--- Configuration: {name} ---")
        report = run_search(bounds, ovf, dz)
        print(report.summary())
        if not report.passed:
            all_passed = False

    print("\n" + "=" * 40)
    if all_passed:
        print("ALL CONFIGURATIONS PASSED")
    else:
        print("SOME CONFIGURATIONS HAD COUNTEREXAMPLES")
        sys.exit(1)


if __name__ == "__main__":
    main()
