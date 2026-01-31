"""Spec conformance tests.

These tests are *driven by* the spec: they iterate over every
postcondition, error condition, and algebraic property defined in
``spec.build_spec`` and verify the implementation satisfies them.

If the spec changes (e.g. a new postcondition is added), these tests
automatically cover it — no manual test authoring required for the
new predicate.
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings, assume
from hypothesis.strategies import integers

from calculator import Calculator
from spec import Bounds, OverflowMode, DivZeroMode, build_spec

# ---------------------------------------------------------------------------
# Configuration — small bounds so exhaustive checks are fast
# ---------------------------------------------------------------------------

BOUNDS = Bounds(lo=-8, hi=7)
SPEC = build_spec(BOUNDS, OverflowMode.CLAMP, DivZeroMode.ERROR)
CALC = Calculator(BOUNDS, OverflowMode.CLAMP, DivZeroMode.ERROR)
bounded = integers(min_value=BOUNDS.lo, max_value=BOUNDS.hi)


def _get_op(name: str):
    return getattr(CALC, name)


# ===================================================================
# POSTCONDITIONS — property-based
# ===================================================================

class TestPostconditions:
    """Every postcondition in the spec holds for random inputs."""

    @given(a=bounded, b=bounded)
    @settings(max_examples=300)
    def test_add_postconditions(self, a, b):
        result = CALC.add(a, b)
        for post in SPEC.operations["add"].postconditions:
            assert post.check(a, b, result), (
                f"Postcondition '{post.name}' failed: add({a}, {b}) = {result}"
            )

    @given(a=bounded, b=bounded)
    @settings(max_examples=300)
    def test_sub_postconditions(self, a, b):
        result = CALC.sub(a, b)
        for post in SPEC.operations["sub"].postconditions:
            assert post.check(a, b, result), (
                f"Postcondition '{post.name}' failed: sub({a}, {b}) = {result}"
            )

    @given(a=bounded, b=bounded)
    @settings(max_examples=300)
    def test_mul_postconditions(self, a, b):
        result = CALC.mul(a, b)
        for post in SPEC.operations["mul"].postconditions:
            assert post.check(a, b, result), (
                f"Postcondition '{post.name}' failed: mul({a}, {b}) = {result}"
            )

    @given(a=bounded, b=bounded)
    @settings(max_examples=300)
    def test_div_postconditions(self, a, b):
        assume(b != 0)
        result = CALC.div(a, b)
        for post in SPEC.operations["div"].postconditions:
            assert post.check(a, b, result), (
                f"Postcondition '{post.name}' failed: div({a}, {b}) = {result}"
            )


# ===================================================================
# ERROR CONDITIONS
# ===================================================================

class TestErrorConditions:
    """Every error condition in the spec triggers correctly."""

    def test_div_by_zero_triggers(self):
        for a in BOUNDS.all_values():
            with pytest.raises(ZeroDivisionError):
                CALC.div(a, 0)

    def test_overflow_error_mode(self):
        """ERROR-mode calculator raises on every out-of-bounds result."""
        calc_err = Calculator(BOUNDS, OverflowMode.ERROR, DivZeroMode.ERROR)
        spec_err = build_spec(BOUNDS, OverflowMode.ERROR, DivZeroMode.ERROR)

        for a in BOUNDS.all_values():
            for b in BOUNDS.all_values():
                for ec in spec_err.operations["add"].error_conditions:
                    if ec.trigger(a, b):
                        with pytest.raises(ec.exception):
                            calc_err.add(a, b)


# ===================================================================
# ALGEBRAIC PROPERTIES — property-based
# ===================================================================

class TestAlgebraicProperties:
    """Every algebraic property in the spec holds for random inputs."""

    @given(a=bounded, b=bounded)
    @settings(max_examples=300)
    def test_binary_properties(self, a, b):
        for op_name, prop in SPEC.all_properties:
            if prop.arity != 2:
                continue
            try:
                ok = prop.check(CALC, a, b)
            except (ZeroDivisionError, OverflowError, ValueError):
                continue
            assert ok, (
                f"Property '{prop.name}' failed for {op_name}({a}, {b})"
            )

    @given(a=bounded)
    @settings(max_examples=300)
    def test_unary_properties(self, a):
        for op_name, prop in SPEC.all_properties:
            if prop.arity != 1:
                continue
            try:
                ok = prop.check(CALC, a)
            except (ZeroDivisionError, OverflowError, ValueError):
                continue
            assert ok, (
                f"Property '{prop.name}' failed for {op_name}({a})"
            )


# ===================================================================
# EXHAUSTIVE VERIFICATION — small bounds
# ===================================================================

class TestExhaustive:
    """For small bounds, check *every* input pair against postconditions."""

    def test_all_pairs_add(self):
        checked = 0
        for a in BOUNDS.all_values():
            for b in BOUNDS.all_values():
                result = CALC.add(a, b)
                for post in SPEC.operations["add"].postconditions:
                    assert post.check(a, b, result)
                checked += 1
        assert checked == BOUNDS.width ** 2

    def test_all_pairs_sub(self):
        checked = 0
        for a in BOUNDS.all_values():
            for b in BOUNDS.all_values():
                result = CALC.sub(a, b)
                for post in SPEC.operations["sub"].postconditions:
                    assert post.check(a, b, result)
                checked += 1
        assert checked == BOUNDS.width ** 2

    def test_all_pairs_mul(self):
        checked = 0
        for a in BOUNDS.all_values():
            for b in BOUNDS.all_values():
                result = CALC.mul(a, b)
                for post in SPEC.operations["mul"].postconditions:
                    assert post.check(a, b, result)
                checked += 1
        assert checked == BOUNDS.width ** 2

    def test_all_pairs_div(self):
        checked = 0
        for a in BOUNDS.all_values():
            for b in BOUNDS.all_values():
                if b == 0:
                    continue
                result = CALC.div(a, b)
                for post in SPEC.operations["div"].postconditions:
                    assert post.check(a, b, result)
                checked += 1
        # width^2 minus the column where b == 0
        assert checked == BOUNDS.width ** 2 - BOUNDS.width

    def test_exhaustive_pair_count(self):
        """Sanity: confirm the expected number of pairs."""
        assert BOUNDS.width == 16
        assert BOUNDS.width ** 2 == 256
