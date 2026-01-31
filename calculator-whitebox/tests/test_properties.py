"""Property-based tests using Hypothesis.

These tests verify algebraic properties that must hold for *all* inputs
within bounds.  They complement the white-box tests by exploring the
input space broadly rather than targeting specific branches.
"""
from __future__ import annotations

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis.strategies import integers

from calculator import Calculator
from spec import Bounds, OverflowMode, DivZeroMode

# ---------------------------------------------------------------------------
# Shared configuration
# ---------------------------------------------------------------------------

BOUNDS = Bounds(lo=-50, hi=50)
CALC = Calculator(BOUNDS, OverflowMode.CLAMP, DivZeroMode.ERROR)
bounded = integers(min_value=BOUNDS.lo, max_value=BOUNDS.hi)


# ===================================================================
# ADDITION
# ===================================================================

class TestAdditionProperties:

    @given(a=bounded, b=bounded)
    def test_closure(self, a, b):
        assert BOUNDS.contains(CALC.add(a, b))

    @given(a=bounded, b=bounded)
    def test_commutativity(self, a, b):
        assert CALC.add(a, b) == CALC.add(b, a)

    @given(a=bounded)
    def test_identity(self, a):
        assert CALC.add(a, 0) == a

    @given(a=bounded, b=bounded, c=bounded)
    @settings(max_examples=500)
    def test_associativity_when_no_overflow(self, a, b, c):
        """Associativity holds when no intermediate overflow occurs."""
        assume(BOUNDS.contains(a + b) and BOUNDS.contains((a + b) + c))
        assume(BOUNDS.contains(b + c) and BOUNDS.contains(a + (b + c)))
        assert CALC.add(CALC.add(a, b), c) == CALC.add(a, CALC.add(b, c))


# ===================================================================
# SUBTRACTION
# ===================================================================

class TestSubtractionProperties:

    @given(a=bounded, b=bounded)
    def test_closure(self, a, b):
        assert BOUNDS.contains(CALC.sub(a, b))

    @given(a=bounded)
    def test_identity(self, a):
        assert CALC.sub(a, 0) == a

    @given(a=bounded)
    def test_self_inverse(self, a):
        assert CALC.sub(a, a) == 0


# ===================================================================
# MULTIPLICATION
# ===================================================================

class TestMultiplicationProperties:

    @given(a=bounded, b=bounded)
    def test_closure(self, a, b):
        assert BOUNDS.contains(CALC.mul(a, b))

    @given(a=bounded, b=bounded)
    def test_commutativity(self, a, b):
        assert CALC.mul(a, b) == CALC.mul(b, a)

    @given(a=bounded)
    def test_identity(self, a):
        assert CALC.mul(a, 1) == a

    @given(a=bounded)
    def test_zero(self, a):
        assert CALC.mul(a, 0) == 0


# ===================================================================
# DIVISION
# ===================================================================

class TestDivisionProperties:

    @given(a=bounded, b=bounded)
    def test_closure(self, a, b):
        assume(b != 0)
        assert BOUNDS.contains(CALC.div(a, b))

    @given(a=bounded)
    def test_identity(self, a):
        assert CALC.div(a, 1) == a

    @given(a=bounded)
    def test_self(self, a):
        assume(a != 0)
        assert CALC.div(a, a) == 1

    @given(b=bounded)
    def test_zero_numerator(self, b):
        assume(b != 0)
        assert CALC.div(0, b) == 0

    @given(a=bounded, b=bounded)
    @settings(max_examples=500)
    def test_truncation_toward_zero(self, a, b):
        """Result magnitude never exceeds abs(a)."""
        assume(b != 0)
        result = CALC.div(a, b)
        assert abs(result) <= abs(a)


# ===================================================================
# CROSS-OPERATION
# ===================================================================

class TestCrossOperationProperties:

    @given(a=bounded, b=bounded)
    def test_add_sub_inverse(self, a, b):
        """add then sub returns original when no overflow."""
        result = CALC.add(a, b)
        assume(a + b == result)  # no overflow occurred
        assert CALC.sub(result, b) == a

    @given(a=bounded, b=bounded)
    @settings(suppress_health_check=[HealthCheck.filter_too_much])
    def test_mul_div_inverse(self, a, b):
        """mul then div returns original when exact and no overflow."""
        assume(b != 0)
        product = CALC.mul(a, b)
        assume(a * b == product)  # no overflow occurred
        assert CALC.div(product, b) == a

    @given(a=bounded)
    def test_sub_add_inverse(self, a):
        """sub(a, a) + a gives a when no overflow."""
        zero = CALC.sub(a, a)
        assert CALC.add(zero, a) == a
