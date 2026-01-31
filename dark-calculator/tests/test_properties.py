"""
Property-based tests using Hypothesis.

These tests extend the factory's built-in verification with
Hypothesis's shrinking and strategy machinery.  They cover
larger bounds where exhaustive checking is infeasible.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from hypothesis import given, settings, assume
from hypothesis.strategies import integers

from bounds import Bounds, INT8, INT16, OverflowStrategy
from calculator import BoundedCalculator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def bounded_ints(bounds: Bounds):
    """Hypothesis strategy that generates ints within bounds."""
    return integers(min_value=bounds.lo, max_value=bounds.hi)


# ---------------------------------------------------------------------------
# Addition properties
# ---------------------------------------------------------------------------

class TestAdditionProperties:
    bounds = INT8
    calc = BoundedCalculator(bounds=bounds)

    @given(a=bounded_ints(INT8), b=bounded_ints(INT8))
    def test_closure(self, a, b):
        result = self.calc.add(a, b)
        assert self.bounds.lo <= result <= self.bounds.hi

    @given(a=bounded_ints(INT8), b=bounded_ints(INT8))
    def test_commutativity(self, a, b):
        assert self.calc.add(a, b) == self.calc.add(b, a)

    @given(a=bounded_ints(INT8))
    def test_identity(self, a):
        assert self.calc.add(a, 0) == a

    @given(a=bounded_ints(INT8), b=bounded_ints(INT8), c=bounded_ints(INT8))
    @settings(max_examples=500)
    def test_associativity(self, a, b, c):
        """Associativity holds when raw intermediates stay in bounds."""
        assume(self.bounds.lo <= a + b <= self.bounds.hi)
        assume(self.bounds.lo <= b + c <= self.bounds.hi)
        lhs = self.calc.add(self.calc.add(a, b), c)
        rhs = self.calc.add(a, self.calc.add(b, c))
        assert lhs == rhs


# ---------------------------------------------------------------------------
# Subtraction properties
# ---------------------------------------------------------------------------

class TestSubtractionProperties:
    bounds = INT8
    calc = BoundedCalculator(bounds=bounds)

    @given(a=bounded_ints(INT8), b=bounded_ints(INT8))
    def test_closure(self, a, b):
        result = self.calc.sub(a, b)
        assert self.bounds.lo <= result <= self.bounds.hi

    @given(a=bounded_ints(INT8))
    def test_identity(self, a):
        assert self.calc.sub(a, 0) == a

    @given(a=bounded_ints(INT8))
    def test_self_inverse(self, a):
        assert self.calc.sub(a, a) == 0


# ---------------------------------------------------------------------------
# Multiplication properties
# ---------------------------------------------------------------------------

class TestMultiplicationProperties:
    bounds = INT8
    calc = BoundedCalculator(bounds=bounds)

    @given(a=bounded_ints(INT8), b=bounded_ints(INT8))
    def test_closure(self, a, b):
        result = self.calc.mul(a, b)
        assert self.bounds.lo <= result <= self.bounds.hi

    @given(a=bounded_ints(INT8), b=bounded_ints(INT8))
    def test_commutativity(self, a, b):
        assert self.calc.mul(a, b) == self.calc.mul(b, a)

    @given(a=bounded_ints(INT8))
    def test_identity(self, a):
        assert self.calc.mul(a, 1) == a

    @given(a=bounded_ints(INT8))
    def test_zero(self, a):
        assert self.calc.mul(a, 0) == 0


# ---------------------------------------------------------------------------
# Division properties
# ---------------------------------------------------------------------------

class TestDivisionProperties:
    bounds = INT8
    calc = BoundedCalculator(bounds=bounds)

    @given(a=bounded_ints(INT8), b=bounded_ints(INT8))
    def test_closure(self, a, b):
        assume(b != 0)
        result = self.calc.div(a, b)
        assert self.bounds.lo <= result <= self.bounds.hi

    @given(a=bounded_ints(INT8))
    def test_identity(self, a):
        assert self.calc.div(a, 1) == a

    @given(a=bounded_ints(INT8))
    def test_self(self, a):
        assume(a != 0)
        assert self.calc.div(a, a) == 1

    @given(b=bounded_ints(INT8))
    def test_zero_numerator(self, b):
        assume(b != 0)
        assert self.calc.div(0, b) == 0

    def test_division_by_zero_raises(self):
        with pytest.raises(ZeroDivisionError):
            self.calc.div(1, 0)


# ---------------------------------------------------------------------------
# Cross-operation properties
# ---------------------------------------------------------------------------

class TestCrossOperationProperties:
    bounds = INT8
    calc = BoundedCalculator(bounds=bounds)

    @given(a=bounded_ints(INT8), b=bounded_ints(INT8))
    def test_add_sub_inverse(self, a, b):
        """(a + b) - b should equal a when no clamping occurs."""
        raw_sum = a + b
        if self.bounds.lo <= raw_sum <= self.bounds.hi:
            assert self.calc.sub(self.calc.add(a, b), b) == a

    @given(a=bounded_ints(INT8))
    def test_neg_double_inverse(self, a):
        """neg(neg(a)) == a when raw negation stays in bounds."""
        # -a must itself be in bounds for the round-trip to hold
        assume(self.bounds.lo <= -a <= self.bounds.hi)
        assert self.calc.neg(self.calc.neg(a)) == a


# ---------------------------------------------------------------------------
# Wider bounds - INT16
# ---------------------------------------------------------------------------

class TestInt16Properties:
    bounds = INT16
    calc = BoundedCalculator(bounds=bounds)

    @given(a=bounded_ints(INT16), b=bounded_ints(INT16))
    @settings(max_examples=1000)
    def test_add_closure(self, a, b):
        result = self.calc.add(a, b)
        assert self.bounds.lo <= result <= self.bounds.hi

    @given(a=bounded_ints(INT16), b=bounded_ints(INT16))
    @settings(max_examples=1000)
    def test_mul_commutativity(self, a, b):
        assert self.calc.mul(a, b) == self.calc.mul(b, a)
