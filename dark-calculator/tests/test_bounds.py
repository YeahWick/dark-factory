"""
Tests for the Bounds layer.

These verify that the bounds enforcement itself is correct -
clamping, wrapping, error raising, and division-by-zero strategies.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from hypothesis import given
from hypothesis.strategies import integers

from bounds import (
    Bounds,
    OverflowStrategy,
    DivisionByZeroStrategy,
    INT8,
    UINT8,
    TINY,
    PERCENT,
)


# ---------------------------------------------------------------------------
# Bounds construction
# ---------------------------------------------------------------------------

class TestBoundsConstruction:
    def test_valid_bounds(self):
        b = Bounds(lo=-10, hi=10)
        assert b.lo == -10
        assert b.hi == 10
        assert b.width == 21

    def test_single_value_bounds(self):
        b = Bounds(lo=0, hi=0)
        assert b.width == 1
        assert b.contains(0)
        assert not b.contains(1)

    def test_invalid_bounds_raises(self):
        with pytest.raises(ValueError, match="lo.*must be <= hi"):
            Bounds(lo=10, hi=-10)

    def test_presets(self):
        assert INT8.lo == -128
        assert INT8.hi == 127
        assert INT8.width == 256
        assert UINT8.lo == 0
        assert UINT8.hi == 255
        assert PERCENT.width == 101


# ---------------------------------------------------------------------------
# Clamping strategy
# ---------------------------------------------------------------------------

class TestClampStrategy:
    bounds = Bounds(lo=-10, hi=10, overflow=OverflowStrategy.CLAMP)

    def test_within_bounds_unchanged(self):
        for v in [-10, -5, 0, 5, 10]:
            assert self.bounds.apply(v) == v

    def test_above_hi_clamps(self):
        assert self.bounds.apply(11) == 10
        assert self.bounds.apply(1000) == 10

    def test_below_lo_clamps(self):
        assert self.bounds.apply(-11) == -10
        assert self.bounds.apply(-1000) == -10

    @given(v=integers(min_value=-10, max_value=10))
    def test_in_range_identity(self, v):
        assert self.bounds.apply(v) == v

    @given(v=integers(min_value=11, max_value=10_000))
    def test_overflow_clamps_to_hi(self, v):
        assert self.bounds.apply(v) == 10

    @given(v=integers(min_value=-10_000, max_value=-11))
    def test_underflow_clamps_to_lo(self, v):
        assert self.bounds.apply(v) == -10


# ---------------------------------------------------------------------------
# Wrapping strategy
# ---------------------------------------------------------------------------

class TestWrapStrategy:
    bounds = Bounds(lo=0, hi=7, overflow=OverflowStrategy.WRAP)

    def test_within_bounds_unchanged(self):
        for v in range(8):
            assert self.bounds.apply(v) == v

    def test_wrap_overflow(self):
        assert self.bounds.apply(8) == 0
        assert self.bounds.apply(9) == 1
        assert self.bounds.apply(15) == 7
        assert self.bounds.apply(16) == 0

    def test_wrap_underflow(self):
        assert self.bounds.apply(-1) == 7
        assert self.bounds.apply(-2) == 6
        assert self.bounds.apply(-8) == 0

    @given(v=integers(min_value=-100, max_value=100))
    def test_wrap_always_in_bounds(self, v):
        result = self.bounds.apply(v)
        assert 0 <= result <= 7


# ---------------------------------------------------------------------------
# Error strategy
# ---------------------------------------------------------------------------

class TestErrorStrategy:
    bounds = Bounds(lo=-10, hi=10, overflow=OverflowStrategy.ERROR)

    def test_within_bounds_ok(self):
        assert self.bounds.apply(0) == 0
        assert self.bounds.apply(-10) == -10
        assert self.bounds.apply(10) == 10

    def test_overflow_raises(self):
        with pytest.raises(OverflowError):
            self.bounds.apply(11)

    def test_underflow_raises(self):
        with pytest.raises(OverflowError):
            self.bounds.apply(-11)


# ---------------------------------------------------------------------------
# Division by zero strategies
# ---------------------------------------------------------------------------

class TestDivisionByZeroStrategies:
    def test_error_strategy(self):
        b = Bounds(lo=-10, hi=10, div_zero=DivisionByZeroStrategy.ERROR)
        with pytest.raises(ZeroDivisionError):
            b.handle_div_zero()

    def test_return_zero_strategy(self):
        b = Bounds(lo=-10, hi=10, div_zero=DivisionByZeroStrategy.RETURN_ZERO)
        assert b.handle_div_zero() == 0

    def test_return_max_strategy(self):
        b = Bounds(lo=-10, hi=10, div_zero=DivisionByZeroStrategy.RETURN_MAX)
        assert b.handle_div_zero() == 10


# ---------------------------------------------------------------------------
# Contains
# ---------------------------------------------------------------------------

class TestContains:
    @given(v=integers(min_value=-128, max_value=127))
    def test_int8_contains_all_valid(self, v):
        assert INT8.contains(v)

    def test_int8_excludes_out_of_range(self):
        assert not INT8.contains(128)
        assert not INT8.contains(-129)

    @given(v=integers(min_value=-8, max_value=7))
    def test_tiny_contains(self, v):
        assert TINY.contains(v)
