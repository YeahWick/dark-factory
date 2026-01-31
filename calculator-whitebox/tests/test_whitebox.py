"""White-box tests for the bounded calculator.

Each test class targets specific decision branches documented in the
spec (see ``BranchSpec`` ids).  A coverage matrix at the bottom of this
file records which test covers which branch, enabling external tools to
verify that every branch is exercised.

Naming convention
-----------------
test_<branch_id_lowercase>_<scenario>
"""
from __future__ import annotations

import pytest

from calculator import Calculator
from spec import Bounds, OverflowMode, DivZeroMode

# ---------------------------------------------------------------------------
# Shared small bounds  [-8, 7]  (width 16 — easy to reason about)
# ---------------------------------------------------------------------------

TINY = Bounds(lo=-8, hi=7)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def calc_clamp():
    return Calculator(TINY, OverflowMode.CLAMP, DivZeroMode.ERROR)


@pytest.fixture
def calc_wrap():
    return Calculator(TINY, OverflowMode.WRAP, DivZeroMode.ERROR)


@pytest.fixture
def calc_error():
    return Calculator(TINY, OverflowMode.ERROR, DivZeroMode.ERROR)


@pytest.fixture
def calc_div_zero():
    return Calculator(TINY, OverflowMode.CLAMP, DivZeroMode.ZERO)


# ===================================================================
# INPUT VALIDATION  (INPUT-VALID, INPUT-INVALID-A, INPUT-INVALID-B)
# ===================================================================

class TestInputValidation:

    def test_input_valid(self, calc_clamp):
        """Branch: INPUT-VALID — both inputs in bounds accepted."""
        assert calc_clamp.add(3, 4) == 7

    def test_input_invalid_a_below(self, calc_clamp):
        """Branch: INPUT-INVALID-A — first input below lo."""
        with pytest.raises(ValueError):
            calc_clamp.add(-9, 0)

    def test_input_invalid_a_above(self, calc_clamp):
        """Branch: INPUT-INVALID-A — first input above hi."""
        with pytest.raises(ValueError):
            calc_clamp.add(8, 0)

    def test_input_invalid_b_below(self, calc_clamp):
        """Branch: INPUT-INVALID-B — second input below lo."""
        with pytest.raises(ValueError):
            calc_clamp.add(0, -9)

    def test_input_invalid_b_above(self, calc_clamp):
        """Branch: INPUT-INVALID-B — second input above hi."""
        with pytest.raises(ValueError):
            calc_clamp.add(0, 8)

    # Boundary values — exactly at lo and hi
    def test_boundary_lo_accepted(self, calc_clamp):
        assert calc_clamp.add(-8, 0) == -8

    def test_boundary_hi_accepted(self, calc_clamp):
        assert calc_clamp.add(7, 0) == 7

    # Validation applies to every operation
    @pytest.mark.parametrize("op", ["add", "sub", "mul", "div"])
    def test_validation_on_all_ops(self, calc_clamp, op):
        with pytest.raises(ValueError):
            getattr(calc_clamp, op)(100, 0)


# ===================================================================
# OVERFLOW: CLAMP  (OVF-CLAMP-HI, OVF-CLAMP-LO, OVF-IN-BOUNDS)
# ===================================================================

class TestOverflowClamp:

    def test_ovf_in_bounds(self, calc_clamp):
        """Branch: OVF-IN-BOUNDS — result within bounds, no adjustment."""
        assert calc_clamp.add(2, 3) == 5

    def test_ovf_clamp_hi(self, calc_clamp):
        """Branch: OVF-CLAMP-HI — positive overflow clamped to hi."""
        assert calc_clamp.add(7, 7) == 7   # 14 -> 7

    def test_ovf_clamp_lo(self, calc_clamp):
        """Branch: OVF-CLAMP-LO — negative overflow clamped to lo."""
        assert calc_clamp.add(-8, -8) == -8  # -16 -> -8

    def test_clamp_hi_boundary(self, calc_clamp):
        """Boundary: sum exactly equals hi."""
        assert calc_clamp.add(4, 3) == 7

    def test_clamp_lo_boundary(self, calc_clamp):
        """Boundary: sum exactly equals lo."""
        assert calc_clamp.add(-4, -4) == -8

    def test_clamp_one_above_hi(self, calc_clamp):
        """Boundary: sum is hi + 1."""
        assert calc_clamp.add(4, 4) == 7   # 8 -> 7

    def test_clamp_one_below_lo(self, calc_clamp):
        """Boundary: sum is lo - 1."""
        assert calc_clamp.add(-5, -4) == -8  # -9 -> -8

    def test_clamp_sub_overflow(self, calc_clamp):
        """Clamp applies to subtraction too."""
        assert calc_clamp.sub(-5, 5) == -8  # -10 -> -8

    def test_clamp_mul_overflow(self, calc_clamp):
        """Clamp applies to multiplication too."""
        assert calc_clamp.mul(7, 7) == 7    # 49 -> 7


# ===================================================================
# OVERFLOW: WRAP  (OVF-WRAP)
# ===================================================================

class TestOverflowWrap:

    def test_ovf_wrap_positive(self, calc_wrap):
        """Branch: OVF-WRAP — positive overflow wraps to lo side."""
        # 7 + 1 = 8  ->  -8 + (8 - (-8)) % 16 = -8 + 0 = -8
        assert calc_wrap.add(7, 1) == -8

    def test_ovf_wrap_negative(self, calc_wrap):
        """Branch: OVF-WRAP — negative overflow wraps to hi side."""
        # -8 + -1 = -9  ->  -8 + (-9 - (-8)) % 16 = -8 + 15 = 7
        assert calc_wrap.add(-8, -1) == 7

    def test_wrap_no_overflow(self, calc_wrap):
        """No wrapping needed when result is in bounds."""
        assert calc_wrap.add(2, 3) == 5

    def test_wrap_large_overflow(self, calc_wrap):
        """Wrap handles large overflows (multiple widths)."""
        assert calc_wrap.mul(7, 7) == TINY.wrap(49)


# ===================================================================
# OVERFLOW: ERROR  (OVF-ERROR)
# ===================================================================

class TestOverflowError:

    def test_ovf_error_positive(self, calc_error):
        """Branch: OVF-ERROR — positive overflow raises."""
        with pytest.raises(OverflowError):
            calc_error.add(7, 7)

    def test_ovf_error_negative(self, calc_error):
        """Branch: OVF-ERROR — negative overflow raises."""
        with pytest.raises(OverflowError):
            calc_error.add(-8, -8)

    def test_error_no_overflow(self, calc_error):
        """No error when result is in bounds."""
        assert calc_error.add(2, 3) == 5

    def test_error_boundary(self, calc_error):
        """No error when result is exactly at boundary."""
        assert calc_error.add(4, 3) == 7
        assert calc_error.add(-4, -4) == -8


# ===================================================================
# DIVISION  (DIV-NORMAL, DIV-ZERO-ERROR, DIV-ZERO-RETURN, DIV-TRUNCATE)
# ===================================================================

class TestDivision:

    # -- normal division (DIV-NORMAL) ---
    def test_div_normal_exact(self, calc_clamp):
        """Branch: DIV-NORMAL — exact division."""
        assert calc_clamp.div(6, 3) == 2

    def test_div_normal_positive_truncation(self, calc_clamp):
        """Branch: DIV-TRUNCATE — 7/2 = 3 (not 3.5)."""
        assert calc_clamp.div(7, 2) == 3

    def test_div_normal_negative_truncation(self, calc_clamp):
        """Branch: DIV-TRUNCATE — -7/2 = -3 (toward zero, not -4)."""
        assert calc_clamp.div(-7, 2) == -3

    def test_div_negative_divisor_truncation(self, calc_clamp):
        """Branch: DIV-TRUNCATE — 7/-2 = -3 (toward zero, not -4)."""
        assert calc_clamp.div(7, -2) == -3

    def test_div_both_negative_exact(self, calc_clamp):
        """DIV-NORMAL — -6/-3 = 2 (positive, exact)."""
        assert calc_clamp.div(-6, -3) == 2

    def test_div_both_negative_truncation(self, calc_clamp):
        """DIV-NORMAL — -7/-2 = 3 (positive, no truncation adjustment)."""
        assert calc_clamp.div(-7, -2) == 3

    # -- division by zero (DIV-ZERO-ERROR, DIV-ZERO-RETURN) ---
    def test_div_zero_error(self, calc_clamp):
        """Branch: DIV-ZERO-ERROR — raises when mode is ERROR."""
        with pytest.raises(ZeroDivisionError):
            calc_clamp.div(5, 0)

    def test_div_zero_return(self, calc_div_zero):
        """Branch: DIV-ZERO-RETURN — returns 0 when mode is ZERO."""
        assert calc_div_zero.div(5, 0) == 0

    def test_div_zero_return_negative(self, calc_div_zero):
        """DIV-ZERO-RETURN with negative numerator."""
        assert calc_div_zero.div(-5, 0) == 0

    # -- identity / special values ---
    def test_div_identity(self, calc_clamp):
        assert calc_clamp.div(5, 1) == 5

    def test_div_self(self, calc_clamp):
        assert calc_clamp.div(5, 5) == 1

    def test_div_zero_numerator(self, calc_clamp):
        assert calc_clamp.div(0, 5) == 0

    # -- division overflow ---
    def test_div_overflow_clamp(self, calc_clamp):
        """Division result out of bounds clamped (e.g., -8 / -1 = 8 > 7)."""
        assert calc_clamp.div(-8, -1) == 7


# ===================================================================
# SUBTRACTION (selected branch coverage)
# ===================================================================

class TestSubtraction:

    def test_sub_normal(self, calc_clamp):
        assert calc_clamp.sub(5, 3) == 2

    def test_sub_negative_result(self, calc_clamp):
        assert calc_clamp.sub(3, 5) == -2

    def test_sub_self(self, calc_clamp):
        assert calc_clamp.sub(5, 5) == 0

    def test_sub_underflow_clamps(self, calc_clamp):
        assert calc_clamp.sub(-5, 5) == -8


# ===================================================================
# MULTIPLICATION (selected branch coverage)
# ===================================================================

class TestMultiplication:

    def test_mul_normal(self, calc_clamp):
        assert calc_clamp.mul(2, 3) == 6

    def test_mul_overflow_clamps(self, calc_clamp):
        assert calc_clamp.mul(7, 7) == 7

    def test_mul_underflow_clamps(self, calc_clamp):
        assert calc_clamp.mul(7, -7) == -8

    def test_mul_by_zero(self, calc_clamp):
        assert calc_clamp.mul(5, 0) == 0

    def test_mul_by_one(self, calc_clamp):
        assert calc_clamp.mul(5, 1) == 5

    def test_mul_negative(self, calc_clamp):
        assert calc_clamp.mul(-3, 2) == -6

    def test_mul_two_negatives(self, calc_clamp):
        assert calc_clamp.mul(-2, -3) == 6


# ===================================================================
# BRANCH COVERAGE MATRIX
# ===================================================================
# Maps each spec branch-ID to the test(s) that exercise it.
# External tooling can cross-check this against real coverage data.

BRANCH_COVERAGE = {
    "INPUT-VALID": [
        "TestInputValidation::test_input_valid",
    ],
    "INPUT-INVALID-A": [
        "TestInputValidation::test_input_invalid_a_below",
        "TestInputValidation::test_input_invalid_a_above",
    ],
    "INPUT-INVALID-B": [
        "TestInputValidation::test_input_invalid_b_below",
        "TestInputValidation::test_input_invalid_b_above",
    ],
    "OVF-IN-BOUNDS": [
        "TestOverflowClamp::test_ovf_in_bounds",
    ],
    "OVF-CLAMP-HI": [
        "TestOverflowClamp::test_ovf_clamp_hi",
    ],
    "OVF-CLAMP-LO": [
        "TestOverflowClamp::test_ovf_clamp_lo",
    ],
    "OVF-WRAP": [
        "TestOverflowWrap::test_ovf_wrap_positive",
        "TestOverflowWrap::test_ovf_wrap_negative",
    ],
    "OVF-ERROR": [
        "TestOverflowError::test_ovf_error_positive",
        "TestOverflowError::test_ovf_error_negative",
    ],
    "DIV-NORMAL": [
        "TestDivision::test_div_normal_exact",
    ],
    "DIV-ZERO-ERROR": [
        "TestDivision::test_div_zero_error",
    ],
    "DIV-ZERO-RETURN": [
        "TestDivision::test_div_zero_return",
    ],
    "DIV-TRUNCATE": [
        "TestDivision::test_div_normal_positive_truncation",
        "TestDivision::test_div_normal_negative_truncation",
    ],
}
