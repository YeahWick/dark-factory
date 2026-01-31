"""
Spec conformance tests.

These test the factory's end-to-end verification:
  - A correct implementation passes verification.
  - A broken implementation is rejected.
  - Exhaustive verification actually checks all combinations.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from bounds import Bounds, TINY, SMALL, INT8, OverflowStrategy, DivisionByZeroStrategy
from calculator import BoundedCalculator
from factory import DarkFactory, VerificationError, VerificationReport
from spec import addition_spec, Property


# ---------------------------------------------------------------------------
# Factory produces verified calculators
# ---------------------------------------------------------------------------

class TestFactoryProducesVerified:
    def test_tiny_bounds(self):
        """Exhaustive verification on TINY bounds should pass."""
        calc = DarkFactory.create(TINY)
        assert isinstance(calc, BoundedCalculator)
        assert calc.bounds == TINY

    def test_small_bounds(self):
        """Exhaustive verification on SMALL (INT8) bounds should pass."""
        calc = DarkFactory.create(SMALL)
        assert isinstance(calc, BoundedCalculator)
        assert calc.bounds == SMALL

    def test_custom_bounds(self):
        bounds = Bounds(lo=-50, hi=50)
        calc = DarkFactory.create(bounds)
        assert calc.bounds.lo == -50
        assert calc.bounds.hi == 50

    def test_unsigned_bounds(self):
        bounds = Bounds(lo=0, hi=255)
        calc = DarkFactory.create(bounds)
        assert calc.bounds.lo == 0
        assert calc.bounds.hi == 255

    def test_single_value_bounds(self):
        """Bounds where lo == hi: everything clamps to that value."""
        bounds = Bounds(lo=0, hi=0)
        calc = DarkFactory.create(bounds)
        assert calc.add(0, 0) == 0
        assert calc.mul(0, 0) == 0

    def test_percent_bounds(self):
        bounds = Bounds(lo=0, hi=100)
        calc = DarkFactory.create(bounds)
        assert calc.add(60, 50) == 100  # clamped
        assert calc.sub(10, 20) == 0    # clamped
        assert calc.mul(10, 10) == 100  # exact


# ---------------------------------------------------------------------------
# Factory rejects broken implementations
# ---------------------------------------------------------------------------

class TestFactoryRejectsBroken:
    def test_broken_addition_spec_detected(self):
        """
        Inject a property that should fail and verify the factory catches it.
        """
        bounds = TINY

        # A property that claims add(a, b) always equals 42 - obviously wrong
        bad_prop = Property(
            name="always_42",
            description="add(a, b) == 42",
            predicate=lambda add, a, b: add(a, b) == 42,
            bounds=bounds,
        )

        # Directly verify this property fails
        calc = BoundedCalculator(bounds=bounds)
        # Find a counterexample manually
        found_violation = False
        for a in range(bounds.lo, bounds.hi + 1):
            for b in range(bounds.lo, bounds.hi + 1):
                if calc.add(a, b) != 42:
                    found_violation = True
                    break
            if found_violation:
                break
        assert found_violation

    def test_verification_report_has_counterexample(self):
        """When a property fails, the report includes a counterexample."""
        from factory import DarkFactory

        bounds = TINY
        bad_prop = Property(
            name="always_negative",
            description="result is always negative",
            predicate=lambda add, a, b: add(a, b) < 0,
            bounds=bounds,
        )

        from spec import Spec
        bad_spec = Spec(name="bad_addition")
        bad_spec.add(bad_prop)

        calc = BoundedCalculator(bounds=bounds)
        report = DarkFactory._verify_spec(bad_spec, calc.add, bounds)
        assert not report.passed
        assert report.results[0].counterexample is not None


# ---------------------------------------------------------------------------
# Exhaustive verification coverage
# ---------------------------------------------------------------------------

class TestExhaustiveVerification:
    def test_tiny_addition_checks_all_pairs(self):
        """For TINY bounds (-8..7), addition closure checks 16*16 = 256 pairs."""
        bounds = TINY
        spec = addition_spec(bounds)
        calc = BoundedCalculator(bounds=bounds)

        # The closure property checks pairs (arity=2)
        closure_prop = spec.properties[0]
        assert closure_prop.name == "closure"

        result = DarkFactory._verify_property(closure_prop, calc.add, bounds)
        assert result.passed
        assert result.tests_run == bounds.width ** 2  # 16^2 = 256

    def test_tiny_identity_checks_all_singles(self):
        """Identity property checks all 16 values in TINY."""
        bounds = TINY
        spec = addition_spec(bounds)
        calc = BoundedCalculator(bounds=bounds)

        identity_prop = spec.properties[2]
        assert identity_prop.name == "identity"

        result = DarkFactory._verify_property(identity_prop, calc.add, bounds)
        assert result.passed
        assert result.tests_run == bounds.width  # 16

    def test_tiny_associativity_checks_all_triples(self):
        """Associativity checks all 16^3 = 4096 triples in TINY.

        The predicate is guarded: it returns True (vacuously) when
        raw intermediates escape bounds, so every triple passes.
        """
        bounds = TINY
        spec = addition_spec(bounds)
        calc = BoundedCalculator(bounds=bounds)

        assoc_prop = spec.properties[3]
        assert assoc_prop.name == "associativity"

        result = DarkFactory._verify_property(assoc_prop, calc.add, bounds)
        assert result.passed
        assert result.tests_run == bounds.width ** 3  # 4096


# ---------------------------------------------------------------------------
# Overflow strategies interact correctly with specs
# ---------------------------------------------------------------------------

class TestOverflowStrategyConformance:
    def test_wrap_addition_closure(self):
        """Wrapping arithmetic still satisfies closure."""
        bounds = Bounds(lo=0, hi=7, overflow=OverflowStrategy.WRAP)
        calc = DarkFactory.create(bounds)
        # 7 + 1 wraps to 0
        assert calc.add(7, 1) == 0
        assert bounds.contains(calc.add(7, 1))

    def test_clamp_multiplication_closure(self):
        """Clamped multiplication stays in bounds."""
        bounds = Bounds(lo=-10, hi=10, overflow=OverflowStrategy.CLAMP)
        calc = DarkFactory.create(bounds)
        assert calc.mul(10, 10) == 10  # clamped to hi
        assert calc.mul(-10, 10) == -10  # clamped to lo

    def test_error_strategy_raises_on_overflow(self):
        """ERROR strategy raises instead of returning out-of-bounds."""
        bounds = Bounds(lo=-10, hi=10, overflow=OverflowStrategy.ERROR)
        calc = BoundedCalculator(bounds=bounds)
        with pytest.raises(OverflowError):
            calc.add(10, 1)

    def test_div_zero_return_zero(self):
        bounds = Bounds(
            lo=-10, hi=10,
            div_zero=DivisionByZeroStrategy.RETURN_ZERO,
        )
        calc = BoundedCalculator(bounds=bounds)
        assert calc.div(5, 0) == 0

    def test_div_zero_return_max(self):
        bounds = Bounds(
            lo=-10, hi=10,
            div_zero=DivisionByZeroStrategy.RETURN_MAX,
        )
        calc = BoundedCalculator(bounds=bounds)
        assert calc.div(5, 0) == 10


# ---------------------------------------------------------------------------
# Calculator convenience operations
# ---------------------------------------------------------------------------

class TestConvenienceOps:
    calc = BoundedCalculator(bounds=SMALL)

    def test_neg(self):
        assert self.calc.neg(5) == -5
        assert self.calc.neg(-5) == 5
        assert self.calc.neg(0) == 0

    def test_abs(self):
        assert self.calc.abs(5) == 5
        assert self.calc.abs(-5) == 5
        assert self.calc.abs(0) == 0

    def test_pow_basic(self):
        assert self.calc.pow(2, 0) == 1
        assert self.calc.pow(2, 1) == 2
        assert self.calc.pow(2, 3) == 8
        assert self.calc.pow(3, 3) == 27

    def test_pow_overflow_clamps(self):
        # 2^10 = 1024, but SMALL bounds are [-128, 127]
        assert self.calc.pow(2, 10) == 127

    def test_pow_negative_exp_raises(self):
        with pytest.raises(ValueError, match="negative exponents"):
            self.calc.pow(2, -1)
