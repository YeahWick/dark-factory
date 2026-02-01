"""Spec conformance tests.

Auto-verifies every rule in the auth spec against known-good and
known-bad user objects. When a new rule is added to the spec, it
is tested without writing new test code.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from auth import hash_password
from models import User
from spec import USER_RULES, validate_user


VALID_PASSWORD = "secureP@ss1"


def _good_user(**overrides) -> User:
    """Build a known-valid user, optionally overriding fields."""
    defaults = dict(
        username="testuser",
        password_hash=hash_password(VALID_PASSWORD),
        roles=["viewer"],
        disabled=False,
    )
    defaults.update(overrides)
    return User(**defaults)


class TestAllRulesPassForValidUser:
    """Every spec rule must pass for a well-formed user."""

    def test_good_user_passes_all(self):
        user = _good_user()
        report = validate_user(user)
        assert report.passed, report.summary()

    def test_good_user_with_multiple_roles(self):
        user = _good_user(roles=["admin", "viewer", "editor"])
        report = validate_user(user)
        assert report.passed, report.summary()

    def test_good_user_disabled(self):
        user = _good_user(disabled=True)
        report = validate_user(user)
        assert report.passed, report.summary()


class TestIndividualRuleDetection:
    """Each rule should detect its specific violation."""

    @pytest.mark.parametrize("rule", USER_RULES, ids=lambda r: r.id)
    def test_rule_passes_for_valid(self, rule):
        user = _good_user()
        assert rule.check(user) is True, f"Rule {rule.id} should pass"

    def test_user_id_detects_empty(self):
        rule = _find_rule("AUTH-USER-ID")
        user = _good_user()
        user = user.model_copy(update={"id": ""})
        assert rule.check(user) is False

    def test_user_name_detects_empty(self):
        rule = _find_rule("AUTH-USER-NAME")
        user = _good_user()
        user = user.model_copy(update={"username": ""})
        assert rule.check(user) is False

    def test_user_name_detects_blank(self):
        rule = _find_rule("AUTH-USER-NAME")
        user = _good_user()
        user = user.model_copy(update={"username": "   "})
        assert rule.check(user) is False

    def test_user_name_fmt_detects_invalid(self):
        rule = _find_rule("AUTH-USER-NAME-FMT")
        user = _good_user()
        user = user.model_copy(update={"username": "123invalid"})
        assert rule.check(user) is False

    def test_user_name_fmt_detects_special_chars(self):
        rule = _find_rule("AUTH-USER-NAME-FMT")
        user = _good_user()
        user = user.model_copy(update={"username": "user@name"})
        assert rule.check(user) is False

    def test_user_hash_detects_empty(self):
        rule = _find_rule("AUTH-USER-HASH")
        user = _good_user()
        user = user.model_copy(update={"password_hash": ""})
        assert rule.check(user) is False

    def test_user_hash_detects_no_separator(self):
        rule = _find_rule("AUTH-USER-HASH")
        user = _good_user()
        user = user.model_copy(update={"password_hash": "noseparator"})
        assert rule.check(user) is False

    def test_user_role_detects_empty_list(self):
        rule = _find_rule("AUTH-USER-ROLE")
        user = _good_user()
        user = user.model_copy(update={"roles": []})
        assert rule.check(user) is False

    def test_user_role_str_detects_blank_role(self):
        rule = _find_rule("AUTH-USER-ROLE-STR")
        user = _good_user()
        user = user.model_copy(update={"roles": ["admin", "  "]})
        assert rule.check(user) is False

    def test_user_timestamps_detects_missing(self):
        rule = _find_rule("AUTH-USER-TIMESTAMPS")
        user = _good_user()
        user = user.model_copy(update={"created_at": None})
        assert rule.check(user) is False

    def test_user_time_order_detects_violation(self):
        rule = _find_rule("AUTH-USER-TIME-ORDER")
        now = datetime.now(timezone.utc)
        user = _good_user()
        user = user.model_copy(
            update={
                "created_at": now,
                "updated_at": now - timedelta(seconds=1),
            }
        )
        assert rule.check(user) is False

    def test_user_disabled_detects_non_bool(self):
        rule = _find_rule("AUTH-USER-DISABLED")
        user = _good_user()
        user = user.model_copy(update={"disabled": None})
        assert rule.check(user) is False


class TestValidationReport:

    def test_report_summary_all_pass(self):
        user = _good_user()
        report = validate_user(user)
        assert "All" in report.summary()
        assert "passed" in report.summary()

    def test_report_summary_with_failures(self):
        user = _good_user()
        user = user.model_copy(update={"username": ""})
        report = validate_user(user)
        assert not report.passed
        assert len(report.failures) > 0
        assert "failed" in report.summary()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_rule(rule_id: str):
    for r in USER_RULES:
        if r.id == rule_id:
            return r
    raise ValueError(f"Rule not found: {rule_id}")
