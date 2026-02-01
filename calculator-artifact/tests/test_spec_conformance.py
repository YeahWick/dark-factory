"""Spec conformance tests.

Auto-verifies every rule in the artifact spec against known-good and
known-bad artifacts. Ensures that the spec rules are executable and
correctly distinguish valid from invalid artifacts.
"""

from __future__ import annotations

import pytest

from models import (
    Artifact,
    Port,
    PortDirection,
    ProcessSpec,
    SideEffect,
    SideEffectKind,
)
from spec import ARTIFACT_RULES, validate_artifact


def _good_artifact(**overrides) -> Artifact:
    """Build a known-valid artifact, optionally overriding fields."""
    defaults = dict(
        name="test",
        description="A test artifact",
        ports=[
            Port(name="a", direction=PortDirection.INPUT, port_type="int"),
            Port(name="out", direction=PortDirection.OUTPUT, port_type="int"),
        ],
        process=ProcessSpec(kind="calculator.add"),
        tags=["test"],
    )
    defaults.update(overrides)
    return Artifact(**defaults)


class TestAllRulesPassForValidArtifact:
    """Every spec rule must pass for a well-formed artifact."""

    def test_good_artifact_passes_all(self):
        artifact = _good_artifact()
        report = validate_artifact(artifact)
        assert report.passed, report.summary()

    def test_good_artifact_with_side_effects(self):
        artifact = _good_artifact(
            side_effects=[
                SideEffect(kind=SideEffectKind.LOG, description="log it"),
            ]
        )
        report = validate_artifact(artifact)
        assert report.passed, report.summary()

    def test_good_artifact_no_ports(self):
        artifact = _good_artifact(ports=[])
        report = validate_artifact(artifact)
        assert report.passed, report.summary()

    def test_good_artifact_with_optional_port(self):
        artifact = _good_artifact(
            ports=[
                Port(
                    name="scale",
                    direction=PortDirection.INPUT,
                    port_type="float",
                    required=False,
                    default_value=1.0,
                ),
                Port(name="out", direction=PortDirection.OUTPUT, port_type="float"),
            ]
        )
        report = validate_artifact(artifact)
        assert report.passed, report.summary()


class TestIndividualRuleDetection:
    """Each rule should detect its specific violation."""

    @pytest.mark.parametrize("rule", ARTIFACT_RULES, ids=lambda r: r.id)
    def test_rule_passes_for_valid(self, rule):
        artifact = _good_artifact()
        assert rule.check(artifact) is True, f"Rule {rule.id} should pass"

    def test_art_name_detects_empty(self):
        artifact = _good_artifact()
        # Bypass pydantic validation by constructing directly
        artifact = artifact.model_copy(update={"name": ""})
        rule = _find_rule("ART-NAME")
        assert rule.check(artifact) is False

    def test_art_port_unique_detects_duplicates(self):
        rule = _find_rule("ART-PORT-UNIQUE")
        artifact = _good_artifact(
            ports=[
                Port(name="x", direction=PortDirection.INPUT, port_type="int"),
                Port(name="x", direction=PortDirection.INPUT, port_type="float"),
            ]
        )
        assert rule.check(artifact) is False

    def test_art_port_unique_allows_same_name_different_direction(self):
        rule = _find_rule("ART-PORT-UNIQUE")
        artifact = _good_artifact(
            ports=[
                Port(name="val", direction=PortDirection.INPUT, port_type="int"),
                Port(name="val", direction=PortDirection.OUTPUT, port_type="int"),
            ]
        )
        assert rule.check(artifact) is True

    def test_art_time_order_detects_violation(self):
        from datetime import datetime, timedelta, timezone

        rule = _find_rule("ART-TIME-ORDER")
        now = datetime.now(timezone.utc)
        artifact = _good_artifact()
        artifact = artifact.model_copy(
            update={
                "created_at": now,
                "updated_at": now - timedelta(seconds=1),
            }
        )
        assert rule.check(artifact) is False

    def test_art_opt_default_detects_missing_default(self):
        rule = _find_rule("ART-OPT-DEFAULT")
        artifact = _good_artifact(
            ports=[
                Port(
                    name="scale",
                    direction=PortDirection.INPUT,
                    port_type="float",
                    required=False,
                    default_value=None,  # violation: optional but no default
                ),
            ]
        )
        assert rule.check(artifact) is False

    def test_art_tags_detects_empty_tag(self):
        rule = _find_rule("ART-TAGS")
        artifact = _good_artifact(tags=["good", ""])
        assert rule.check(artifact) is False


class TestValidationReport:

    def test_report_summary_all_pass(self):
        artifact = _good_artifact()
        report = validate_artifact(artifact)
        assert "All" in report.summary()
        assert "passed" in report.summary()

    def test_report_summary_with_failures(self):
        artifact = _good_artifact()
        artifact = artifact.model_copy(update={"name": ""})
        report = validate_artifact(artifact)
        assert not report.passed
        assert len(report.failures) > 0
        assert "failed" in report.summary()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_rule(rule_id: str):
    for r in ARTIFACT_RULES:
        if r.id == rule_id:
            return r
    raise ValueError(f"Rule not found: {rule_id}")
