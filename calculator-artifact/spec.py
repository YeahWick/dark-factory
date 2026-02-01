"""Artifact specification and validation rules.

Defines the invariants that every artifact must satisfy, both at creation
time and after updates. The spec is executable -- each rule is a callable
predicate that returns True/False, enabling automated conformance testing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from models import (
    Artifact,
    ArtifactCreate,
    ArtifactUpdate,
    Port,
    PortDirection,
    ProcessSpec,
    SideEffect,
)


# ---------------------------------------------------------------------------
# Rule: a named, executable predicate over an artifact
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    """A named validation rule for artifacts."""

    id: str
    name: str
    description: str
    check: Callable[[Artifact], bool]


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------

def _has_name(a: Artifact) -> bool:
    return bool(a.name and a.name.strip())


def _has_process(a: Artifact) -> bool:
    return a.process is not None and bool(a.process.kind)


def _port_names_unique_per_direction(a: Artifact) -> bool:
    for direction in PortDirection:
        names = [p.name for p in a.ports if p.direction == direction]
        if len(names) != len(set(names)):
            return False
    return True


def _port_names_are_identifiers(a: Artifact) -> bool:
    return all(p.name.isidentifier() for p in a.ports)


def _process_kind_is_dotted(a: Artifact) -> bool:
    import re
    return bool(re.match(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$", a.process.kind))


def _has_id(a: Artifact) -> bool:
    return bool(a.id)


def _has_timestamps(a: Artifact) -> bool:
    return a.created_at is not None and a.updated_at is not None


def _updated_not_before_created(a: Artifact) -> bool:
    return a.updated_at >= a.created_at


def _optional_ports_have_defaults(a: Artifact) -> bool:
    """Optional input ports should have a default value."""
    for p in a.ports:
        if p.direction == PortDirection.INPUT and not p.required:
            if p.default_value is None:
                return False
    return True


def _tags_are_non_empty_strings(a: Artifact) -> bool:
    return all(isinstance(t, str) and bool(t.strip()) for t in a.tags)


# ---------------------------------------------------------------------------
# Spec: collection of all rules
# ---------------------------------------------------------------------------

ARTIFACT_RULES: list[Rule] = [
    Rule(
        id="ART-NAME",
        name="artifact_has_name",
        description="Artifact must have a non-empty name",
        check=_has_name,
    ),
    Rule(
        id="ART-PROCESS",
        name="artifact_has_process",
        description="Artifact must have a process spec with a kind",
        check=_has_process,
    ),
    Rule(
        id="ART-PORT-UNIQUE",
        name="port_names_unique_per_direction",
        description="Port names must be unique within each direction (input/output)",
        check=_port_names_unique_per_direction,
    ),
    Rule(
        id="ART-PORT-IDENT",
        name="port_names_are_identifiers",
        description="Port names must be valid Python identifiers",
        check=_port_names_are_identifiers,
    ),
    Rule(
        id="ART-PROCESS-KIND",
        name="process_kind_is_dotted",
        description="Process kind must be a dotted lowercase identifier",
        check=_process_kind_is_dotted,
    ),
    Rule(
        id="ART-ID",
        name="artifact_has_id",
        description="Artifact must have a non-empty id",
        check=_has_id,
    ),
    Rule(
        id="ART-TIMESTAMPS",
        name="artifact_has_timestamps",
        description="Artifact must have created_at and updated_at timestamps",
        check=_has_timestamps,
    ),
    Rule(
        id="ART-TIME-ORDER",
        name="updated_not_before_created",
        description="updated_at must not be earlier than created_at",
        check=_updated_not_before_created,
    ),
    Rule(
        id="ART-OPT-DEFAULT",
        name="optional_ports_have_defaults",
        description="Optional input ports should have a default value",
        check=_optional_ports_have_defaults,
    ),
    Rule(
        id="ART-TAGS",
        name="tags_are_non_empty_strings",
        description="All tags must be non-empty strings",
        check=_tags_are_non_empty_strings,
    ),
]


@dataclass(frozen=True)
class ValidationResult:
    rule_id: str
    rule_name: str
    passed: bool
    description: str


@dataclass(frozen=True)
class ValidationReport:
    results: list[ValidationResult]

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> list[ValidationResult]:
        return [r for r in self.results if not r.passed]

    def summary(self) -> str:
        total = len(self.results)
        failed = len(self.failures)
        if failed == 0:
            return f"All {total} rules passed"
        lines = [f"{failed}/{total} rules failed:"]
        for f in self.failures:
            lines.append(f"  [{f.rule_id}] {f.rule_name}: {f.description}")
        return "\n".join(lines)


def validate_artifact(artifact: Artifact) -> ValidationReport:
    """Run all spec rules against an artifact and return a report."""
    results = []
    for rule in ARTIFACT_RULES:
        try:
            passed = rule.check(artifact)
        except Exception:
            passed = False
        results.append(
            ValidationResult(
                rule_id=rule.id,
                rule_name=rule.name,
                passed=passed,
                description=rule.description,
            )
        )
    return ValidationReport(results=results)
