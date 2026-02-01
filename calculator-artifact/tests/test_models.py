"""Tests for artifact data models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models import (
    Artifact,
    ArtifactCreate,
    ArtifactUpdate,
    Port,
    PortDirection,
    ProcessSpec,
    SideEffect,
    SideEffectKind,
)


# ---------------------------------------------------------------------------
# Port tests
# ---------------------------------------------------------------------------

class TestPort:

    def test_valid_port(self):
        p = Port(name="value", direction=PortDirection.INPUT, port_type="int")
        assert p.name == "value"
        assert p.direction == PortDirection.INPUT
        assert p.port_type == "int"
        assert p.required is True
        assert p.default_value is None

    def test_port_with_default(self):
        p = Port(
            name="scale",
            direction=PortDirection.INPUT,
            port_type="float",
            required=False,
            default_value=1.0,
        )
        assert p.required is False
        assert p.default_value == 1.0

    def test_port_name_must_be_identifier(self):
        with pytest.raises(ValidationError, match="identifier"):
            Port(name="not valid!", direction=PortDirection.INPUT, port_type="int")

    def test_port_name_cannot_be_empty(self):
        with pytest.raises(ValidationError):
            Port(name="", direction=PortDirection.INPUT, port_type="int")

    def test_port_type_cannot_be_empty(self):
        with pytest.raises(ValidationError):
            Port(name="x", direction=PortDirection.INPUT, port_type="")

    def test_port_direction_enum(self):
        assert PortDirection.INPUT.value == "input"
        assert PortDirection.OUTPUT.value == "output"


# ---------------------------------------------------------------------------
# ProcessSpec tests
# ---------------------------------------------------------------------------

class TestProcessSpec:

    def test_valid_kind(self):
        ps = ProcessSpec(kind="calculator.add")
        assert ps.kind == "calculator.add"
        assert ps.config == {}

    def test_simple_kind(self):
        ps = ProcessSpec(kind="transform")
        assert ps.kind == "transform"

    def test_nested_kind(self):
        ps = ProcessSpec(kind="calculator.math.add")
        assert ps.kind == "calculator.math.add"

    def test_kind_with_config(self):
        ps = ProcessSpec(kind="calculator.add", config={"overflow": "clamp"})
        assert ps.config["overflow"] == "clamp"

    def test_invalid_kind_uppercase(self):
        with pytest.raises(ValidationError):
            ProcessSpec(kind="Calculator.Add")

    def test_invalid_kind_spaces(self):
        with pytest.raises(ValidationError):
            ProcessSpec(kind="calculator add")

    def test_invalid_kind_empty(self):
        with pytest.raises(ValidationError):
            ProcessSpec(kind="")

    def test_invalid_kind_leading_dot(self):
        with pytest.raises(ValidationError):
            ProcessSpec(kind=".calculator")

    def test_invalid_kind_trailing_dot(self):
        with pytest.raises(ValidationError):
            ProcessSpec(kind="calculator.")


# ---------------------------------------------------------------------------
# SideEffect tests
# ---------------------------------------------------------------------------

class TestSideEffect:

    def test_valid_side_effect(self):
        se = SideEffect(kind=SideEffectKind.LOG)
        assert se.kind == SideEffectKind.LOG
        assert se.config == {}

    def test_side_effect_with_config(self):
        se = SideEffect(
            kind=SideEffectKind.METRIC,
            description="Track operation count",
            config={"metric_name": "ops.count"},
        )
        assert se.description == "Track operation count"
        assert se.config["metric_name"] == "ops.count"

    def test_all_side_effect_kinds(self):
        for kind in SideEffectKind:
            se = SideEffect(kind=kind)
            assert se.kind == kind


# ---------------------------------------------------------------------------
# ArtifactCreate tests
# ---------------------------------------------------------------------------

class TestArtifactCreate:

    def test_minimal_payload(self):
        ac = ArtifactCreate(
            name="node",
            process=ProcessSpec(kind="identity"),
        )
        assert ac.name == "node"
        assert ac.ports == []
        assert ac.side_effects == []
        assert ac.tags == []
        assert ac.metadata == {}

    def test_full_payload(self, sample_create_payload):
        assert sample_create_payload.name == "adder"
        assert len(sample_create_payload.ports) == 3
        assert sample_create_payload.process.kind == "calculator.add"
        assert "math" in sample_create_payload.tags

    def test_blank_name_rejected(self):
        with pytest.raises(ValidationError, match="blank"):
            ArtifactCreate(name="  ", process=ProcessSpec(kind="identity"))

    def test_duplicate_input_ports_rejected(self):
        with pytest.raises(ValidationError, match="Duplicate"):
            ArtifactCreate(
                name="bad",
                process=ProcessSpec(kind="identity"),
                ports=[
                    Port(name="x", direction=PortDirection.INPUT, port_type="int"),
                    Port(name="x", direction=PortDirection.INPUT, port_type="float"),
                ],
            )

    def test_same_name_different_direction_ok(self):
        ac = ArtifactCreate(
            name="passthrough",
            process=ProcessSpec(kind="identity"),
            ports=[
                Port(name="value", direction=PortDirection.INPUT, port_type="int"),
                Port(name="value", direction=PortDirection.OUTPUT, port_type="int"),
            ],
        )
        assert len(ac.ports) == 2


# ---------------------------------------------------------------------------
# ArtifactUpdate tests
# ---------------------------------------------------------------------------

class TestArtifactUpdate:

    def test_empty_update(self):
        au = ArtifactUpdate()
        assert au.name is None
        assert au.ports is None

    def test_partial_update(self):
        au = ArtifactUpdate(name="renamed")
        assert au.name == "renamed"
        assert au.ports is None

    def test_blank_name_rejected(self):
        with pytest.raises(ValidationError, match="blank"):
            ArtifactUpdate(name="  ")


# ---------------------------------------------------------------------------
# Artifact tests
# ---------------------------------------------------------------------------

class TestArtifact:

    def test_auto_id_and_timestamps(self):
        a = Artifact(name="test", process=ProcessSpec(kind="identity"))
        assert len(a.id) == 32  # hex uuid
        assert a.created_at is not None
        assert a.updated_at is not None

    def test_inputs_outputs_properties(self, sample_create_payload):
        a = Artifact(
            name=sample_create_payload.name,
            ports=sample_create_payload.ports,
            process=sample_create_payload.process,
        )
        assert len(a.inputs) == 2
        assert len(a.outputs) == 1
        assert all(p.direction == PortDirection.INPUT for p in a.inputs)
        assert all(p.direction == PortDirection.OUTPUT for p in a.outputs)
