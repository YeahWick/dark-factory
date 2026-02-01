"""Shared fixtures for artifact tests."""

from __future__ import annotations

import pytest

from models import (
    ArtifactCreate,
    Port,
    PortDirection,
    ProcessSpec,
    SideEffect,
    SideEffectKind,
)
from store import ArtifactStore


@pytest.fixture
def store() -> ArtifactStore:
    return ArtifactStore()


@pytest.fixture
def sample_create_payload() -> ArtifactCreate:
    """A minimal valid creation payload."""
    return ArtifactCreate(
        name="adder",
        description="Adds two integers",
        ports=[
            Port(name="a", direction=PortDirection.INPUT, port_type="int"),
            Port(name="b", direction=PortDirection.INPUT, port_type="int"),
            Port(name="result", direction=PortDirection.OUTPUT, port_type="int"),
        ],
        process=ProcessSpec(kind="calculator.add"),
        tags=["math", "basic"],
    )


@pytest.fixture
def sample_create_with_side_effects() -> ArtifactCreate:
    """Creation payload that includes side effects."""
    return ArtifactCreate(
        name="logged-multiplier",
        description="Multiplies two integers and logs the operation",
        ports=[
            Port(name="x", direction=PortDirection.INPUT, port_type="int"),
            Port(name="y", direction=PortDirection.INPUT, port_type="int"),
            Port(name="product", direction=PortDirection.OUTPUT, port_type="int"),
        ],
        process=ProcessSpec(
            kind="calculator.mul",
            config={"overflow": "clamp", "bounds": [-128, 127]},
        ),
        side_effects=[
            SideEffect(
                kind=SideEffectKind.LOG,
                description="Log multiplication operation",
                config={"level": "info"},
            ),
            SideEffect(
                kind=SideEffectKind.METRIC,
                description="Increment multiply counter",
                config={"metric_name": "ops.multiply.count"},
            ),
        ],
        tags=["math", "instrumented"],
    )
