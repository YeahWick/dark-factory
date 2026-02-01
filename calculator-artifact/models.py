"""Artifact models for DAG node CRUD.

An Artifact represents a block/node in a processing DAG. Each artifact
declares typed input and output ports, a process specification describing
what the node does, and optional side effects. This module defines the
data models only -- no execution logic.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Port: typed input/output slot on an artifact
# ---------------------------------------------------------------------------

class PortDirection(str, Enum):
    INPUT = "input"
    OUTPUT = "output"


class Port(BaseModel):
    """A typed connection point on an artifact."""

    name: str = Field(..., min_length=1, max_length=128)
    direction: PortDirection
    port_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Type annotation, e.g. 'int', 'float', 'str', 'list[int]'",
    )
    description: str = Field(default="", max_length=512)
    required: bool = True
    default_value: Any | None = None

    @field_validator("name")
    @classmethod
    def name_is_identifier(cls, v: str) -> str:
        if not v.isidentifier():
            raise ValueError(f"Port name must be a valid identifier, got {v!r}")
        return v


# ---------------------------------------------------------------------------
# ProcessSpec: declarative description of what the node does
# ---------------------------------------------------------------------------

class ProcessSpec(BaseModel):
    """Declarative specification of the artifact's processing logic.

    `kind` is a dotted string like 'calculator.add' or 'transform.map'.
    `config` holds kind-specific parameters.
    """

    kind: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$",
        description="Dotted process kind, e.g. 'calculator.add'",
    )
    config: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# SideEffect: optional effect the node may trigger
# ---------------------------------------------------------------------------

class SideEffectKind(str, Enum):
    LOG = "log"
    METRIC = "metric"
    NOTIFY = "notify"
    STORE = "store"


class SideEffect(BaseModel):
    """Declarative side effect attached to an artifact."""

    kind: SideEffectKind
    description: str = Field(default="", max_length=512)
    config: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Artifact: the top-level DAG node
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex


class ArtifactCreate(BaseModel):
    """Payload for creating a new artifact (no id/timestamps)."""

    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=2048)
    ports: list[Port] = Field(default_factory=list)
    process: ProcessSpec
    side_effects: list[SideEffect] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Artifact name must not be blank")
        return v.strip()

    @field_validator("ports")
    @classmethod
    def unique_port_names_per_direction(cls, ports: list[Port]) -> list[Port]:
        seen_input: set[str] = set()
        seen_output: set[str] = set()
        for p in ports:
            bucket = seen_input if p.direction == PortDirection.INPUT else seen_output
            if p.name in bucket:
                raise ValueError(
                    f"Duplicate {p.direction.value} port name: {p.name!r}"
                )
            bucket.add(p.name)
        return ports


class ArtifactUpdate(BaseModel):
    """Payload for partial artifact update. Only supplied fields are changed."""

    name: str | None = Field(default=None, min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=2048)
    ports: list[Port] | None = None
    process: ProcessSpec | None = None
    side_effects: list[SideEffect] | None = None
    tags: list[str] | None = None
    metadata: dict[str, Any] | None = None

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v: str | None) -> str | None:
        if v is not None and not v.strip():
            raise ValueError("Artifact name must not be blank")
        return v.strip() if v else v

    @field_validator("ports")
    @classmethod
    def unique_port_names_per_direction(
        cls, ports: list[Port] | None
    ) -> list[Port] | None:
        if ports is None:
            return ports
        seen_input: set[str] = set()
        seen_output: set[str] = set()
        for p in ports:
            bucket = seen_input if p.direction == PortDirection.INPUT else seen_output
            if p.name in bucket:
                raise ValueError(
                    f"Duplicate {p.direction.value} port name: {p.name!r}"
                )
            bucket.add(p.name)
        return ports


class Artifact(BaseModel):
    """Full artifact record as stored and returned by the API."""

    id: str = Field(default_factory=_new_id)
    name: str
    description: str = ""
    ports: list[Port] = Field(default_factory=list)
    process: ProcessSpec
    side_effects: list[SideEffect] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    @property
    def inputs(self) -> list[Port]:
        return [p for p in self.ports if p.direction == PortDirection.INPUT]

    @property
    def outputs(self) -> list[Port]:
        return [p for p in self.ports if p.direction == PortDirection.OUTPUT]
