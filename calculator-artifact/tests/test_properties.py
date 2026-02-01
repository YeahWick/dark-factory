"""Property-based tests for artifact CRUD operations.

Uses Hypothesis to discover edge cases in model validation,
store operations, and round-trip consistency.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from models import (
    ArtifactCreate,
    ArtifactUpdate,
    Port,
    PortDirection,
    ProcessSpec,
    SideEffect,
    SideEffectKind,
)
from store import ArtifactStore


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

identifier_st = st.from_regex(r"[a-z][a-z0-9_]{0,20}", fullmatch=True)

port_type_st = st.sampled_from(["int", "float", "str", "bool", "list[int]", "any"])

process_kind_st = st.from_regex(r"[a-z][a-z0-9]*(\.[a-z][a-z0-9]*){0,3}", fullmatch=True)

side_effect_kind_st = st.sampled_from(list(SideEffectKind))


def port_st(direction: PortDirection | None = None) -> st.SearchStrategy[Port]:
    dir_st = st.just(direction) if direction else st.sampled_from(list(PortDirection))
    return st.builds(
        Port,
        name=identifier_st,
        direction=dir_st,
        port_type=port_type_st,
        description=st.just(""),
        required=st.just(True),
        default_value=st.just(None),
    )


def unique_ports_st() -> st.SearchStrategy[list[Port]]:
    """Generate a list of ports with unique names per direction."""
    input_ports = st.lists(
        port_st(PortDirection.INPUT), max_size=5, unique_by=lambda p: p.name
    )
    output_ports = st.lists(
        port_st(PortDirection.OUTPUT), max_size=5, unique_by=lambda p: p.name
    )
    return st.tuples(input_ports, output_ports).map(lambda t: t[0] + t[1])


def process_spec_st() -> st.SearchStrategy[ProcessSpec]:
    return st.builds(ProcessSpec, kind=process_kind_st)


def side_effect_st() -> st.SearchStrategy[SideEffect]:
    return st.builds(SideEffect, kind=side_effect_kind_st)


def artifact_create_st() -> st.SearchStrategy[ArtifactCreate]:
    return st.builds(
        ArtifactCreate,
        name=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "Pd")),
            min_size=1,
            max_size=50,
        ),
        description=st.text(max_size=100),
        ports=unique_ports_st(),
        process=process_spec_st(),
        side_effects=st.lists(side_effect_st(), max_size=3),
        tags=st.lists(
            st.text(
                alphabet=st.characters(whitelist_categories=("L", "N")),
                min_size=1,
                max_size=20,
            ),
            max_size=5,
        ),
        metadata=st.just({}),
    )


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

class TestStoreRoundTrip:
    """Create → Get must return an equivalent artifact."""

    @given(payload=artifact_create_st())
    @settings(max_examples=50)
    def test_create_get_roundtrip(self, payload: ArtifactCreate):
        store = ArtifactStore()
        created = store.create(payload)
        fetched = store.get(created.id)
        assert fetched.id == created.id
        assert fetched.name == created.name
        assert fetched.ports == created.ports
        assert fetched.process == created.process

    @given(payload=artifact_create_st())
    @settings(max_examples=50)
    def test_create_appears_in_list(self, payload: ArtifactCreate):
        store = ArtifactStore()
        created = store.create(payload)
        items = store.list()
        assert any(a.id == created.id for a in items)

    @given(payload=artifact_create_st())
    @settings(max_examples=50)
    def test_delete_removes(self, payload: ArtifactCreate):
        store = ArtifactStore()
        created = store.create(payload)
        store.delete(created.id)
        assert store.count() == 0


class TestUpdatePreservation:
    """Updates should only change specified fields."""

    @given(payload=artifact_create_st(), new_name=st.text(
        alphabet=st.characters(whitelist_categories=("L", "N", "Pd")),
        min_size=1,
        max_size=50,
    ))
    @settings(max_examples=50)
    def test_update_name_preserves_process(
        self, payload: ArtifactCreate, new_name: str
    ):
        assume(new_name.strip())
        store = ArtifactStore()
        created = store.create(payload)
        updated = store.update(created.id, ArtifactUpdate(name=new_name))
        assert updated.name == new_name.strip()
        assert updated.process == created.process
        assert updated.ports == created.ports


class TestIdempotency:
    """Operations should be idempotent where expected."""

    @given(payload=artifact_create_st())
    @settings(max_examples=30)
    def test_empty_update_idempotent(self, payload: ArtifactCreate):
        store = ArtifactStore()
        created = store.create(payload)
        updated = store.update(created.id, ArtifactUpdate())
        assert updated.name == created.name
        assert updated.ports == created.ports
        assert updated.process == created.process
