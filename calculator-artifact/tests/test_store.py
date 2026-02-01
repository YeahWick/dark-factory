"""Tests for the in-memory artifact store."""

from __future__ import annotations

import pytest

from models import (
    ArtifactCreate,
    ArtifactUpdate,
    Port,
    PortDirection,
    ProcessSpec,
    SideEffect,
    SideEffectKind,
)
from store import ArtifactNotFoundError, ArtifactStore, ArtifactValidationError


class TestCreate:

    def test_create_returns_artifact_with_id(self, store, sample_create_payload):
        artifact = store.create(sample_create_payload)
        assert artifact.id
        assert artifact.name == "adder"
        assert len(artifact.ports) == 3
        assert artifact.process.kind == "calculator.add"

    def test_create_sets_timestamps(self, store, sample_create_payload):
        artifact = store.create(sample_create_payload)
        assert artifact.created_at is not None
        assert artifact.updated_at == artifact.created_at

    def test_create_increments_count(self, store, sample_create_payload):
        assert store.count() == 0
        store.create(sample_create_payload)
        assert store.count() == 1
        store.create(
            ArtifactCreate(name="other", process=ProcessSpec(kind="identity"))
        )
        assert store.count() == 2

    def test_create_with_side_effects(self, store, sample_create_with_side_effects):
        artifact = store.create(sample_create_with_side_effects)
        assert len(artifact.side_effects) == 2
        assert artifact.side_effects[0].kind == SideEffectKind.LOG
        assert artifact.side_effects[1].kind == SideEffectKind.METRIC

    def test_create_with_metadata(self, store):
        payload = ArtifactCreate(
            name="meta-node",
            process=ProcessSpec(kind="transform"),
            metadata={"author": "test", "version": 2},
        )
        artifact = store.create(payload)
        assert artifact.metadata["author"] == "test"
        assert artifact.metadata["version"] == 2


class TestGet:

    def test_get_returns_created_artifact(self, store, sample_create_payload):
        created = store.create(sample_create_payload)
        fetched = store.get(created.id)
        assert fetched.id == created.id
        assert fetched.name == created.name

    def test_get_nonexistent_raises(self, store):
        with pytest.raises(ArtifactNotFoundError):
            store.get("nonexistent-id")


class TestList:

    def test_list_empty_store(self, store):
        assert store.list() == []

    def test_list_returns_all(self, store, sample_create_payload):
        store.create(sample_create_payload)
        store.create(
            ArtifactCreate(name="other", process=ProcessSpec(kind="identity"))
        )
        items = store.list()
        assert len(items) == 2

    def test_list_ordered_by_created_at_desc(self, store):
        a1 = store.create(
            ArtifactCreate(name="first", process=ProcessSpec(kind="identity"))
        )
        a2 = store.create(
            ArtifactCreate(name="second", process=ProcessSpec(kind="identity"))
        )
        items = store.list()
        assert items[0].name == "second"
        assert items[1].name == "first"

    def test_list_filter_by_tag(self, store, sample_create_payload):
        store.create(sample_create_payload)  # tags: ["math", "basic"]
        store.create(
            ArtifactCreate(
                name="other", process=ProcessSpec(kind="identity"), tags=["other"]
            )
        )
        math_items = store.list(tag="math")
        assert len(math_items) == 1
        assert math_items[0].name == "adder"

    def test_list_filter_by_process_kind(self, store, sample_create_payload):
        store.create(sample_create_payload)  # kind: calculator.add
        store.create(
            ArtifactCreate(name="other", process=ProcessSpec(kind="identity"))
        )
        add_items = store.list(process_kind="calculator.add")
        assert len(add_items) == 1
        assert add_items[0].name == "adder"

    def test_list_pagination_offset(self, store):
        for i in range(5):
            store.create(
                ArtifactCreate(name=f"node{i}", process=ProcessSpec(kind="identity"))
            )
        items = store.list(offset=2, limit=2)
        assert len(items) == 2

    def test_list_pagination_limit(self, store):
        for i in range(10):
            store.create(
                ArtifactCreate(name=f"node{i}", process=ProcessSpec(kind="identity"))
            )
        items = store.list(limit=3)
        assert len(items) == 3


class TestUpdate:

    def test_update_name(self, store, sample_create_payload):
        created = store.create(sample_create_payload)
        updated = store.update(created.id, ArtifactUpdate(name="renamed"))
        assert updated.name == "renamed"
        assert updated.id == created.id

    def test_update_preserves_unchanged_fields(self, store, sample_create_payload):
        created = store.create(sample_create_payload)
        updated = store.update(created.id, ArtifactUpdate(name="renamed"))
        assert updated.ports == created.ports
        assert updated.process == created.process
        assert updated.tags == created.tags

    def test_update_advances_updated_at(self, store, sample_create_payload):
        created = store.create(sample_create_payload)
        updated = store.update(created.id, ArtifactUpdate(name="renamed"))
        assert updated.updated_at >= created.updated_at
        assert updated.created_at == created.created_at

    def test_update_ports(self, store, sample_create_payload):
        created = store.create(sample_create_payload)
        new_ports = [
            Port(name="x", direction=PortDirection.INPUT, port_type="float"),
            Port(name="out", direction=PortDirection.OUTPUT, port_type="float"),
        ]
        updated = store.update(created.id, ArtifactUpdate(ports=new_ports))
        assert len(updated.ports) == 2
        assert updated.ports[0].port_type == "float"

    def test_update_tags(self, store, sample_create_payload):
        created = store.create(sample_create_payload)
        updated = store.update(created.id, ArtifactUpdate(tags=["new", "tags"]))
        assert updated.tags == ["new", "tags"]

    def test_update_nonexistent_raises(self, store):
        with pytest.raises(ArtifactNotFoundError):
            store.update("bad-id", ArtifactUpdate(name="nope"))

    def test_empty_update_returns_existing(self, store, sample_create_payload):
        created = store.create(sample_create_payload)
        same = store.update(created.id, ArtifactUpdate())
        assert same.id == created.id
        assert same.name == created.name


class TestDelete:

    def test_delete_returns_deleted(self, store, sample_create_payload):
        created = store.create(sample_create_payload)
        deleted = store.delete(created.id)
        assert deleted.id == created.id

    def test_delete_removes_from_store(self, store, sample_create_payload):
        created = store.create(sample_create_payload)
        store.delete(created.id)
        assert store.count() == 0
        with pytest.raises(ArtifactNotFoundError):
            store.get(created.id)

    def test_delete_nonexistent_raises(self, store):
        with pytest.raises(ArtifactNotFoundError):
            store.delete("bad-id")


class TestClear:

    def test_clear_empties_store(self, store, sample_create_payload):
        store.create(sample_create_payload)
        store.create(
            ArtifactCreate(name="other", process=ProcessSpec(kind="identity"))
        )
        assert store.count() == 2
        store.clear()
        assert store.count() == 0
