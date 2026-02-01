"""Tests for the FastAPI REST endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import create_app
from store import ArtifactStore


@pytest.fixture
def client():
    store = ArtifactStore()
    app = create_app(store=store)
    return TestClient(app)


def _adder_payload() -> dict:
    return {
        "name": "adder",
        "description": "Adds two integers",
        "ports": [
            {"name": "a", "direction": "input", "port_type": "int"},
            {"name": "b", "direction": "input", "port_type": "int"},
            {"name": "result", "direction": "output", "port_type": "int"},
        ],
        "process": {"kind": "calculator.add"},
        "tags": ["math", "basic"],
    }


def _multiplier_payload() -> dict:
    return {
        "name": "multiplier",
        "description": "Multiplies two integers",
        "ports": [
            {"name": "x", "direction": "input", "port_type": "int"},
            {"name": "y", "direction": "input", "port_type": "int"},
            {"name": "product", "direction": "output", "port_type": "int"},
        ],
        "process": {"kind": "calculator.mul"},
        "tags": ["math"],
    }


# ---------------------------------------------------------------------------
# POST /artifacts
# ---------------------------------------------------------------------------

class TestCreateEndpoint:

    def test_create_returns_201(self, client):
        resp = client.post("/artifacts", json=_adder_payload())
        assert resp.status_code == 201

    def test_create_returns_artifact_with_id(self, client):
        resp = client.post("/artifacts", json=_adder_payload())
        data = resp.json()
        assert "id" in data
        assert data["name"] == "adder"
        assert len(data["ports"]) == 3
        assert data["process"]["kind"] == "calculator.add"
        assert "created_at" in data
        assert "updated_at" in data

    def test_create_minimal(self, client):
        resp = client.post("/artifacts", json={
            "name": "node",
            "process": {"kind": "identity"},
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "node"
        assert data["ports"] == []

    def test_create_invalid_name_422(self, client):
        resp = client.post("/artifacts", json={
            "name": "  ",
            "process": {"kind": "identity"},
        })
        assert resp.status_code == 422

    def test_create_invalid_process_kind_422(self, client):
        resp = client.post("/artifacts", json={
            "name": "bad",
            "process": {"kind": "INVALID KIND"},
        })
        assert resp.status_code == 422

    def test_create_with_side_effects(self, client):
        payload = _adder_payload()
        payload["side_effects"] = [
            {"kind": "log", "description": "Log it", "config": {"level": "info"}},
        ]
        resp = client.post("/artifacts", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert len(data["side_effects"]) == 1
        assert data["side_effects"][0]["kind"] == "log"

    def test_create_with_metadata(self, client):
        payload = _adder_payload()
        payload["metadata"] = {"author": "test", "version": 1}
        resp = client.post("/artifacts", json=payload)
        assert resp.status_code == 201
        assert resp.json()["metadata"]["author"] == "test"


# ---------------------------------------------------------------------------
# GET /artifacts
# ---------------------------------------------------------------------------

class TestListEndpoint:

    def test_list_empty(self, client):
        resp = client.get("/artifacts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_list_returns_created(self, client):
        client.post("/artifacts", json=_adder_payload())
        client.post("/artifacts", json=_multiplier_payload())
        resp = client.get("/artifacts")
        data = resp.json()
        assert len(data["items"]) == 2
        assert data["total"] == 2

    def test_list_filter_by_tag(self, client):
        client.post("/artifacts", json=_adder_payload())  # tags: math, basic
        client.post("/artifacts", json=_multiplier_payload())  # tags: math
        resp = client.get("/artifacts", params={"tag": "basic"})
        data = resp.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["name"] == "adder"

    def test_list_filter_by_process_kind(self, client):
        client.post("/artifacts", json=_adder_payload())
        client.post("/artifacts", json=_multiplier_payload())
        resp = client.get("/artifacts", params={"process_kind": "calculator.mul"})
        data = resp.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["name"] == "multiplier"

    def test_list_pagination(self, client):
        for i in range(5):
            client.post("/artifacts", json={
                "name": f"node{i}",
                "process": {"kind": "identity"},
            })
        resp = client.get("/artifacts", params={"offset": 1, "limit": 2})
        data = resp.json()
        assert len(data["items"]) == 2
        assert data["total"] == 5


# ---------------------------------------------------------------------------
# GET /artifacts/{id}
# ---------------------------------------------------------------------------

class TestGetEndpoint:

    def test_get_existing(self, client):
        create_resp = client.post("/artifacts", json=_adder_payload())
        artifact_id = create_resp.json()["id"]
        resp = client.get(f"/artifacts/{artifact_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == artifact_id

    def test_get_nonexistent_404(self, client):
        resp = client.get("/artifacts/nonexistent")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# PUT /artifacts/{id}
# ---------------------------------------------------------------------------

class TestUpdateEndpoint:

    def test_update_name(self, client):
        create_resp = client.post("/artifacts", json=_adder_payload())
        artifact_id = create_resp.json()["id"]
        resp = client.put(f"/artifacts/{artifact_id}", json={"name": "renamed"})
        assert resp.status_code == 200
        assert resp.json()["name"] == "renamed"

    def test_update_preserves_fields(self, client):
        create_resp = client.post("/artifacts", json=_adder_payload())
        data = create_resp.json()
        artifact_id = data["id"]
        resp = client.put(f"/artifacts/{artifact_id}", json={"name": "renamed"})
        updated = resp.json()
        assert updated["ports"] == data["ports"]
        assert updated["process"] == data["process"]

    def test_update_tags(self, client):
        create_resp = client.post("/artifacts", json=_adder_payload())
        artifact_id = create_resp.json()["id"]
        resp = client.put(
            f"/artifacts/{artifact_id}", json={"tags": ["new", "tags"]}
        )
        assert resp.json()["tags"] == ["new", "tags"]

    def test_update_nonexistent_404(self, client):
        resp = client.put("/artifacts/bad-id", json={"name": "nope"})
        assert resp.status_code == 404

    def test_update_invalid_name_422(self, client):
        create_resp = client.post("/artifacts", json=_adder_payload())
        artifact_id = create_resp.json()["id"]
        resp = client.put(f"/artifacts/{artifact_id}", json={"name": "  "})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# DELETE /artifacts/{id}
# ---------------------------------------------------------------------------

class TestDeleteEndpoint:

    def test_delete_returns_deleted(self, client):
        create_resp = client.post("/artifacts", json=_adder_payload())
        artifact_id = create_resp.json()["id"]
        resp = client.delete(f"/artifacts/{artifact_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == artifact_id

    def test_delete_removes_from_store(self, client):
        create_resp = client.post("/artifacts", json=_adder_payload())
        artifact_id = create_resp.json()["id"]
        client.delete(f"/artifacts/{artifact_id}")
        resp = client.get(f"/artifacts/{artifact_id}")
        assert resp.status_code == 404

    def test_delete_nonexistent_404(self, client):
        resp = client.delete("/artifacts/bad-id")
        assert resp.status_code == 404
