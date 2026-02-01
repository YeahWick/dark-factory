"""Tests for the FastAPI REST endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import create_app
from store import UserStore

TEST_SECRET = "test-secret-for-api"
VALID_PASSWORD = "secureP@ss1"


@pytest.fixture
def client():
    store = UserStore()
    app = create_app(store=store, secret=TEST_SECRET)
    return TestClient(app)


def _register_user(client, username="alice", password=VALID_PASSWORD,
                   roles=None) -> dict:
    payload = {
        "username": username,
        "password": password,
    }
    if roles:
        payload["roles"] = roles
    resp = client.post("/auth/register", json=payload)
    assert resp.status_code == 201, resp.json()
    return resp.json()


def _login_user(client, username="alice", password=VALID_PASSWORD) -> dict:
    resp = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, resp.json()
    return resp.json()


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------

class TestRegisterEndpoint:

    def test_register_returns_201(self, client):
        resp = client.post("/auth/register", json={
            "username": "alice",
            "password": VALID_PASSWORD,
        })
        assert resp.status_code == 201

    def test_register_returns_user_without_hash(self, client):
        resp = client.post("/auth/register", json={
            "username": "alice",
            "password": VALID_PASSWORD,
        })
        data = resp.json()
        assert "id" in data
        assert data["username"] == "alice"
        assert "password_hash" not in data
        assert "password" not in data
        assert data["roles"] == ["viewer"]
        assert data["disabled"] is False

    def test_register_with_roles(self, client):
        resp = client.post("/auth/register", json={
            "username": "alice",
            "password": VALID_PASSWORD,
            "roles": ["admin", "viewer"],
        })
        assert resp.status_code == 201
        assert resp.json()["roles"] == ["admin", "viewer"]

    def test_register_duplicate_409(self, client):
        _register_user(client)
        resp = client.post("/auth/register", json={
            "username": "alice",
            "password": VALID_PASSWORD,
        })
        assert resp.status_code == 409

    def test_register_invalid_username_422(self, client):
        resp = client.post("/auth/register", json={
            "username": "ab",  # too short
            "password": VALID_PASSWORD,
        })
        assert resp.status_code == 422

    def test_register_short_password_422(self, client):
        resp = client.post("/auth/register", json={
            "username": "alice",
            "password": "short",
        })
        assert resp.status_code == 422

    def test_register_bad_username_format_422(self, client):
        resp = client.post("/auth/register", json={
            "username": "123invalid",
            "password": VALID_PASSWORD,
        })
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------

class TestLoginEndpoint:

    def test_login_success(self, client):
        _register_user(client)
        resp = client.post("/auth/login", json={
            "username": "alice",
            "password": VALID_PASSWORD,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["username"] == "alice"

    def test_login_wrong_password_401(self, client):
        _register_user(client)
        resp = client.post("/auth/login", json={
            "username": "alice",
            "password": "wrongpassword1",
        })
        assert resp.status_code == 401

    def test_login_unknown_user_401(self, client):
        resp = client.post("/auth/login", json={
            "username": "nobody",
            "password": VALID_PASSWORD,
        })
        assert resp.status_code == 401

    def test_login_disabled_401(self, client):
        data = _register_user(client)
        # Disable the user through the store directly
        from store import UserStore
        from models import UserUpdate
        from api import get_store
        store = get_store()
        store.update(data["id"], UserUpdate(disabled=True))

        resp = client.post("/auth/login", json={
            "username": "alice",
            "password": VALID_PASSWORD,
        })
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------

class TestMeEndpoint:

    def test_get_me_authenticated(self, client):
        _register_user(client)
        login = _login_user(client)
        resp = client.get("/auth/me", headers=_auth_header(login["access_token"]))
        assert resp.status_code == 200
        assert resp.json()["username"] == "alice"

    def test_get_me_no_token_401(self, client):
        resp = client.get("/auth/me")
        assert resp.status_code == 401

    def test_get_me_bad_token_401(self, client):
        resp = client.get("/auth/me", headers=_auth_header("invalid.token"))
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# PUT /auth/me
# ---------------------------------------------------------------------------

class TestUpdateMeEndpoint:

    def test_update_roles(self, client):
        _register_user(client)
        login = _login_user(client)
        headers = _auth_header(login["access_token"])
        resp = client.put("/auth/me", json={"roles": ["admin"]}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["roles"] == ["admin"]

    def test_update_disabled(self, client):
        _register_user(client)
        login = _login_user(client)
        headers = _auth_header(login["access_token"])
        resp = client.put("/auth/me", json={"disabled": True}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["disabled"] is True

    def test_update_no_token_401(self, client):
        resp = client.put("/auth/me", json={"roles": ["admin"]})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /protected/status
# ---------------------------------------------------------------------------

class TestProtectedStatus:

    def test_protected_authenticated(self, client):
        _register_user(client)
        login = _login_user(client)
        resp = client.get(
            "/protected/status",
            headers=_auth_header(login["access_token"]),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "alice"
        assert data["message"] == "You are authenticated"

    def test_protected_no_token_401(self, client):
        resp = client.get("/protected/status")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /protected/admin
# ---------------------------------------------------------------------------

class TestProtectedAdmin:

    def test_admin_with_admin_role(self, client):
        _register_user(client, username="bob_admin",
                       roles=["admin", "viewer"])
        login = _login_user(client, username="bob_admin")
        resp = client.get(
            "/protected/admin",
            headers=_auth_header(login["access_token"]),
        )
        assert resp.status_code == 200
        assert resp.json()["message"] == "You have admin access"

    def test_admin_without_admin_role_403(self, client):
        _register_user(client)  # viewer only
        login = _login_user(client)
        resp = client.get(
            "/protected/admin",
            headers=_auth_header(login["access_token"]),
        )
        assert resp.status_code == 403

    def test_admin_no_token_401(self, client):
        resp = client.get("/protected/admin")
        assert resp.status_code == 401
