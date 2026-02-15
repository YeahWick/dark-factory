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


# ---------------------------------------------------------------------------
# Endpoint hardening: every protected endpoint rejects invalid tokens
# ---------------------------------------------------------------------------

# All endpoints that require authentication.
PROTECTED_ENDPOINTS = [
    ("GET", "/auth/me"),
    ("PUT", "/auth/me"),
    ("GET", "/protected/status"),
    ("GET", "/protected/admin"),
]


class TestEndpointHardening:
    """Ensure every protected endpoint rejects forged, expired, malformed,
    and tampered tokens.

    Branches exercised: AUTHZ-NO-TOKEN, AUTHZ-INVALID-TOKEN, TOKEN-BAD-SIG,
    TOKEN-MALFORMED, TOKEN-EXPIRED.
    """

    # -- no token at all ----------------------------------------------------

    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    def test_no_token_401(self, client, method, path):
        resp = client.request(method, path)
        assert resp.status_code == 401

    # -- forged token: valid structure, wrong signing secret ----------------

    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    def test_forged_token_wrong_secret_401(self, client, method, path):
        from auth import create_token

        forged = create_token("fake-user-id", "wrong-secret", ttl=3600)
        resp = client.request(method, path, headers=_auth_header(forged))
        assert resp.status_code == 401

    # -- expired token (signed with correct secret) -------------------------

    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    def test_expired_token_401(self, client, method, path):
        from auth import create_token

        expired = create_token("fake-user-id", TEST_SECRET, ttl=-1)
        resp = client.request(method, path, headers=_auth_header(expired))
        assert resp.status_code == 401

    # -- malformed: no dot separator ----------------------------------------

    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    def test_malformed_no_dot_401(self, client, method, path):
        resp = client.request(method, path, headers=_auth_header("nodothere"))
        assert resp.status_code == 401

    # -- malformed: random garbage with a dot -------------------------------

    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    def test_garbage_token_401(self, client, method, path):
        resp = client.request(
            method, path, headers=_auth_header("!!!garbage!!!.also-garbage"),
        )
        assert resp.status_code == 401

    # -- tampered payload: modify base64 without re-signing -----------------

    @pytest.mark.parametrize("method,path", PROTECTED_ENDPOINTS)
    def test_tampered_payload_401(self, client, method, path):
        _register_user(client)
        login = _login_user(client)
        token = login["access_token"]
        payload_b64, sig = token.split(".", 1)
        # Flip a character in the payload to break the signature match
        flipped = "A" if payload_b64[-1] != "A" else "B"
        tampered = f"{payload_b64[:-1]}{flipped}.{sig}"
        resp = client.request(method, path, headers=_auth_header(tampered))
        assert resp.status_code == 401

    # -- token for a deleted user -------------------------------------------

    def test_deleted_user_token_401(self, client):
        data = _register_user(client)
        login = _login_user(client)
        token = login["access_token"]
        # Delete the user through the store
        from api import get_store

        get_store().delete(data["id"])
        resp = client.get("/protected/status", headers=_auth_header(token))
        assert resp.status_code == 401

    # -- token for a nonexistent subject ------------------------------------

    def test_nonexistent_subject_token_401(self, client):
        from auth import create_token

        # Valid signature + not expired, but subject doesn't exist in store
        token = create_token("no-such-user-id", TEST_SECRET, ttl=3600)
        resp = client.get("/protected/status", headers=_auth_header(token))
        assert resp.status_code == 401
