"""White-box tests for the authentication system.

Each test class targets specific decision branches documented in the
spec (see ``BranchSpec`` ids).  A coverage matrix at the bottom records
which test covers which branch.

Naming convention: test_<branch_id_lowercase>_<scenario>
"""
from __future__ import annotations

import time

import pytest

from auth import (
    create_token,
    hash_password,
    validate_token,
    verify_password,
)
from store import (
    AuthenticationError,
    DuplicateUsernameError,
    UserStore,
)
from models import UserCreate, UserUpdate
from spec import MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH

TEST_SECRET = "test-secret-key"
VALID_PASSWORD = "secureP@ss1"


# ===================================================================
# PASSWORD HASHING (PWD-EMPTY, PWD-SHORT, PWD-LONG, PWD-VALID)
# ===================================================================

class TestPasswordHashing:

    def test_pwd_valid(self):
        """Branch: PWD-VALID — valid password is hashed."""
        result = hash_password(VALID_PASSWORD)
        assert "$" in result
        salt_hex, digest_hex = result.split("$")
        assert len(salt_hex) == 32  # 16 bytes -> 32 hex chars
        assert len(digest_hex) == 64  # SHA-256 -> 32 bytes -> 64 hex chars

    def test_pwd_empty(self):
        """Branch: PWD-EMPTY — empty password rejected."""
        with pytest.raises(ValueError, match="must not be empty"):
            hash_password("")

    def test_pwd_short(self):
        """Branch: PWD-SHORT — too-short password rejected."""
        with pytest.raises(ValueError, match="at least"):
            hash_password("short")

    def test_pwd_short_boundary(self):
        """Boundary: password of length min_length - 1."""
        pw = "a" * (MIN_PASSWORD_LENGTH - 1)
        with pytest.raises(ValueError):
            hash_password(pw)

    def test_pwd_valid_boundary_min(self):
        """Boundary: password of exactly min_length."""
        pw = "a" * MIN_PASSWORD_LENGTH
        result = hash_password(pw)
        assert "$" in result

    def test_pwd_long(self):
        """Branch: PWD-LONG — too-long password rejected."""
        pw = "a" * (MAX_PASSWORD_LENGTH + 1)
        with pytest.raises(ValueError, match="at most"):
            hash_password(pw)

    def test_pwd_valid_boundary_max(self):
        """Boundary: password of exactly max_length."""
        pw = "a" * MAX_PASSWORD_LENGTH
        result = hash_password(pw)
        assert "$" in result

    def test_pwd_unique_salts(self):
        """Same password produces different hashes (random salt)."""
        h1 = hash_password(VALID_PASSWORD)
        h2 = hash_password(VALID_PASSWORD)
        assert h1 != h2


# ===================================================================
# PASSWORD VERIFICATION (VERIFY-MATCH, VERIFY-MISMATCH, VERIFY-BAD-FMT)
# ===================================================================

class TestPasswordVerification:

    def test_verify_match(self):
        """Branch: VERIFY-MATCH — correct password matches."""
        hashed = hash_password(VALID_PASSWORD)
        assert verify_password(VALID_PASSWORD, hashed) is True

    def test_verify_mismatch(self):
        """Branch: VERIFY-MISMATCH — wrong password doesn't match."""
        hashed = hash_password(VALID_PASSWORD)
        assert verify_password("wrongpassword1", hashed) is False

    def test_verify_bad_fmt(self):
        """Branch: VERIFY-BAD-FMT — malformed hash raises."""
        with pytest.raises(ValueError, match="missing separator"):
            verify_password(VALID_PASSWORD, "no-dollar-sign-here")

    def test_verify_empty_password(self):
        """Empty password against valid hash returns False."""
        hashed = hash_password(VALID_PASSWORD)
        assert verify_password("", hashed) is False

    def test_verify_roundtrip_various_passwords(self):
        """Roundtrip for several valid passwords."""
        passwords = ["abcdefgh", "12345678", "P@ssw0rd!", "a" * 50]
        for pw in passwords:
            hashed = hash_password(pw)
            assert verify_password(pw, hashed) is True


# ===================================================================
# TOKEN CREATION (TOKEN-CREATE-OK, TOKEN-CREATE-NO-SUB, TOKEN-CREATE-NO-SECRET)
# ===================================================================

class TestTokenCreation:

    def test_token_create_ok(self):
        """Branch: TOKEN-CREATE-OK — valid inputs produce a token."""
        token = create_token("user123", TEST_SECRET)
        assert "." in token
        parts = token.split(".")
        assert len(parts) == 2

    def test_token_create_no_sub(self):
        """Branch: TOKEN-CREATE-NO-SUB — empty subject rejected."""
        with pytest.raises(ValueError, match="subject"):
            create_token("", TEST_SECRET)

    def test_token_create_no_secret(self):
        """Branch: TOKEN-CREATE-NO-SECRET — empty secret rejected."""
        with pytest.raises(ValueError, match="secret"):
            create_token("user123", "")

    def test_token_create_with_roles(self):
        """Token includes roles in payload."""
        token = create_token("user123", TEST_SECRET, roles=["admin"])
        payload = validate_token(token, TEST_SECRET)
        assert payload["roles"] == ["admin"]

    def test_token_create_with_ttl(self):
        """Token respects custom TTL."""
        token = create_token("user123", TEST_SECRET, ttl=60)
        payload = validate_token(token, TEST_SECRET)
        assert payload["exp"] - payload["iat"] == pytest.approx(60, abs=1)


# ===================================================================
# TOKEN VALIDATION (TOKEN-VALID, TOKEN-EXPIRED, TOKEN-BAD-SIG, TOKEN-MALFORMED)
# ===================================================================

class TestTokenValidation:

    def test_token_valid(self):
        """Branch: TOKEN-VALID — valid token passes validation."""
        token = create_token("user123", TEST_SECRET, ttl=3600)
        payload = validate_token(token, TEST_SECRET)
        assert payload["sub"] == "user123"
        assert "exp" in payload
        assert "iat" in payload

    def test_token_expired(self):
        """Branch: TOKEN-EXPIRED — expired token rejected."""
        token = create_token("user123", TEST_SECRET, ttl=-1)
        with pytest.raises(ValueError, match="expired"):
            validate_token(token, TEST_SECRET)

    def test_token_bad_sig(self):
        """Branch: TOKEN-BAD-SIG — token with wrong secret rejected."""
        token = create_token("user123", TEST_SECRET)
        with pytest.raises(ValueError, match="signature"):
            validate_token(token, "wrong-secret")

    def test_token_malformed_no_dot(self):
        """Branch: TOKEN-MALFORMED — token without dot separator."""
        with pytest.raises(ValueError, match="[Mm]alformed"):
            validate_token("nodothere", TEST_SECRET)

    def test_token_malformed_bad_base64(self):
        """Branch: TOKEN-MALFORMED — invalid base64 payload."""
        # Create a token with valid signature format but bad payload
        token = "!!!invalid-base64!!!.abcdef1234567890"
        with pytest.raises(ValueError):
            validate_token(token, TEST_SECRET)

    def test_token_roundtrip_preserves_sub(self):
        """Roundtrip: create then validate recovers subject."""
        for sub in ["alice", "bob", "user-123", "a" * 50]:
            token = create_token(sub, TEST_SECRET)
            payload = validate_token(token, TEST_SECRET)
            assert payload["sub"] == sub


# ===================================================================
# REGISTRATION (REG-SUCCESS, REG-DUP)
# ===================================================================

class TestRegistration:

    def test_reg_success(self, store):
        """Branch: REG-SUCCESS — new user registered."""
        payload = UserCreate(
            username="alice", password=VALID_PASSWORD, roles=["viewer"]
        )
        user = store.register(payload)
        assert user.username == "alice"
        assert user.id
        assert user.password_hash
        assert user.roles == ["viewer"]
        assert user.disabled is False

    def test_reg_dup(self, store):
        """Branch: REG-DUP — duplicate username rejected."""
        payload = UserCreate(
            username="alice", password=VALID_PASSWORD, roles=["viewer"]
        )
        store.register(payload)
        with pytest.raises(DuplicateUsernameError):
            store.register(payload)

    def test_reg_multiple_users(self, store):
        """Multiple users can be registered with different names."""
        for name in ["alice", "bob_user", "charlie.x"]:
            user = store.register(
                UserCreate(username=name, password=VALID_PASSWORD)
            )
            assert user.username == name
        assert store.count() == 3


# ===================================================================
# AUTHENTICATION (AUTH-SUCCESS, AUTH-NO-USER, AUTH-BAD-PASS, AUTH-DISABLED)
# ===================================================================

class TestAuthentication:

    def _register(self, store, username="alice", password=VALID_PASSWORD,
                  roles=None, disabled=False):
        user = store.register(
            UserCreate(
                username=username,
                password=password,
                roles=roles or ["viewer"],
            )
        )
        if disabled:
            from models import UserUpdate
            store.update(user.id, UserUpdate(disabled=True))
        return user

    def test_auth_success(self, store):
        """Branch: AUTH-SUCCESS — valid credentials return user + token."""
        self._register(store)
        user, token = store.authenticate(
            "alice", VALID_PASSWORD, TEST_SECRET
        )
        assert user.username == "alice"
        assert "." in token

    def test_auth_no_user(self, store):
        """Branch: AUTH-NO-USER — unknown username rejected."""
        with pytest.raises(AuthenticationError):
            store.authenticate("nobody", VALID_PASSWORD, TEST_SECRET)

    def test_auth_bad_pass(self, store):
        """Branch: AUTH-BAD-PASS — wrong password rejected."""
        self._register(store)
        with pytest.raises(AuthenticationError):
            store.authenticate("alice", "wrongpassword1", TEST_SECRET)

    def test_auth_disabled(self, store):
        """Branch: AUTH-DISABLED — disabled account rejected."""
        self._register(store, disabled=True)
        with pytest.raises(AuthenticationError):
            store.authenticate("alice", VALID_PASSWORD, TEST_SECRET)

    def test_auth_token_is_valid(self, store):
        """Token from authentication is valid."""
        self._register(store)
        user, token = store.authenticate(
            "alice", VALID_PASSWORD, TEST_SECRET
        )
        payload = validate_token(token, TEST_SECRET)
        assert payload["sub"] == user.id


# ===================================================================
# USER CRUD
# ===================================================================

class TestUserCRUD:

    def test_get_existing(self, store):
        user = store.register(
            UserCreate(username="alice", password=VALID_PASSWORD)
        )
        fetched = store.get(user.id)
        assert fetched.id == user.id

    def test_get_not_found(self, store):
        from store import UserNotFoundError
        with pytest.raises(UserNotFoundError):
            store.get("nonexistent")

    def test_get_by_username(self, store):
        user = store.register(
            UserCreate(username="alice", password=VALID_PASSWORD)
        )
        fetched = store.get_by_username("alice")
        assert fetched.id == user.id

    def test_list_empty(self, store):
        assert store.list() == []

    def test_list_returns_users(self, store):
        store.register(UserCreate(username="alice", password=VALID_PASSWORD))
        store.register(UserCreate(username="bob_user", password=VALID_PASSWORD))
        users = store.list()
        assert len(users) == 2

    def test_list_pagination(self, store):
        for i in range(5):
            store.register(
                UserCreate(username=f"user{i}xx", password=VALID_PASSWORD)
            )
        page = store.list(offset=1, limit=2)
        assert len(page) == 2

    def test_update_roles(self, store):
        user = store.register(
            UserCreate(username="alice", password=VALID_PASSWORD)
        )
        updated = store.update(user.id, UserUpdate(roles=["admin"]))
        assert updated.roles == ["admin"]

    def test_update_disabled(self, store):
        user = store.register(
            UserCreate(username="alice", password=VALID_PASSWORD)
        )
        updated = store.update(user.id, UserUpdate(disabled=True))
        assert updated.disabled is True

    def test_update_password(self, store):
        user = store.register(
            UserCreate(username="alice", password=VALID_PASSWORD)
        )
        old_hash = user.password_hash
        updated = store.update(
            user.id, UserUpdate(password="newP@ssword1")
        )
        assert updated.password_hash != old_hash

    def test_empty_update_idempotent(self, store):
        user = store.register(
            UserCreate(username="alice", password=VALID_PASSWORD)
        )
        updated = store.update(user.id, UserUpdate())
        assert updated.username == user.username
        assert updated.roles == user.roles

    def test_delete(self, store):
        user = store.register(
            UserCreate(username="alice", password=VALID_PASSWORD)
        )
        deleted = store.delete(user.id)
        assert deleted.id == user.id
        assert store.count() == 0

    def test_delete_not_found(self, store):
        from store import UserNotFoundError
        with pytest.raises(UserNotFoundError):
            store.delete("nonexistent")


# ===================================================================
# AUTHORIZATION / MIDDLEWARE (AUTHZ-NO-TOKEN, AUTHZ-INVALID-TOKEN,
#                             AUTHZ-ALLOWED, AUTHZ-DENIED)
# ===================================================================

class TestAuthorization:
    """White-box tests for middleware auth branches.

    These exercise get_current_user and require_role at the HTTP level
    through a real FastAPI TestClient so the Depends() chain runs end-to-end.
    """

    @pytest.fixture
    def _app(self):
        """Yields (TestClient, store, secret) for a fresh app."""
        from fastapi.testclient import TestClient
        from app import create_app
        _secret = "test-secret-for-authz"
        _store = UserStore()
        app = create_app(store=_store, secret=_secret)
        return TestClient(app), _store, _secret

    def _register_and_login(self, client, store, secret,
                            username="alice", roles=None):
        payload = UserCreate(
            username=username,
            password=VALID_PASSWORD,
            roles=roles or ["viewer"],
        )
        user = store.register(payload)
        token = create_token(user.id, secret, roles=user.roles)
        return user, token

    # -- AUTHZ-NO-TOKEN: missing token → 401 --------------------------

    def test_authz_no_token_status(self, _app):
        """Branch: AUTHZ-NO-TOKEN — no credentials returns 401."""
        client, _, _ = _app
        resp = client.get("/protected/status")
        assert resp.status_code == 401

    def test_authz_no_token_admin(self, _app):
        """Branch: AUTHZ-NO-TOKEN — no credentials on admin returns 401."""
        client, _, _ = _app
        resp = client.get("/protected/admin")
        assert resp.status_code == 401

    # -- AUTHZ-INVALID-TOKEN: bad token → 401 -------------------------

    def test_authz_invalid_token_forged(self, _app):
        """Branch: AUTHZ-INVALID-TOKEN — forged (wrong-secret) token returns 401."""
        client, _, _ = _app
        forged = create_token("fake-id", "wrong-secret", ttl=3600)
        resp = client.get(
            "/protected/status",
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert resp.status_code == 401

    def test_authz_invalid_token_expired(self, _app):
        """Branch: AUTHZ-INVALID-TOKEN — expired token returns 401."""
        client, store, secret = _app
        user, _ = self._register_and_login(client, store, secret)
        expired = create_token(user.id, secret, ttl=-1)
        resp = client.get(
            "/protected/status",
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert resp.status_code == 401

    def test_authz_invalid_token_malformed(self, _app):
        """Branch: AUTHZ-INVALID-TOKEN — malformed token returns 401."""
        client, _, _ = _app
        resp = client.get(
            "/protected/status",
            headers={"Authorization": "Bearer no-dot-separator"},
        )
        assert resp.status_code == 401

    def test_authz_invalid_token_tampered(self, _app):
        """Branch: AUTHZ-INVALID-TOKEN — tampered payload returns 401."""
        client, store, secret = _app
        user, token = self._register_and_login(client, store, secret)
        payload_b64, sig = token.split(".", 1)
        flipped = "A" if payload_b64[-1] != "A" else "B"
        tampered = f"{payload_b64[:-1]}{flipped}.{sig}"
        resp = client.get(
            "/protected/status",
            headers={"Authorization": f"Bearer {tampered}"},
        )
        assert resp.status_code == 401

    # -- AUTHZ-ALLOWED: user has required role → 200 -------------------

    def test_authz_allowed_admin_role(self, _app):
        """Branch: AUTHZ-ALLOWED — admin user can access admin endpoint."""
        client, store, secret = _app
        _, token = self._register_and_login(
            client, store, secret, username="bob_admin",
            roles=["admin", "viewer"],
        )
        resp = client.get(
            "/protected/admin",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    # -- AUTHZ-DENIED: user lacks required role → 403 ------------------

    def test_authz_denied_viewer_on_admin(self, _app):
        """Branch: AUTHZ-DENIED — viewer cannot access admin endpoint."""
        client, store, secret = _app
        _, token = self._register_and_login(
            client, store, secret, roles=["viewer"],
        )
        resp = client.get(
            "/protected/admin",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403


# ===================================================================
# BRANCH COVERAGE MATRIX
# ===================================================================

BRANCH_COVERAGE = {
    "PWD-EMPTY": [
        "TestPasswordHashing::test_pwd_empty",
    ],
    "PWD-SHORT": [
        "TestPasswordHashing::test_pwd_short",
        "TestPasswordHashing::test_pwd_short_boundary",
    ],
    "PWD-LONG": [
        "TestPasswordHashing::test_pwd_long",
    ],
    "PWD-VALID": [
        "TestPasswordHashing::test_pwd_valid",
        "TestPasswordHashing::test_pwd_valid_boundary_min",
        "TestPasswordHashing::test_pwd_valid_boundary_max",
    ],
    "VERIFY-MATCH": [
        "TestPasswordVerification::test_verify_match",
        "TestPasswordVerification::test_verify_roundtrip_various_passwords",
    ],
    "VERIFY-MISMATCH": [
        "TestPasswordVerification::test_verify_mismatch",
    ],
    "VERIFY-BAD-FMT": [
        "TestPasswordVerification::test_verify_bad_fmt",
    ],
    "TOKEN-CREATE-OK": [
        "TestTokenCreation::test_token_create_ok",
    ],
    "TOKEN-CREATE-NO-SUB": [
        "TestTokenCreation::test_token_create_no_sub",
    ],
    "TOKEN-CREATE-NO-SECRET": [
        "TestTokenCreation::test_token_create_no_secret",
    ],
    "TOKEN-VALID": [
        "TestTokenValidation::test_token_valid",
    ],
    "TOKEN-EXPIRED": [
        "TestTokenValidation::test_token_expired",
    ],
    "TOKEN-BAD-SIG": [
        "TestTokenValidation::test_token_bad_sig",
    ],
    "TOKEN-MALFORMED": [
        "TestTokenValidation::test_token_malformed_no_dot",
        "TestTokenValidation::test_token_malformed_bad_base64",
    ],
    "REG-SUCCESS": [
        "TestRegistration::test_reg_success",
    ],
    "REG-DUP": [
        "TestRegistration::test_reg_dup",
    ],
    "AUTH-SUCCESS": [
        "TestAuthentication::test_auth_success",
    ],
    "AUTH-NO-USER": [
        "TestAuthentication::test_auth_no_user",
    ],
    "AUTH-BAD-PASS": [
        "TestAuthentication::test_auth_bad_pass",
    ],
    "AUTH-DISABLED": [
        "TestAuthentication::test_auth_disabled",
    ],
    "AUTHZ-NO-TOKEN": [
        "TestAuthorization::test_authz_no_token_status",
        "TestAuthorization::test_authz_no_token_admin",
    ],
    "AUTHZ-INVALID-TOKEN": [
        "TestAuthorization::test_authz_invalid_token_forged",
        "TestAuthorization::test_authz_invalid_token_expired",
        "TestAuthorization::test_authz_invalid_token_malformed",
        "TestAuthorization::test_authz_invalid_token_tampered",
    ],
    "AUTHZ-ALLOWED": [
        "TestAuthorization::test_authz_allowed_admin_role",
    ],
    "AUTHZ-DENIED": [
        "TestAuthorization::test_authz_denied_viewer_on_admin",
    ],
}
