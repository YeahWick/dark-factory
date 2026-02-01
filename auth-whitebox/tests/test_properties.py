"""Property-based tests for the authentication system.

Uses Hypothesis to discover edge cases in password hashing,
token handling, and user store operations.
"""
from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from auth import create_token, hash_password, validate_token, verify_password
from models import UserCreate, UserUpdate
from spec import MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
from store import UserStore

TEST_SECRET = "test-secret-for-properties"

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

valid_password_st = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P")),
    min_size=MIN_PASSWORD_LENGTH,
    max_size=min(MAX_PASSWORD_LENGTH, 64),
)

username_st = st.from_regex(
    r"[a-zA-Z][a-zA-Z0-9_.]{2,20}", fullmatch=True
)

role_st = st.sampled_from(["viewer", "editor", "admin", "moderator"])


def user_create_st() -> st.SearchStrategy[UserCreate]:
    return st.builds(
        UserCreate,
        username=username_st,
        password=valid_password_st,
        roles=st.lists(role_st, min_size=1, max_size=3),
    )


# ---------------------------------------------------------------------------
# Password properties
# ---------------------------------------------------------------------------

class TestPasswordProperties:

    @given(password=valid_password_st)
    @settings(max_examples=50)
    def test_hash_verify_roundtrip(self, password: str):
        """hash then verify always returns True."""
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    @given(password=valid_password_st, other=valid_password_st)
    @settings(max_examples=50)
    def test_wrong_password_fails(self, password: str, other: str):
        """verify with wrong password returns False."""
        assume(password != other)
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        assume(len(other) >= MIN_PASSWORD_LENGTH)
        hashed = hash_password(password)
        assert verify_password(other, hashed) is False

    @given(password=valid_password_st)
    @settings(max_examples=30)
    def test_hash_format_consistent(self, password: str):
        """Hash always has salt$digest format."""
        assume(len(password) >= MIN_PASSWORD_LENGTH)
        hashed = hash_password(password)
        parts = hashed.split("$")
        assert len(parts) == 2
        assert len(parts[0]) == 32   # 16 bytes hex
        assert len(parts[1]) == 64   # 32 bytes hex


# ---------------------------------------------------------------------------
# Token properties
# ---------------------------------------------------------------------------

class TestTokenProperties:

    @given(subject=st.text(min_size=1, max_size=50))
    @settings(max_examples=50)
    def test_create_validate_roundtrip(self, subject: str):
        """create then validate recovers subject."""
        token = create_token(subject, TEST_SECRET, ttl=3600)
        payload = validate_token(token, TEST_SECRET)
        assert payload["sub"] == subject

    @given(subject=st.text(min_size=1, max_size=50))
    @settings(max_examples=30)
    def test_wrong_secret_fails(self, subject: str):
        """validate with wrong secret raises."""
        import pytest
        token = create_token(subject, TEST_SECRET, ttl=3600)
        with pytest.raises(ValueError):
            validate_token(token, "wrong-secret")

    @given(
        subject=st.text(min_size=1, max_size=30),
        roles=st.lists(role_st, min_size=0, max_size=3),
    )
    @settings(max_examples=30)
    def test_roles_preserved(self, subject: str, roles: list[str]):
        """Roles in token payload match creation input."""
        token = create_token(subject, TEST_SECRET, roles=roles)
        payload = validate_token(token, TEST_SECRET)
        assert payload["roles"] == roles


# ---------------------------------------------------------------------------
# Store properties
# ---------------------------------------------------------------------------

class TestStoreProperties:

    @given(payload=user_create_st())
    @settings(max_examples=30)
    def test_register_get_roundtrip(self, payload: UserCreate):
        """Register then get returns same user."""
        store = UserStore()
        user = store.register(payload)
        fetched = store.get(user.id)
        assert fetched.id == user.id
        assert fetched.username == user.username

    @given(payload=user_create_st())
    @settings(max_examples=30)
    def test_register_appears_in_list(self, payload: UserCreate):
        """Registered user appears in list."""
        store = UserStore()
        user = store.register(payload)
        users = store.list()
        assert any(u.id == user.id for u in users)

    @given(payload=user_create_st())
    @settings(max_examples=30)
    def test_delete_removes(self, payload: UserCreate):
        """Delete removes user from store."""
        store = UserStore()
        user = store.register(payload)
        store.delete(user.id)
        assert store.count() == 0

    @given(payload=user_create_st())
    @settings(max_examples=30)
    def test_authenticate_after_register(self, payload: UserCreate):
        """Can authenticate immediately after registering."""
        assume(len(payload.password) >= MIN_PASSWORD_LENGTH)
        store = UserStore()
        store.register(payload)
        user, token = store.authenticate(
            payload.username, payload.password, TEST_SECRET
        )
        assert user.username == payload.username
        assert "." in token
