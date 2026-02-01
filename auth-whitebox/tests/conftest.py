"""Shared fixtures for auth tests."""
from __future__ import annotations

import pytest

from models import UserCreate
from store import UserStore


TEST_SECRET = "test-secret-key-for-testing"
VALID_PASSWORD = "secureP@ss1"


@pytest.fixture
def store() -> UserStore:
    return UserStore()


@pytest.fixture
def sample_user_payload() -> UserCreate:
    """A minimal valid user creation payload."""
    return UserCreate(
        username="alice",
        password=VALID_PASSWORD,
        roles=["viewer"],
    )


@pytest.fixture
def sample_admin_payload() -> UserCreate:
    """A user creation payload with admin role."""
    return UserCreate(
        username="bob_admin",
        password=VALID_PASSWORD,
        roles=["admin", "viewer"],
    )
