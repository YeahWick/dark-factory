"""Authentication models.

Pydantic models for users, credentials, and tokens. These define the
data shapes used across the auth system. No business logic lives here
-- only structure and basic field validation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# User models
# ---------------------------------------------------------------------------

class UserCreate(BaseModel):
    """Payload for registering a new user."""

    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=1)
    roles: list[str] = Field(default_factory=lambda: ["viewer"])

    @field_validator("username")
    @classmethod
    def username_format(cls, v: str) -> str:
        import re
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_.-]{2,63}$", v):
            raise ValueError(
                "Username must start with a letter and contain only "
                "letters, digits, underscores, dots, or hyphens"
            )
        return v

    @field_validator("roles")
    @classmethod
    def roles_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("At least one role is required")
        for role in v:
            if not role.strip():
                raise ValueError("Roles must be non-empty strings")
        return v


class UserUpdate(BaseModel):
    """Payload for updating a user. Only supplied fields are changed."""

    password: str | None = None
    roles: list[str] | None = None
    disabled: bool | None = None

    @field_validator("roles")
    @classmethod
    def roles_non_empty(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            if not v:
                raise ValueError("At least one role is required")
            for role in v:
                if not role.strip():
                    raise ValueError("Roles must be non-empty strings")
        return v


class User(BaseModel):
    """Full user record as stored and returned by the API."""

    id: str = Field(default_factory=_new_id)
    username: str
    password_hash: str
    roles: list[str] = Field(default_factory=lambda: ["viewer"])
    disabled: bool = False
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class UserPublic(BaseModel):
    """User record without sensitive fields, for API responses."""

    id: str
    username: str
    roles: list[str]
    disabled: bool
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Auth request/response models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    """Credentials for logging in."""

    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    """Response from a successful login."""

    access_token: str
    token_type: str = "bearer"
    user: UserPublic


class TokenPayload(BaseModel):
    """Decoded token payload."""

    sub: str
    exp: float
    iat: float
    roles: list[str] = Field(default_factory=list)
