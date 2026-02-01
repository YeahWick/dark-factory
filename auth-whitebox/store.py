"""In-memory user store with CRUD operations.

Provides user management with spec validation on every write.
All mutations go through the store, which enforces spec validation
and maintains timestamp bookkeeping.
"""
from __future__ import annotations

from datetime import datetime, timezone

from auth import hash_password, verify_password, create_token
from models import User, UserCreate, UserUpdate, UserPublic, _new_id, _utcnow
from spec import validate_user, ValidationReport


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class UserNotFoundError(Exception):
    """Raised when a user lookup fails."""

    def __init__(self, identifier: str) -> None:
        self.identifier = identifier
        super().__init__(f"User not found: {identifier}")


class UserValidationError(Exception):
    """Raised when a user fails spec validation."""

    def __init__(self, report: ValidationReport) -> None:
        self.report = report
        super().__init__(report.summary())


class DuplicateUsernameError(Exception):
    """Raised when a username is already taken."""

    def __init__(self, username: str) -> None:
        self.username = username
        super().__init__(f"Username already taken: {username}")


class AuthenticationError(Exception):
    """Raised when login credentials are invalid."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


# ---------------------------------------------------------------------------
# User store
# ---------------------------------------------------------------------------

class UserStore:
    """In-memory CRUD store for users."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._by_username: dict[str, str] = {}  # username -> user_id

    def _validate_or_raise(self, user: User) -> None:
        report = validate_user(user)
        if not report.passed:
            raise UserValidationError(report)

    # -- Registration -------------------------------------------------------

    def register(self, payload: UserCreate) -> User:
        """Register a new user.

        Branches: REG-SUCCESS, REG-DUP
        """
        if payload.username in self._by_username:                 # REG-DUP
            raise DuplicateUsernameError(payload.username)

        now = _utcnow()
        pw_hash = hash_password(payload.password)

        user = User(
            id=_new_id(),
            username=payload.username,
            password_hash=pw_hash,
            roles=payload.roles,
            disabled=False,
            created_at=now,
            updated_at=now,
        )
        self._validate_or_raise(user)
        self._users[user.id] = user                               # REG-SUCCESS
        self._by_username[user.username] = user.id
        return user

    # -- Authentication -----------------------------------------------------

    def authenticate(
        self,
        username: str,
        password: str,
        secret: str,
        token_ttl: int = 3600,
    ) -> tuple[User, str]:
        """Authenticate a user and return (user, token).

        Branches: AUTH-SUCCESS, AUTH-NO-USER, AUTH-BAD-PASS, AUTH-DISABLED
        """
        user_id = self._by_username.get(username)
        if user_id is None:                                       # AUTH-NO-USER
            raise AuthenticationError("Invalid username or password")

        user = self._users[user_id]

        if user.disabled:                                         # AUTH-DISABLED
            raise AuthenticationError("Account is disabled")

        if not verify_password(password, user.password_hash):     # AUTH-BAD-PASS
            raise AuthenticationError("Invalid username or password")

        # AUTH-SUCCESS
        token = create_token(
            subject=user.id,
            secret=secret,
            ttl=token_ttl,
            roles=user.roles,
        )
        return user, token

    # -- CRUD ---------------------------------------------------------------

    def get(self, user_id: str) -> User:
        """Retrieve a user by id."""
        try:
            return self._users[user_id]
        except KeyError:
            raise UserNotFoundError(user_id) from None

    def get_by_username(self, username: str) -> User:
        """Retrieve a user by username."""
        user_id = self._by_username.get(username)
        if user_id is None:
            raise UserNotFoundError(username)
        return self._users[user_id]

    def list(self, *, offset: int = 0, limit: int = 50) -> list[User]:
        """List users with pagination."""
        items = list(self._users.values())
        items.sort(key=lambda u: u.created_at, reverse=True)
        return items[offset : offset + limit]

    def update(self, user_id: str, payload: UserUpdate) -> User:
        """Update a user. Only supplied fields are changed."""
        existing = self.get(user_id)
        update_data = payload.model_dump(exclude_unset=True)

        if not update_data:
            return existing

        merged = existing.model_dump()

        if "password" in update_data and update_data["password"] is not None:
            merged["password_hash"] = hash_password(update_data["password"])
            del update_data["password"]

        merged.update(update_data)
        merged["updated_at"] = _utcnow()

        updated = User.model_validate(merged)
        self._validate_or_raise(updated)
        self._users[user_id] = updated
        return updated

    def delete(self, user_id: str) -> User:
        """Delete a user and return the deleted record."""
        user = self.get(user_id)
        del self._users[user_id]
        del self._by_username[user.username]
        return user

    def count(self) -> int:
        return len(self._users)

    def clear(self) -> None:
        """Remove all users (useful for testing)."""
        self._users.clear()
        self._by_username.clear()
