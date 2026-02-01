"""FastAPI authentication dependencies.

Provides injectable dependencies that protect endpoints with token-based
authentication and role-based authorization.

Branches: AUTHZ-NO-TOKEN, AUTHZ-INVALID-TOKEN, AUTHZ-ALLOWED, AUTHZ-DENIED
"""
from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth import validate_token
from models import UserPublic

_security = HTTPBearer(auto_error=False)

# Module-level configuration injected by the app factory.
_secret: str = ""
_get_user_fn: Callable[[str], UserPublic] | None = None


def configure(secret: str, get_user_fn: Callable[[str], UserPublic]) -> None:
    """Configure the middleware. Called once at app startup."""
    global _secret, _get_user_fn
    _secret = secret
    _get_user_fn = get_user_fn


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_security),
) -> UserPublic:
    """Dependency: extract and validate the current user from the token.

    Branches: AUTHZ-NO-TOKEN, AUTHZ-INVALID-TOKEN
    """
    if credentials is None:                                       # AUTHZ-NO-TOKEN
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = validate_token(credentials.credentials, _secret)
    except ValueError as e:                                       # AUTHZ-INVALID-TOKEN
        raise HTTPException(status_code=401, detail=str(e))

    assert _get_user_fn is not None
    try:
        user = _get_user_fn(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def require_role(role: str) -> Callable:
    """Dependency factory: require that the current user has a specific role.

    Branches: AUTHZ-ALLOWED, AUTHZ-DENIED
    """

    async def _check_role(
        user: UserPublic = Depends(get_current_user),
    ) -> UserPublic:
        if role in user.roles:                                    # AUTHZ-ALLOWED
            return user
        raise HTTPException(                                      # AUTHZ-DENIED
            status_code=403,
            detail=f"Role '{role}' required",
        )

    return _check_role
