"""FastAPI REST endpoints for authentication.

Routes
------
POST   /auth/register     Register a new user
POST   /auth/login        Log in and receive a token
GET    /auth/me           Get current user profile
PUT    /auth/me           Update current user profile

Protected example routes (require authentication)
-------------------------------------------------
GET    /protected/status  Example protected endpoint
GET    /protected/admin   Example admin-only endpoint
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from middleware import get_current_user, require_role
from models import (
    LoginRequest,
    LoginResponse,
    UserCreate,
    UserPublic,
    UserUpdate,
)
from store import (
    AuthenticationError,
    DuplicateUsernameError,
    UserNotFoundError,
    UserStore,
    UserValidationError,
)

# ---------------------------------------------------------------------------
# Auth router
# ---------------------------------------------------------------------------

auth_router = APIRouter(prefix="/auth", tags=["auth"])

_store: UserStore | None = None
_secret: str = ""


def set_store(store: UserStore) -> None:
    global _store
    _store = store


def set_secret(secret: str) -> None:
    global _secret
    _secret = secret


def get_store() -> UserStore:
    assert _store is not None, "Store not initialized"
    return _store


def _to_public(user) -> UserPublic:
    return UserPublic(
        id=user.id,
        username=user.username,
        roles=user.roles,
        disabled=user.disabled,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


# -- Auth endpoints ---------------------------------------------------------

@auth_router.post("/register", response_model=UserPublic, status_code=201)
def register(payload: UserCreate) -> UserPublic:
    """Register a new user account."""
    store = get_store()
    try:
        user = store.register(payload)
    except DuplicateUsernameError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except UserValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return _to_public(user)


@auth_router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    """Authenticate and receive an access token."""
    store = get_store()
    try:
        user, token = store.authenticate(
            username=payload.username,
            password=payload.password,
            secret=_secret,
        )
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user=_to_public(user),
    )


@auth_router.get("/me", response_model=UserPublic)
def get_me(user: UserPublic = Depends(get_current_user)) -> UserPublic:
    """Get the current authenticated user's profile."""
    return user


@auth_router.put("/me", response_model=UserPublic)
def update_me(
    payload: UserUpdate,
    user: UserPublic = Depends(get_current_user),
) -> UserPublic:
    """Update the current user's profile."""
    store = get_store()
    try:
        updated = store.update(user.id, payload)
    except UserValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return _to_public(updated)


# ---------------------------------------------------------------------------
# Protected example router
# ---------------------------------------------------------------------------

protected_router = APIRouter(prefix="/protected", tags=["protected"])


@protected_router.get("/status")
def protected_status(
    user: UserPublic = Depends(get_current_user),
) -> dict:
    """Example endpoint requiring authentication."""
    return {
        "message": "You are authenticated",
        "user_id": user.id,
        "username": user.username,
    }


@protected_router.get("/admin")
def protected_admin(
    user: UserPublic = Depends(require_role("admin")),
) -> dict:
    """Example endpoint requiring admin role."""
    return {
        "message": "You have admin access",
        "user_id": user.id,
        "username": user.username,
    }
