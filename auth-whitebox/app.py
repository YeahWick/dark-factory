"""Application factory and entry point.

Run with:
    uvicorn app:app --reload
"""
from __future__ import annotations

from fastapi import FastAPI

from api import auth_router, protected_router, set_store, set_secret, get_store
from middleware import configure as configure_middleware
from models import UserPublic
from store import UserStore

DEFAULT_SECRET = "change-me-in-production"


def create_app(
    store: UserStore | None = None,
    secret: str = DEFAULT_SECRET,
) -> FastAPI:
    """Build and return the FastAPI application.

    Accepts an optional store and secret for testing.
    """
    if store is None:
        store = UserStore()

    set_store(store)
    set_secret(secret)

    def _get_user_public(user_id: str) -> UserPublic:
        user = get_store().get(user_id)
        return UserPublic(
            id=user.id,
            username=user.username,
            roles=user.roles,
            disabled=user.disabled,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )

    configure_middleware(secret=secret, get_user_fn=_get_user_public)

    app = FastAPI(
        title="Auth Frontend API",
        description=(
            "Authentication frontend that protects endpoints with "
            "token-based auth and role-based access control. "
            "Register, login, and access protected resources."
        ),
        version="0.1.0",
    )
    app.include_router(auth_router)
    app.include_router(protected_router)
    return app


# Default app instance for `uvicorn app:app`
app = create_app()
