"""Application factory and entry point.

Run with:
    uvicorn app:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI

from api import router, set_store
from store import ArtifactStore


def create_app(store: ArtifactStore | None = None) -> FastAPI:
    """Build and return the FastAPI application.

    Accepts an optional store for testing; creates a fresh one if omitted.
    """
    if store is None:
        store = ArtifactStore()

    set_store(store)

    app = FastAPI(
        title="Calculator Artifact API",
        description=(
            "CRUD API for DAG artifacts (blocks/nodes). Each artifact declares "
            "typed input and output ports, a process specification, and optional "
            "side effects. Artifacts created here are wired into processing "
            "pipelines in a later stage."
        ),
        version="0.1.0",
    )
    app.include_router(router)
    return app


# Default app instance for `uvicorn app:app`
app = create_app()
