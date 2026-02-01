"""FastAPI REST endpoints for artifact CRUD.

Routes
------
POST   /artifacts          Create a new artifact
GET    /artifacts          List artifacts (filterable by tag, process_kind)
GET    /artifacts/{id}     Retrieve a single artifact
PUT    /artifacts/{id}     Partially update an artifact
DELETE /artifacts/{id}     Delete an artifact
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from models import Artifact, ArtifactCreate, ArtifactUpdate
from store import ArtifactNotFoundError, ArtifactStore, ArtifactValidationError

router = APIRouter(prefix="/artifacts", tags=["artifacts"])

# The store instance is injected by the app factory (see app.py).
_store: ArtifactStore | None = None


def set_store(store: ArtifactStore) -> None:
    """Inject the store instance. Called once at app startup."""
    global _store
    _store = store


def get_store() -> ArtifactStore:
    assert _store is not None, "Store not initialized"
    return _store


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

class ArtifactListResponse(BaseModel):
    items: list[Artifact]
    total: int


class ErrorResponse(BaseModel):
    detail: str


def _not_found(artifact_id: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"Artifact not found: {artifact_id}")


def _validation_error(e: ArtifactValidationError) -> HTTPException:
    return HTTPException(status_code=422, detail=str(e))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", response_model=Artifact, status_code=201)
def create_artifact(payload: ArtifactCreate) -> Artifact:
    """Create a new artifact."""
    store = get_store()
    try:
        return store.create(payload)
    except ArtifactValidationError as e:
        raise _validation_error(e) from e


@router.get("", response_model=ArtifactListResponse)
def list_artifacts(
    tag: str | None = Query(default=None, description="Filter by tag"),
    process_kind: str | None = Query(
        default=None, description="Filter by process kind"
    ),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=50, ge=1, le=200, description="Pagination limit"),
) -> ArtifactListResponse:
    """List artifacts with optional filtering."""
    store = get_store()
    items = store.list(tag=tag, process_kind=process_kind, offset=offset, limit=limit)
    return ArtifactListResponse(items=items, total=store.count())


@router.get("/{artifact_id}", response_model=Artifact)
def get_artifact(artifact_id: str) -> Artifact:
    """Retrieve a single artifact by id."""
    store = get_store()
    try:
        return store.get(artifact_id)
    except ArtifactNotFoundError:
        raise _not_found(artifact_id)


@router.put("/{artifact_id}", response_model=Artifact)
def update_artifact(artifact_id: str, payload: ArtifactUpdate) -> Artifact:
    """Partially update an artifact."""
    store = get_store()
    try:
        return store.update(artifact_id, payload)
    except ArtifactNotFoundError:
        raise _not_found(artifact_id)
    except ArtifactValidationError as e:
        raise _validation_error(e) from e


@router.delete("/{artifact_id}", response_model=Artifact)
def delete_artifact(artifact_id: str) -> Artifact:
    """Delete an artifact and return the deleted record."""
    store = get_store()
    try:
        return store.delete(artifact_id)
    except ArtifactNotFoundError:
        raise _not_found(artifact_id)
