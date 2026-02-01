"""In-memory artifact store with CRUD operations.

Provides a simple storage backend that can be swapped for a database later.
All mutations go through the store, which enforces spec validation on every
write and maintains timestamp bookkeeping.
"""

from __future__ import annotations

from datetime import datetime, timezone

from models import Artifact, ArtifactCreate, ArtifactUpdate, _new_id, _utcnow
from spec import validate_artifact, ValidationReport


class ArtifactNotFoundError(Exception):
    """Raised when an artifact lookup fails."""

    def __init__(self, artifact_id: str) -> None:
        self.artifact_id = artifact_id
        super().__init__(f"Artifact not found: {artifact_id}")


class ArtifactValidationError(Exception):
    """Raised when an artifact fails spec validation."""

    def __init__(self, report: ValidationReport) -> None:
        self.report = report
        super().__init__(report.summary())


class ArtifactStore:
    """In-memory CRUD store for artifacts."""

    def __init__(self) -> None:
        self._artifacts: dict[str, Artifact] = {}

    # -- helpers -------------------------------------------------------------

    def _validate_or_raise(self, artifact: Artifact) -> None:
        report = validate_artifact(artifact)
        if not report.passed:
            raise ArtifactValidationError(report)

    # -- CRUD ----------------------------------------------------------------

    def create(self, payload: ArtifactCreate) -> Artifact:
        """Create a new artifact from the given payload."""
        now = _utcnow()
        artifact = Artifact(
            id=_new_id(),
            name=payload.name,
            description=payload.description,
            ports=payload.ports,
            process=payload.process,
            side_effects=payload.side_effects,
            tags=payload.tags,
            metadata=payload.metadata,
            created_at=now,
            updated_at=now,
        )
        self._validate_or_raise(artifact)
        self._artifacts[artifact.id] = artifact
        return artifact

    def get(self, artifact_id: str) -> Artifact:
        """Retrieve an artifact by id."""
        try:
            return self._artifacts[artifact_id]
        except KeyError:
            raise ArtifactNotFoundError(artifact_id) from None

    def list(
        self,
        *,
        tag: str | None = None,
        process_kind: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> list[Artifact]:
        """List artifacts with optional filtering and pagination."""
        items = list(self._artifacts.values())

        if tag is not None:
            items = [a for a in items if tag in a.tags]
        if process_kind is not None:
            items = [a for a in items if a.process.kind == process_kind]

        items.sort(key=lambda a: a.created_at, reverse=True)
        return items[offset : offset + limit]

    def update(self, artifact_id: str, payload: ArtifactUpdate) -> Artifact:
        """Partially update an artifact. Only supplied fields are changed."""
        existing = self.get(artifact_id)
        update_data = payload.model_dump(exclude_unset=True)

        if not update_data:
            return existing

        merged = existing.model_dump()
        merged.update(update_data)
        merged["updated_at"] = _utcnow()

        updated = Artifact.model_validate(merged)
        self._validate_or_raise(updated)
        self._artifacts[artifact_id] = updated
        return updated

    def delete(self, artifact_id: str) -> Artifact:
        """Delete an artifact and return the deleted record."""
        artifact = self.get(artifact_id)
        del self._artifacts[artifact_id]
        return artifact

    def count(self) -> int:
        return len(self._artifacts)

    def clear(self) -> None:
        """Remove all artifacts (useful for testing)."""
        self._artifacts.clear()
