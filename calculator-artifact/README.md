# calculator-artifact

CRUD API for DAG artifacts (blocks/nodes) in the dark factory pattern.

An **artifact** is a declarative node in a processing DAG. Each artifact defines:

- **Ports** — typed input and output connection points
- **Process spec** — what the node does (dotted kind + config)
- **Side effects** — optional effects like logging, metrics, notifications
- **Tags & metadata** — for filtering and organization

This sub-project handles artifact creation, retrieval, update, and deletion.
Wiring artifacts into executable pipelines is the next stage.

## Data model

```
Artifact
├── id            (auto-generated UUID)
├── name          (required)
├── description
├── ports[]
│   ├── name       (valid identifier, unique per direction)
│   ├── direction  (input | output)
│   ├── port_type  (e.g. "int", "float", "list[int]")
│   ├── required   (default: true)
│   └── default_value
├── process
│   ├── kind       (dotted identifier, e.g. "calculator.add")
│   └── config     (kind-specific parameters)
├── side_effects[]
│   ├── kind       (log | metric | notify | store)
│   ├── description
│   └── config
├── tags[]
├── metadata{}
├── created_at
└── updated_at
```

## API

| Method | Path                 | Description              |
|--------|----------------------|--------------------------|
| POST   | `/artifacts`         | Create a new artifact    |
| GET    | `/artifacts`         | List (filter by tag/kind)|
| GET    | `/artifacts/{id}`    | Retrieve one artifact    |
| PUT    | `/artifacts/{id}`    | Partial update           |
| DELETE | `/artifacts/{id}`    | Delete and return record |

## Spec validation

Every artifact is validated against executable rules defined in `spec.py`:

| Rule ID        | Description                                      |
|----------------|--------------------------------------------------|
| ART-NAME       | Must have a non-empty name                       |
| ART-PROCESS    | Must have a process spec with a kind             |
| ART-PORT-UNIQUE| Port names unique within each direction          |
| ART-PORT-IDENT | Port names must be valid identifiers             |
| ART-PROCESS-KIND| Process kind must be dotted lowercase identifier|
| ART-ID         | Must have a non-empty id                         |
| ART-TIMESTAMPS | Must have created_at and updated_at              |
| ART-TIME-ORDER | updated_at must not precede created_at           |
| ART-OPT-DEFAULT| Optional input ports must have a default value   |
| ART-TAGS       | All tags must be non-empty strings               |

## Quick start

```bash
make install
make test
make run          # starts on http://localhost:8000
```

Interactive docs at `http://localhost:8000/docs` (Swagger UI).

## Test layers

1. **Model tests** — Pydantic validation, field constraints, edge cases
2. **Store tests** — CRUD operations, filtering, pagination, error handling
3. **API tests** — HTTP endpoint behavior, status codes, round-trips
4. **Spec conformance** — Every rule checked against valid and invalid artifacts
5. **Property-based tests** — Hypothesis-driven CRUD invariant checking
