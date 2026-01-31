# dark-calculator

MVP exploration of the **Dark Factory** pattern using bounded integer arithmetic.

## The Pattern

A Dark Factory produces objects that are **already proven correct** for a
declared set of bounds. The consumer never sees the verification step — they
just get an instance they can trust.

```
   Spec (what must be true)
     │
     ▼
   Bounds (the domain limits)
     │
     ▼
   Factory ──verify──► Implementation
     │                     │
     │  all properties     │
     │  hold within        │
     │  bounds?            │
     │                     │
     ├── YES ──► return instance (proven correct)
     └── NO  ──► raise VerificationError (never hands out broken code)
```

### Layers

| Layer | File | Role |
|-------|------|------|
| **Spec** | `spec.py` | Declarative properties — commutativity, closure, identity, etc. |
| **Bounds** | `bounds.py` | Domain limits `[lo, hi]` + overflow strategy (clamp / wrap / error) |
| **Implementation** | `calculator.py` | The actual arithmetic, kept deliberately simple |
| **Factory** | `factory.py` | Builds, **exhaustively verifies**, then returns the calculator |

### Key idea

For small bounds (width ≤ 256), the factory checks **every possible input
combination**. This isn't testing — it's proof by exhaustion. For larger
bounds, it falls back to sampling + property-based testing via Hypothesis.

## Quick start

```bash
pip install -r requirements.txt
pytest tests/ -v
```

## Example

```python
from bounds import Bounds
from factory import DarkFactory

# Get a calculator proven correct for [-100, 100]
calc = DarkFactory.create(Bounds(lo=-100, hi=100))

calc.add(60, 50)   # => 100  (clamped to hi)
calc.sub(10, 20)   # => -10
calc.mul(10, 10)    # => 100  (exact)
calc.mul(10, 11)    # => 100  (clamped)
calc.div(7, 2)      # => 3   (truncated toward zero)
```

The factory verified all spec properties against these bounds *before*
returning `calc`. If any property failed, you'd get a `VerificationError`
with a counterexample — never a silently broken calculator.

## Tests

Three test suites covering different verification angles:

- **`test_bounds.py`** — Bounds enforcement: clamp, wrap, error, div-by-zero strategies
- **`test_properties.py`** — Property-based tests (Hypothesis) across INT8/INT16 bounds
- **`test_spec.py`** — End-to-end factory verification, exhaustive coverage counts, broken-impl rejection
