# CLAUDE.md

Project-wide guidance for Claude when working in this repository.

## White-box verification workflow

Every project in this repo should follow the same five-stage verification
pipeline. The stages are ordered so that each one catches defects the
previous stage cannot.

### 1. Write a formal spec (`spec.py`)

Define every operation as a machine-readable contract containing:

- **Preconditions** -- what inputs must satisfy before the operation runs.
- **Postconditions** -- what the output must satisfy given valid inputs.
- **Error conditions** -- what inputs must cause specific exceptions.
- **Algebraic properties** -- mathematical relationships that must always hold
  (e.g. commutativity, identity, inverse).
- **Branch map** -- a `BranchSpec` entry for every decision point in the
  implementation that white-box tests must exercise.

The spec must be importable by tests and validation tools so checks can be
auto-generated from it.

### 2. Implement against the spec

- Annotate every decision branch in the source with its spec branch-ID
  (e.g. `# OVF-CLAMP-HI`) so traceability from code to spec is explicit.
- Keep implementation modules focused: input validation, core logic, and
  overflow/error handling should be clearly separated.

### 3. Write structured tests (`tests/`)

Three complementary test layers are required:

| Layer | File | Purpose |
|---|---|---|
| **White-box tests** | `test_whitebox.py` | Target specific spec branches. Each test is named `test_<branch_id>_<scenario>`. A `BRANCH_COVERAGE` matrix records which test covers which branch. Apply boundary-value analysis at every decision boundary. |
| **Property-based tests** | `test_properties.py` | Use Hypothesis to explore the input space broadly and verify algebraic properties from the spec. |
| **Spec-conformance tests** | `test_spec_conformance.py` | Iterate over spec predicates automatically. When a new postcondition or error condition is added to the spec, it is tested without writing new test code. |

### 4. Mutation testing (`mutmut`)

Run mutation testing to introduce small changes (mutants) to the
implementation and verify that at least one test detects each mutation.
Surviving mutants reveal concrete gaps in the test suite.

```bash
mutmut run --paths-to-mutate=<module>.py --tests-dir=tests/
mutmut results
```

Analyse surviving mutants with a `mutation_analysis.py` script under
`validation/` to categorise gaps and prioritise fixes.

### 5. Counterexample discovery (`validation/counterexample_search.py`)

An independent validation tool that exhaustively checks input combinations
against every postcondition, error condition, and algebraic property.
This runs outside the test suite and searches for:

1. **Postcondition violations** -- inputs where the implementation does not
   match the spec's expected output.
2. **Error condition violations** -- inputs that should raise but do not, or
   raise the wrong exception.
3. **Property violations** -- algebraic relationships that fail for some
   input combination.

Any counterexample found represents a gap in either the implementation or
the test suite.

## Standard Makefile targets

Every project should expose these targets:

```makefile
make test              # Run the test suite
make coverage          # Run tests with branch-level coverage
make mutate            # Run mutation testing
make counterexamples   # Run counterexample search
make validate          # Full pipeline: tests + coverage + counterexamples
make all               # validate + mutation testing + mutation report
```

## General conventions

- Specs are the source of truth. When behaviour is ambiguous, defer to the
  spec; if the spec is missing a case, update the spec first.
- Tests must never hard-code expected values that could be derived from the
  spec. Import predicates and reuse them.
- Keep bounds small in tests so exhaustive checks complete quickly.
- The `validation/` directory is for tools that run independently of pytest
  (counterexample search, mutation analysis).
