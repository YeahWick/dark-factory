# calculator-whitebox

MVP demonstrating a **white-box verification workflow** — how to write
code that is as verifiable as possible through a spec, structured tests,
mutation testing, and automated counterexample discovery.

## Design overview

```
spec.py                 Formal specification (predicates, properties, branch map)
    │
    ▼
calculator.py           Implementation (annotated with branch IDs from the spec)
    │
    ├── tests/
    │   ├── test_whitebox.py          Branch/path-targeted tests
    │   ├── test_properties.py        Property-based tests (Hypothesis)
    │   └── test_spec_conformance.py  Auto-generated spec conformance checks
    │
    └── validation/
        ├── counterexample_search.py  Exhaustive search for spec violations
        └── mutation_analysis.py      Analyse mutmut surviving-mutant gaps
```

## Workflow

The verification workflow has five stages.  Each stage catches a
different category of defect.

### 1. Write the spec (`spec.py`)

Define every operation as a collection of **preconditions**,
**postconditions**, **error conditions**, and **algebraic properties**.
List every decision branch (`BranchSpec`) that white-box tests must
exercise.

### 2. Implement against the spec (`calculator.py`)

Each decision branch is annotated with its spec branch-ID in a comment
so that traceability from code to spec is explicit.

### 3. Write white-box tests (`tests/test_whitebox.py`)

Each test class targets specific branches.  A `BRANCH_COVERAGE` matrix
at the bottom of the file records which test covers which branch.
Boundary-value analysis is applied at every decision boundary.

Property-based tests (`tests/test_properties.py`) explore the input
space broadly.  Spec-conformance tests (`tests/test_spec_conformance.py`)
iterate over spec predicates automatically — if a new postcondition is
added to the spec, it is tested without writing new test code.

### 4. Mutation testing (`mutmut`)

Mutation testing introduces small changes (mutants) to the
implementation and checks that at least one test fails.  Surviving
mutants reveal concrete test gaps.

### 5. Counterexample discovery (`validation/counterexample_search.py`)

An independent validation tool that exhaustively checks every input pair
against every postcondition, error condition, and algebraic property for
multiple calculator configurations.  Any counterexample found represents
a gap in either the implementation or the test suite.

## Quick start

```bash
cd calculator-whitebox
pip install -r requirements.txt

# Run all tests
make test

# Run with branch coverage
make coverage

# Run counterexample search (external validation)
make counterexamples

# Run mutation testing
make mutate

# Full pipeline
make validate
```

## What this demonstrates

| Concern                    | Mechanism                              |
|----------------------------|----------------------------------------|
| Spec ↔ implementation link | Branch-ID annotations in source        |
| Branch coverage            | White-box tests + `BRANCH_COVERAGE`    |
| Input-space exploration    | Hypothesis property-based tests        |
| Spec conformance           | Auto-iterated postcondition checks     |
| Test quality               | Mutation testing (mutmut)              |
| Gap discovery              | Exhaustive counterexample search       |
| Proof by exhaustion        | All-pairs verification for small bounds|
