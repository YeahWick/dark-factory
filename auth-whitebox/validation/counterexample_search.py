"""Counterexample search -- discovers gaps in implementation or tests.

This module runs independently of the test suite.  It systematically
searches for:

1. Postcondition violations: inputs where the implementation doesn't
   match the spec's expected output.
2. Error condition violations: inputs that should raise but don't (or
   raise the wrong exception).
3. Property violations: algebraic relationships that fail for some
   input combination.

Run directly::

    cd auth-whitebox
    python -m validation.counterexample_search
"""
from __future__ import annotations

import itertools
import sys
from dataclasses import dataclass, field

sys.path.insert(0, ".")

from auth import create_token, hash_password, validate_token, verify_password
from spec import (
    MIN_PASSWORD_LENGTH,
    MAX_PASSWORD_LENGTH,
    build_spec,
    AuthSpec,
)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Counterexample:
    category: str
    operation: str
    inputs: tuple
    expected: str
    actual: str
    description: str


@dataclass
class SearchReport:
    counterexamples: list[Counterexample] = field(default_factory=list)
    checks_run: int = 0

    @property
    def passed(self) -> bool:
        return len(self.counterexamples) == 0

    def summary(self) -> str:
        lines = [
            "Counterexample Search Report",
            "=" * 40,
            f"Total checks: {self.checks_run}",
            f"Counterexamples found: {len(self.counterexamples)}",
        ]
        if self.counterexamples:
            lines.append("")
            for i, cx in enumerate(self.counterexamples, 1):
                lines.append(f"  [{i}] {cx.category} / {cx.operation}")
                lines.append(f"      Inputs:   {cx.inputs}")
                lines.append(f"      Expected: {cx.expected}")
                lines.append(f"      Actual:   {cx.actual}")
                lines.append(f"      {cx.description}")
        else:
            lines.append("\nNo counterexamples found -- all checks passed.")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Search: hash_password postconditions
# ---------------------------------------------------------------------------

def search_hash_password_postconditions(
    spec: AuthSpec,
) -> tuple[list[Counterexample], int]:
    """Verify hash_password postconditions for representative inputs."""
    cxs: list[Counterexample] = []
    checks = 0

    # Valid passwords of various lengths
    valid_passwords = [
        "a" * MIN_PASSWORD_LENGTH,
        "b" * (MIN_PASSWORD_LENGTH + 1),
        "P@ssw0rd!123",
        "x" * 50,
        "a" * MAX_PASSWORD_LENGTH,
    ]

    for pw in valid_passwords:
        checks += 1
        try:
            result = hash_password(pw)
        except Exception as e:
            cxs.append(Counterexample(
                category="unexpected_error",
                operation="hash_password",
                inputs=(pw,),
                expected="hash string",
                actual=f"{type(e).__name__}: {e}",
                description="hash_password raised unexpected exception",
            ))
            continue

        for post in spec.operations["hash_password"].postconditions:
            if not post.check(pw, result):
                cxs.append(Counterexample(
                    category="postcondition_violation",
                    operation="hash_password",
                    inputs=(pw,),
                    expected=post.description,
                    actual=f"result={result!r}",
                    description=f"Postcondition '{post.name}' violated",
                ))

    return cxs, checks


# ---------------------------------------------------------------------------
# Search: hash_password error conditions
# ---------------------------------------------------------------------------

def search_hash_password_errors(
    spec: AuthSpec,
) -> tuple[list[Counterexample], int]:
    """Verify hash_password error conditions."""
    cxs: list[Counterexample] = []
    checks = 0

    error_passwords = [
        "",                                    # empty
        "a" * (MIN_PASSWORD_LENGTH - 1),       # too short
        "a" * (MAX_PASSWORD_LENGTH + 1),       # too long
    ]

    for pw in error_passwords:
        for ec in spec.operations["hash_password"].error_conditions:
            if not ec.trigger(pw):
                continue
            checks += 1
            try:
                result = hash_password(pw)
                cxs.append(Counterexample(
                    category="missing_error",
                    operation="hash_password",
                    inputs=(pw,),
                    expected=f"{ec.exception.__name__}",
                    actual=f"result={result!r}",
                    description=f"Error '{ec.name}' should have triggered",
                ))
            except ec.exception:
                pass  # expected
            except Exception as e:
                cxs.append(Counterexample(
                    category="wrong_error",
                    operation="hash_password",
                    inputs=(pw,),
                    expected=f"{ec.exception.__name__}",
                    actual=f"{type(e).__name__}: {e}",
                    description=f"Wrong exception type for '{ec.name}'",
                ))

    return cxs, checks


# ---------------------------------------------------------------------------
# Search: verify_password properties
# ---------------------------------------------------------------------------

def search_verify_password_properties(
    spec: AuthSpec,
) -> tuple[list[Counterexample], int]:
    """Verify password hash/verify roundtrip properties."""
    cxs: list[Counterexample] = []
    checks = 0

    test_passwords = [
        "a" * MIN_PASSWORD_LENGTH,
        "correcthorse",
        "P@ssw0rd!123",
        "x" * 30,
    ]

    # Roundtrip: verify(pw, hash(pw)) must be True
    for pw in test_passwords:
        checks += 1
        hashed = hash_password(pw)
        if not verify_password(pw, hashed):
            cxs.append(Counterexample(
                category="property_violation",
                operation="verify_password",
                inputs=(pw,),
                expected="verify(pw, hash(pw)) == True",
                actual="False",
                description="Roundtrip property violated",
            ))

    # Wrong password: verify(other, hash(pw)) must be False
    for pw, other in itertools.combinations(test_passwords, 2):
        checks += 1
        hashed = hash_password(pw)
        if verify_password(other, hashed):
            cxs.append(Counterexample(
                category="property_violation",
                operation="verify_password",
                inputs=(pw, other),
                expected="verify(other, hash(pw)) == False",
                actual="True",
                description="Wrong-password property violated",
            ))

    # Malformed hash error
    checks += 1
    try:
        verify_password("anything", "no-dollar-sign")
        cxs.append(Counterexample(
            category="missing_error",
            operation="verify_password",
            inputs=("anything", "no-dollar-sign"),
            expected="ValueError",
            actual="no exception",
            description="Malformed hash should raise ValueError",
        ))
    except ValueError:
        pass
    except Exception as e:
        cxs.append(Counterexample(
            category="wrong_error",
            operation="verify_password",
            inputs=("anything", "no-dollar-sign"),
            expected="ValueError",
            actual=f"{type(e).__name__}",
            description="Wrong exception for malformed hash",
        ))

    return cxs, checks


# ---------------------------------------------------------------------------
# Search: token create/validate properties
# ---------------------------------------------------------------------------

def search_token_properties(
    spec: AuthSpec,
) -> tuple[list[Counterexample], int]:
    """Verify token creation/validation postconditions and properties."""
    cxs: list[Counterexample] = []
    checks = 0
    secret = "counterexample-secret"

    subjects = ["user1", "admin", "test-user-123", "a" * 50]

    # Roundtrip: validate(create(sub, secret), secret) recovers sub
    for sub in subjects:
        checks += 1
        token = create_token(sub, secret, ttl=3600)
        try:
            payload = validate_token(token, secret)
            if payload["sub"] != sub:
                cxs.append(Counterexample(
                    category="property_violation",
                    operation="create_token/validate_token",
                    inputs=(sub,),
                    expected=f"sub={sub!r}",
                    actual=f"sub={payload['sub']!r}",
                    description="Token roundtrip: subject mismatch",
                ))
        except Exception as e:
            cxs.append(Counterexample(
                category="unexpected_error",
                operation="create_token/validate_token",
                inputs=(sub,),
                expected="valid payload",
                actual=f"{type(e).__name__}: {e}",
                description="Token roundtrip failed",
            ))

    # Postconditions: token format
    for sub in subjects:
        checks += 1
        token = create_token(sub, secret, ttl=3600)
        for post in spec.operations["create_token"].postconditions:
            if not post.check(sub, secret, 3600, token):
                cxs.append(Counterexample(
                    category="postcondition_violation",
                    operation="create_token",
                    inputs=(sub,),
                    expected=post.description,
                    actual=f"token={token!r}",
                    description=f"Postcondition '{post.name}' violated",
                ))

    # Wrong secret: validate with wrong secret must raise
    for sub in subjects:
        checks += 1
        token = create_token(sub, secret, ttl=3600)
        try:
            validate_token(token, "wrong-secret")
            cxs.append(Counterexample(
                category="property_violation",
                operation="validate_token",
                inputs=(sub, "wrong-secret"),
                expected="ValueError (signature mismatch)",
                actual="no exception",
                description="Wrong secret should be rejected",
            ))
        except ValueError:
            pass

    # Expired token: create with ttl=-1 must be rejected
    for sub in subjects:
        checks += 1
        token = create_token(sub, secret, ttl=-1)
        try:
            validate_token(token, secret)
            cxs.append(Counterexample(
                category="property_violation",
                operation="validate_token",
                inputs=(sub, "ttl=-1"),
                expected="ValueError (expired)",
                actual="no exception",
                description="Expired token should be rejected",
            ))
        except ValueError:
            pass

    # Malformed token
    malformed = ["notokenhere", "", "abc", "..."]
    for tok in malformed:
        checks += 1
        if "." not in tok:
            try:
                validate_token(tok, secret)
                cxs.append(Counterexample(
                    category="missing_error",
                    operation="validate_token",
                    inputs=(tok,),
                    expected="ValueError (malformed)",
                    actual="no exception",
                    description="Malformed token should be rejected",
                ))
            except ValueError:
                pass

    # Error conditions: empty subject / empty secret
    for ec in spec.operations["create_token"].error_conditions:
        if "subject" in ec.name:
            checks += 1
            try:
                create_token("", secret)
                cxs.append(Counterexample(
                    category="missing_error",
                    operation="create_token",
                    inputs=("",),
                    expected="ValueError",
                    actual="no exception",
                    description="Empty subject should raise",
                ))
            except ValueError:
                pass
        elif "secret" in ec.name:
            checks += 1
            try:
                create_token("user1", "")
                cxs.append(Counterexample(
                    category="missing_error",
                    operation="create_token",
                    inputs=("user1", ""),
                    expected="ValueError",
                    actual="no exception",
                    description="Empty secret should raise",
                ))
            except ValueError:
                pass

    return cxs, checks


# ---------------------------------------------------------------------------
# Top-level runner
# ---------------------------------------------------------------------------

def run_search() -> SearchReport:
    """Run complete counterexample search."""
    spec = build_spec()
    report = SearchReport()

    for search_fn in (
        lambda: search_hash_password_postconditions(spec),
        lambda: search_hash_password_errors(spec),
        lambda: search_verify_password_properties(spec),
        lambda: search_token_properties(spec),
    ):
        cxs, checks = search_fn()
        report.counterexamples.extend(cxs)
        report.checks_run += checks

    return report


def main() -> None:
    """Run counterexample search and report results."""
    print("Running auth counterexample search...\n")
    report = run_search()
    print(report.summary())

    if not report.passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
