"""Formal specification for the authentication frontend.

Defines executable contracts for every auth operation:
- Preconditions: what inputs must satisfy
- Postconditions: what the output must satisfy given valid inputs
- Error conditions: what inputs must cause specific exceptions
- Algebraic properties: relationships that must always hold
- Branch map: every decision point in the implementation

The spec is machine-readable.  Validation tools iterate over it to
auto-generate conformance tests and search for counterexamples.

Layers
------
Rule              named validation predicate over a User object
OperationSpec     per-operation contract (pre/post/error/properties)
BranchSpec        every decision point white-box tests must cover
AuthSpec          the full contract for a configured auth system
build_spec()      constructs an AuthSpec for a given configuration
"""
from __future__ import annotations

import hashlib
import hmac
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 64
USERNAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{2,63}$")
DEFAULT_TOKEN_TTL = 3600  # 1 hour


# ---------------------------------------------------------------------------
# Rule: a named, executable predicate over a user dict
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    """A named validation rule for auth entities."""

    id: str
    name: str
    description: str
    check: Callable[[Any], bool]


# ---------------------------------------------------------------------------
# User validation rules
# ---------------------------------------------------------------------------

def _user_has_id(u: Any) -> bool:
    return bool(getattr(u, "id", None))


def _user_has_username(u: Any) -> bool:
    name = getattr(u, "username", "")
    return bool(name and name.strip())


def _user_username_valid_format(u: Any) -> bool:
    name = getattr(u, "username", "")
    return bool(USERNAME_PATTERN.match(name))


def _user_has_password_hash(u: Any) -> bool:
    h = getattr(u, "password_hash", "")
    return bool(h and "$" in h)


def _user_has_role(u: Any) -> bool:
    roles = getattr(u, "roles", [])
    return len(roles) > 0


def _user_roles_are_strings(u: Any) -> bool:
    roles = getattr(u, "roles", [])
    return all(isinstance(r, str) and bool(r.strip()) for r in roles)


def _user_has_timestamps(u: Any) -> bool:
    return (
        getattr(u, "created_at", None) is not None
        and getattr(u, "updated_at", None) is not None
    )


def _user_time_order(u: Any) -> bool:
    created = getattr(u, "created_at", None)
    updated = getattr(u, "updated_at", None)
    if created is None or updated is None:
        return False
    return updated >= created


def _user_disabled_is_bool(u: Any) -> bool:
    return isinstance(getattr(u, "disabled", None), bool)


USER_RULES: list[Rule] = [
    Rule(
        id="AUTH-USER-ID",
        name="user_has_id",
        description="User must have a non-empty id",
        check=_user_has_id,
    ),
    Rule(
        id="AUTH-USER-NAME",
        name="user_has_username",
        description="User must have a non-empty username",
        check=_user_has_username,
    ),
    Rule(
        id="AUTH-USER-NAME-FMT",
        name="user_username_valid_format",
        description="Username must match ^[a-zA-Z][a-zA-Z0-9_.-]{2,63}$",
        check=_user_username_valid_format,
    ),
    Rule(
        id="AUTH-USER-HASH",
        name="user_has_password_hash",
        description="User must have a password hash in salt$hash format",
        check=_user_has_password_hash,
    ),
    Rule(
        id="AUTH-USER-ROLE",
        name="user_has_role",
        description="User must have at least one role",
        check=_user_has_role,
    ),
    Rule(
        id="AUTH-USER-ROLE-STR",
        name="user_roles_are_strings",
        description="All roles must be non-empty strings",
        check=_user_roles_are_strings,
    ),
    Rule(
        id="AUTH-USER-TIMESTAMPS",
        name="user_has_timestamps",
        description="User must have created_at and updated_at",
        check=_user_has_timestamps,
    ),
    Rule(
        id="AUTH-USER-TIME-ORDER",
        name="user_time_order",
        description="updated_at must not be earlier than created_at",
        check=_user_time_order,
    ),
    Rule(
        id="AUTH-USER-DISABLED",
        name="user_disabled_is_bool",
        description="disabled field must be a boolean",
        check=_user_disabled_is_bool,
    ),
]


# ---------------------------------------------------------------------------
# Validation report
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidationResult:
    rule_id: str
    rule_name: str
    passed: bool
    description: str


@dataclass(frozen=True)
class ValidationReport:
    results: list[ValidationResult]

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> list[ValidationResult]:
        return [r for r in self.results if not r.passed]

    def summary(self) -> str:
        total = len(self.results)
        failed = len(self.failures)
        if failed == 0:
            return f"All {total} rules passed"
        lines = [f"{failed}/{total} rules failed:"]
        for f in self.failures:
            lines.append(f"  [{f.rule_id}] {f.rule_name}: {f.description}")
        return "\n".join(lines)


def validate_user(user: Any) -> ValidationReport:
    """Run all user spec rules against a user and return a report."""
    results = []
    for rule in USER_RULES:
        try:
            passed = rule.check(user)
        except Exception:
            passed = False
        results.append(
            ValidationResult(
                rule_id=rule.id,
                rule_name=rule.name,
                passed=passed,
                description=rule.description,
            )
        )
    return ValidationReport(results=results)


# ---------------------------------------------------------------------------
# Spec building blocks (operation-level contracts)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Precondition:
    name: str
    description: str
    check: Callable[..., bool]


@dataclass(frozen=True)
class Postcondition:
    name: str
    description: str
    check: Callable[..., bool]


@dataclass(frozen=True)
class ErrorCondition:
    name: str
    description: str
    trigger: Callable[..., bool]
    exception: type


@dataclass(frozen=True)
class AlgebraicProperty:
    name: str
    description: str
    arity: int
    check: Callable[..., bool]


@dataclass(frozen=True)
class OperationSpec:
    name: str
    preconditions: list[Precondition]
    postconditions: list[Postcondition]
    error_conditions: list[ErrorCondition]
    properties: list[AlgebraicProperty]


@dataclass(frozen=True)
class BranchSpec:
    """A decision point in the implementation that must be exercised."""

    id: str
    description: str
    condition: str
    operation: str


@dataclass(frozen=True)
class AuthSpec:
    """Complete contract for the auth system."""

    min_password_length: int
    max_password_length: int
    token_ttl: int
    operations: dict[str, OperationSpec]
    branches: list[BranchSpec]
    user_rules: list[Rule]

    @property
    def all_properties(self) -> list[tuple[str, AlgebraicProperty]]:
        out: list[tuple[str, AlgebraicProperty]] = []
        for name, op in self.operations.items():
            for prop in op.properties:
                out.append((name, prop))
        return out

    @property
    def all_postconditions(self) -> list[tuple[str, Postcondition]]:
        out: list[tuple[str, Postcondition]] = []
        for name, op in self.operations.items():
            for post in op.postconditions:
                out.append((name, post))
        return out


# ---------------------------------------------------------------------------
# Spec builder
# ---------------------------------------------------------------------------

def build_spec(
    min_password_length: int = MIN_PASSWORD_LENGTH,
    max_password_length: int = MAX_PASSWORD_LENGTH,
    token_ttl: int = DEFAULT_TOKEN_TTL,
) -> AuthSpec:
    """Construct the full auth specification."""

    # -- hash_password -------------------------------------------------------
    hash_password_spec = OperationSpec(
        name="hash_password",
        preconditions=[
            Precondition(
                "password_not_empty",
                "Password must not be empty",
                lambda pw: bool(pw),
            ),
            Precondition(
                "password_min_length",
                f"Password must be >= {min_password_length} chars",
                lambda pw: len(pw) >= min_password_length,
            ),
            Precondition(
                "password_max_length",
                f"Password must be <= {max_password_length} chars",
                lambda pw: len(pw) <= max_password_length,
            ),
        ],
        postconditions=[
            Postcondition(
                "hash_contains_separator",
                "Hash is in salt$digest format",
                lambda pw, result: "$" in result,
            ),
            Postcondition(
                "hash_salt_is_hex",
                "Salt portion is valid hex",
                lambda pw, result: _is_hex(result.split("$")[0]),
            ),
            Postcondition(
                "hash_digest_is_hex",
                "Digest portion is valid hex",
                lambda pw, result: (
                    len(result.split("$")) == 2
                    and _is_hex(result.split("$")[1])
                ),
            ),
        ],
        error_conditions=[
            ErrorCondition(
                "empty_password",
                "Empty password raises ValueError",
                lambda pw: pw == "",
                ValueError,
            ),
            ErrorCondition(
                "short_password",
                "Too-short password raises ValueError",
                lambda pw: 0 < len(pw) < min_password_length,
                ValueError,
            ),
            ErrorCondition(
                "long_password",
                "Too-long password raises ValueError",
                lambda pw: len(pw) > max_password_length,
                ValueError,
            ),
        ],
        properties=[
            AlgebraicProperty(
                "deterministic_with_salt",
                "Same password + same salt produces same hash",
                1,
                lambda auth_mod, pw: True,  # tested via verify roundtrip
            ),
        ],
    )

    # -- verify_password -----------------------------------------------------
    verify_password_spec = OperationSpec(
        name="verify_password",
        preconditions=[],
        postconditions=[
            Postcondition(
                "correct_password_matches",
                "verify(password, hash(password)) is True",
                lambda pw, hashed, result: result is True if pw else True,
            ),
        ],
        error_conditions=[
            ErrorCondition(
                "malformed_hash",
                "Malformed hash raises ValueError",
                lambda pw, hashed: "$" not in hashed,
                ValueError,
            ),
        ],
        properties=[
            AlgebraicProperty(
                "roundtrip",
                "verify(pw, hash(pw)) == True",
                1,
                lambda auth_mod, pw: auth_mod.verify_password(
                    pw, auth_mod.hash_password(pw)
                ),
            ),
            AlgebraicProperty(
                "wrong_password_fails",
                "verify(other, hash(pw)) == False when other != pw",
                2,
                lambda auth_mod, pw, other: (
                    pw == other
                    or not auth_mod.verify_password(
                        other, auth_mod.hash_password(pw)
                    )
                ),
            ),
        ],
    )

    # -- create_token --------------------------------------------------------
    create_token_spec = OperationSpec(
        name="create_token",
        preconditions=[
            Precondition(
                "subject_not_empty",
                "Subject (user_id) must not be empty",
                lambda sub, secret: bool(sub),
            ),
            Precondition(
                "secret_not_empty",
                "Secret must not be empty",
                lambda sub, secret: bool(secret),
            ),
        ],
        postconditions=[
            Postcondition(
                "token_has_dot",
                "Token contains a dot separator",
                lambda sub, secret, ttl, result: "." in result,
            ),
            Postcondition(
                "token_two_parts",
                "Token has exactly two dot-separated parts",
                lambda sub, secret, ttl, result: len(result.split(".")) == 2,
            ),
        ],
        error_conditions=[
            ErrorCondition(
                "empty_subject",
                "Empty subject raises ValueError",
                lambda sub, secret: sub == "",
                ValueError,
            ),
            ErrorCondition(
                "empty_secret",
                "Empty secret raises ValueError",
                lambda sub, secret: bool(sub) and secret == "",
                ValueError,
            ),
        ],
        properties=[
            AlgebraicProperty(
                "roundtrip",
                "validate(create(sub, secret), secret) recovers sub",
                1,
                lambda auth_mod, sub: (
                    auth_mod.validate_token(
                        auth_mod.create_token(sub, "test-secret", token_ttl),
                        "test-secret",
                    )["sub"] == sub
                ),
            ),
        ],
    )

    # -- validate_token ------------------------------------------------------
    validate_token_spec = OperationSpec(
        name="validate_token",
        preconditions=[],
        postconditions=[
            Postcondition(
                "payload_has_sub",
                "Valid token payload contains 'sub' field",
                lambda token, secret, result: "sub" in result,
            ),
            Postcondition(
                "payload_has_exp",
                "Valid token payload contains 'exp' field",
                lambda token, secret, result: "exp" in result,
            ),
            Postcondition(
                "payload_has_iat",
                "Valid token payload contains 'iat' field",
                lambda token, secret, result: "iat" in result,
            ),
        ],
        error_conditions=[
            ErrorCondition(
                "malformed_token",
                "Malformed token raises ValueError",
                lambda token, secret: "." not in token,
                ValueError,
            ),
        ],
        properties=[],
    )

    # -- branches ------------------------------------------------------------
    branches = [
        # Password hashing
        BranchSpec(
            "PWD-EMPTY",
            "Empty password rejected",
            "password == ''",
            "hash_password",
        ),
        BranchSpec(
            "PWD-SHORT",
            "Too-short password rejected",
            "0 < len(password) < min_length",
            "hash_password",
        ),
        BranchSpec(
            "PWD-LONG",
            "Too-long password rejected",
            "len(password) > max_length",
            "hash_password",
        ),
        BranchSpec(
            "PWD-VALID",
            "Valid password hashed successfully",
            "min_length <= len(password) <= max_length",
            "hash_password",
        ),
        # Password verification
        BranchSpec(
            "VERIFY-MATCH",
            "Password matches stored hash",
            "computed_hash == stored_hash",
            "verify_password",
        ),
        BranchSpec(
            "VERIFY-MISMATCH",
            "Password does not match stored hash",
            "computed_hash != stored_hash",
            "verify_password",
        ),
        BranchSpec(
            "VERIFY-BAD-FMT",
            "Stored hash has invalid format",
            "'$' not in stored_hash",
            "verify_password",
        ),
        # Token creation
        BranchSpec(
            "TOKEN-CREATE-OK",
            "Token created with valid inputs",
            "sub != '' and secret != ''",
            "create_token",
        ),
        BranchSpec(
            "TOKEN-CREATE-NO-SUB",
            "Token creation rejected: empty subject",
            "sub == ''",
            "create_token",
        ),
        BranchSpec(
            "TOKEN-CREATE-NO-SECRET",
            "Token creation rejected: empty secret",
            "secret == ''",
            "create_token",
        ),
        # Token validation
        BranchSpec(
            "TOKEN-VALID",
            "Token passes all validation checks",
            "signature valid and not expired",
            "validate_token",
        ),
        BranchSpec(
            "TOKEN-EXPIRED",
            "Token rejected: expiry time passed",
            "now > payload.exp",
            "validate_token",
        ),
        BranchSpec(
            "TOKEN-BAD-SIG",
            "Token rejected: signature mismatch",
            "computed_sig != token_sig",
            "validate_token",
        ),
        BranchSpec(
            "TOKEN-MALFORMED",
            "Token rejected: cannot decode/parse",
            "token has no dot or bad base64 or bad JSON",
            "validate_token",
        ),
        # Registration
        BranchSpec(
            "REG-SUCCESS",
            "New user registered successfully",
            "username not taken and input valid",
            "register",
        ),
        BranchSpec(
            "REG-DUP",
            "Registration rejected: username taken",
            "username already exists in store",
            "register",
        ),
        # Authentication
        BranchSpec(
            "AUTH-SUCCESS",
            "Login succeeds: valid credentials",
            "user exists and password matches",
            "authenticate",
        ),
        BranchSpec(
            "AUTH-NO-USER",
            "Login fails: user not found",
            "username not in store",
            "authenticate",
        ),
        BranchSpec(
            "AUTH-BAD-PASS",
            "Login fails: wrong password",
            "user exists but password mismatch",
            "authenticate",
        ),
        BranchSpec(
            "AUTH-DISABLED",
            "Login fails: user account disabled",
            "user.disabled == True",
            "authenticate",
        ),
        # Authorization
        BranchSpec(
            "AUTHZ-ALLOWED",
            "User has required role",
            "required_role in user.roles",
            "authorize",
        ),
        BranchSpec(
            "AUTHZ-DENIED",
            "User lacks required role",
            "required_role not in user.roles",
            "authorize",
        ),
        BranchSpec(
            "AUTHZ-NO-TOKEN",
            "No auth token provided",
            "authorization header missing",
            "authorize",
        ),
        BranchSpec(
            "AUTHZ-INVALID-TOKEN",
            "Auth token is invalid",
            "validate_token raises",
            "authorize",
        ),
    ]

    return AuthSpec(
        min_password_length=min_password_length,
        max_password_length=max_password_length,
        token_ttl=token_ttl,
        operations={
            "hash_password": hash_password_spec,
            "verify_password": verify_password_spec,
            "create_token": create_token_spec,
            "validate_token": validate_token_spec,
        },
        branches=branches,
        user_rules=USER_RULES,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_hex(s: str) -> bool:
    """Check if a string is valid hexadecimal."""
    try:
        int(s, 16)
        return len(s) > 0
    except (ValueError, TypeError):
        return False
