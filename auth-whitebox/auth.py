"""Core authentication logic.

Provides password hashing, token creation/validation, and credential
verification.  Every decision branch is annotated with its spec
branch-ID (see spec.py BranchSpec) so white-box tests can trace
coverage back to the specification.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

from spec import MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH


# ---------------------------------------------------------------------------
# Password hashing (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------

_HASH_ITERATIONS = 100_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """Hash a plaintext password using PBKDF2-HMAC-SHA256.

    Returns a string in the format ``salt_hex$digest_hex``.

    Branches: PWD-EMPTY, PWD-SHORT, PWD-LONG, PWD-VALID
    """
    if not password:                                              # PWD-EMPTY
        raise ValueError("Password must not be empty")

    if len(password) < MIN_PASSWORD_LENGTH:                       # PWD-SHORT
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        )

    if len(password) > MAX_PASSWORD_LENGTH:                       # PWD-LONG
        raise ValueError(
            f"Password must be at most {MAX_PASSWORD_LENGTH} characters"
        )

    # PWD-VALID
    salt = os.urandom(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _HASH_ITERATIONS
    )
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored_hash: str) -> bool:
    """Check a plaintext password against a stored hash.

    Branches: VERIFY-MATCH, VERIFY-MISMATCH, VERIFY-BAD-FMT
    """
    if "$" not in stored_hash:                                    # VERIFY-BAD-FMT
        raise ValueError("Invalid hash format: missing separator")

    salt_hex, digest_hex = stored_hash.split("$", 1)
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(digest_hex)

    computed = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _HASH_ITERATIONS
    )

    if hmac.compare_digest(computed, expected):                   # VERIFY-MATCH
        return True
    return False                                                  # VERIFY-MISMATCH


# ---------------------------------------------------------------------------
# Token creation / validation
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _sign(payload_b64: str, secret: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_token(
    subject: str,
    secret: str,
    ttl: int = 3600,
    roles: list[str] | None = None,
) -> str:
    """Create a signed token.

    Token format: ``base64url(json_payload).hex(hmac_sha256)``.

    Branches: TOKEN-CREATE-OK, TOKEN-CREATE-NO-SUB, TOKEN-CREATE-NO-SECRET
    """
    if not subject:                                               # TOKEN-CREATE-NO-SUB
        raise ValueError("Token subject must not be empty")

    if not secret:                                                # TOKEN-CREATE-NO-SECRET
        raise ValueError("Token secret must not be empty")

    # TOKEN-CREATE-OK
    now = time.time()
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
        "roles": roles or [],
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = _b64url_encode(payload_json.encode("utf-8"))
    signature = _sign(payload_b64, secret)
    return f"{payload_b64}.{signature}"


def validate_token(token: str, secret: str) -> dict:
    """Validate a token and return its payload.

    Branches: TOKEN-VALID, TOKEN-EXPIRED, TOKEN-BAD-SIG, TOKEN-MALFORMED
    """
    if "." not in token:                                          # TOKEN-MALFORMED
        raise ValueError("Malformed token: missing separator")

    parts = token.split(".", 1)
    if len(parts) != 2:                                           # TOKEN-MALFORMED
        raise ValueError("Malformed token: expected two parts")

    payload_b64, provided_sig = parts

    # Verify signature
    expected_sig = _sign(payload_b64, secret)
    if not hmac.compare_digest(provided_sig, expected_sig):       # TOKEN-BAD-SIG
        raise ValueError("Invalid token: signature mismatch")

    # Decode payload
    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes)
    except Exception as e:                                        # TOKEN-MALFORMED
        raise ValueError(f"Malformed token: {e}") from e

    # Check expiry
    exp = payload.get("exp", 0)
    if time.time() > exp:                                         # TOKEN-EXPIRED
        raise ValueError("Token has expired")

    # TOKEN-VALID
    return payload
