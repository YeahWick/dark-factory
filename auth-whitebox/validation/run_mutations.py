"""Run mutation testing on auth.py using the mutation-testing library.

Usage::

    cd auth-whitebox
    python -m validation.run_mutations            # from YAML config
    python -m validation.run_mutations --explicit  # programmatic mutations

The library injects mutations at runtime via AST patching -- source files
are never modified.  Tests run in-process so the injector can swap
``__code__`` objects on live function references.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mutation_testing import Mutation, MutationRunner

# Ensure auth module is importable and loaded *in this process* so the
# injector can find it in sys.modules.
import auth  # noqa: F401


ROOT = Path(__file__).resolve().parent.parent


def run_tests() -> bool:
    """Execute the pytest suite in-process; return True if all tests pass."""
    exit_code = pytest.main(
        [str(ROOT / "tests"), "-x", "-q", "--tb=line", "--no-header", "-p", "no:cacheprovider"],
    )
    return exit_code == 0


# ── Explicit mutation definitions (mirror mutations.yaml) ───────────

EXPLICIT_MUTATIONS: list[Mutation] = [
    # hash_password boundary mutations
    Mutation(
        id="PWD-LEN-LT-TO-LE",
        function="hash_password",
        original="len(password) < MIN_PASSWORD_LENGTH",
        mutant="len(password) <= MIN_PASSWORD_LENGTH",
        description="Off-by-one: change < to <= in min-length check",
    ),
    Mutation(
        id="PWD-LEN-GT-TO-GE",
        function="hash_password",
        original="len(password) > MAX_PASSWORD_LENGTH",
        mutant="len(password) >= MAX_PASSWORD_LENGTH",
        description="Off-by-one: change > to >= in max-length check",
    ),
    # verify_password mutations
    Mutation(
        id="VERIFY-NOT-IN-TO-IN",
        function="verify_password",
        original="'$' not in stored_hash",
        mutant="'$' in stored_hash",
        description="Negate format check: not in -> in",
    ),
    Mutation(
        id="VERIFY-TRUE-TO-FALSE",
        function="verify_password",
        original="return True",
        mutant="return False",
        description="Invert match result: True -> False",
    ),
    Mutation(
        id="VERIFY-FALSE-TO-TRUE",
        function="verify_password",
        original="return False",
        mutant="return True",
        description="Invert mismatch result: False -> True",
    ),
    # create_token mutations
    Mutation(
        id="TOKEN-TTL-ADD-TO-SUB",
        function="create_token",
        original="now + ttl",
        mutant="now - ttl",
        description="Break expiry: now + ttl -> now - ttl",
    ),
    # validate_token mutations
    Mutation(
        id="TOKEN-NOT-IN-TO-IN",
        function="validate_token",
        original="'.' not in token",
        mutant="'.' in token",
        description="Negate dot check: not in -> in",
    ),
    Mutation(
        id="TOKEN-EXP-GT-TO-LT",
        function="validate_token",
        original="time.time() > exp",
        mutant="time.time() < exp",
        description="Invert expiry: > exp -> < exp",
    ),
]


def main() -> int:
    runner = MutationRunner(run_tests, verbose=True)

    if "--explicit" in sys.argv:
        print("Running with explicit (programmatic) mutations ...\n")
        report = runner.run(
            mutations=EXPLICIT_MUTATIONS,
            module_name="auth",
        )
    else:
        print("Running from mutations.yaml config ...\n")
        config_path = ROOT / "mutations.yaml"
        report = runner.run_from_config(config_path)

    # Exit 0 only if every mutant was killed
    return 0 if report.all_killed else 1


if __name__ == "__main__":
    sys.exit(main())
