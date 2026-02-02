"""Run mutation testing on auth-whitebox using the mutation-testing library.

Usage::

    cd auth-whitebox
    python -m validation.run_mutations            # from YAML config (auth.py only)
    python -m validation.run_mutations --explicit  # programmatic (auth.py only)
    python -m validation.run_mutations --hardening  # security-hardening mutations
                                                    # across auth, middleware, store

The library injects mutations at runtime via AST patching -- source files
are never modified.  Tests run in-process so the injector can swap
``__code__`` objects on live function references.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mutation_testing import Mutation, MutationRunner
from mutation_testing.runner import MutationReport

# Ensure target modules are loaded *in this process* so the injector can
# find them in sys.modules.
import auth       # noqa: F401
import middleware  # noqa: F401


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


# ── Security-hardening mutations (multi-module) ─────────────────────
#
# These target the most security-critical decision points: signature
# verification, credential gating, and password checking.  Each mutation
# simulates a single-line logic error that would allow unauthorized
# access.

HARDENING_AUTH_MUTATIONS: list[Mutation] = [
    Mutation(
        id="TOKEN-SIG-NEGATE",
        function="validate_token",
        original="not hmac.compare_digest(provided_sig, expected_sig)",
        mutant="hmac.compare_digest(provided_sig, expected_sig)",
        description="Negate signature check: accept forged tokens, reject valid",
    ),
]

HARDENING_MIDDLEWARE_MUTATIONS: list[Mutation] = [
    Mutation(
        id="AUTHZ-CREDS-NEGATE",
        function="get_current_user",
        original="credentials is None",
        mutant="credentials is not None",
        description="Negate null-credential check: skip auth gate",
    ),
]

# Note: store.UserStore.authenticate is a class method, so it cannot be
# targeted directly by the mutation injector (module-level functions only).
# Password-check inversion is already covered by the VERIFY-TRUE-TO-FALSE
# and VERIFY-FALSE-TO-TRUE mutations in auth.py which flow through the
# full login→authenticate path.


def _run_multi_module(runner: MutationRunner) -> MutationReport:
    """Run hardening mutations across auth and middleware modules.

    The library accepts one module per ``run()`` call, so we run each
    group separately and merge the results.
    """
    all_results = []

    groups: list[tuple[str, list[Mutation]]] = [
        ("auth", HARDENING_AUTH_MUTATIONS),
        ("middleware", HARDENING_MIDDLEWARE_MUTATIONS),
    ]

    for module_name, mutations in groups:
        report = runner.run(mutations=mutations, module_name=module_name)
        all_results.extend(report.results)

    total = len(all_results)
    killed = sum(1 for r in all_results if r.killed)
    survived = total - killed
    score = killed / total if total else 0.0

    combined = MutationReport(
        results=all_results,
        total=total,
        killed=killed,
        survived=survived,
        score=score,
    )

    # Print combined summary
    print()
    print("=" * 60)
    print("COMBINED HARDENING SUMMARY")
    print("=" * 60)
    print(f"Total mutations:  {combined.total}")
    print(f"Killed:           {combined.killed}")
    print(f"Survived:         {combined.survived}")
    print(f"Mutation Score:   {combined.score:.1%}")
    print("=" * 60)

    if combined.survived > 0:
        print()
        print("SURVIVING MUTATIONS (improve your tests!):")
        for r in combined.results:
            if not r.killed:
                print(f"  - [{r.mutation.id}] {r.mutation.description}")

    return combined


def main() -> int:
    runner = MutationRunner(run_tests, verbose=True)

    if "--hardening" in sys.argv:
        print("Running security-hardening mutations (multi-module) ...\n")
        report = _run_multi_module(runner)
    elif "--explicit" in sys.argv:
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
