"""Mutation testing analysis.

Wraps ``mutmut`` results and maps surviving mutants back to missing
test scenarios.

Workflow::

    cd calculator-whitebox
    pip install mutmut
    mutmut run --paths-to-mutate=calculator.py --tests-dir=tests/
    python -m validation.mutation_analysis

The goal: every mutant should be *killed* by at least one test.
Surviving mutants reveal concrete gaps in test coverage.
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class Mutant:
    id: int
    status: str          # killed | survived | timeout | suspicious
    source_file: str
    description: str


@dataclass
class MutationReport:
    total: int = 0
    killed: int = 0
    survived: int = 0
    timeout: int = 0
    suspicious: int = 0
    survivors: list[Mutant] = field(default_factory=list)

    @property
    def score(self) -> float:
        if self.total == 0:
            return 0.0
        return self.killed / self.total

    def summary(self) -> str:
        lines = [
            "Mutation Testing Report",
            "=" * 40,
            f"Total mutants:   {self.total}",
            f"Killed:          {self.killed}",
            f"Survived:        {self.survived}",
            f"Timeout:         {self.timeout}",
            f"Suspicious:      {self.suspicious}",
            f"Mutation score:  {self.score:.1%}",
        ]
        if self.survivors:
            lines.append("")
            lines.append("Surviving mutants (test gaps):")
            for m in self.survivors:
                lines.append(f"  [mutant {m.id}] {m.source_file}")
                lines.append(f"       {m.description}")
                lines.append(
                    "       -> Add a test that detects this mutation"
                )
        else:
            lines.append("\nAll mutants killed — test suite is thorough.")
        return "\n".join(lines)


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=".")


def parse_mutmut_results() -> MutationReport:
    """Parse ``mutmut results`` output into a structured report."""
    report = MutationReport()

    try:
        result = _run(["mutmut", "results"])
    except FileNotFoundError:
        print("mutmut not installed.  Install with: pip install mutmut")
        sys.exit(1)

    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        # mutmut results prints lines like "Killed 42" or "Survived 3"
        parts = line.split()
        if len(parts) >= 2 and parts[-1].isdigit():
            count = int(parts[-1])
            label = parts[0].lower()
            if "killed" in label:
                report.killed = count
            elif "survived" in label:
                report.survived = count
            elif "timeout" in label:
                report.timeout = count
            elif "suspicious" in label:
                report.suspicious = count

    report.total = (
        report.killed + report.survived + report.timeout + report.suspicious
    )

    # Collect details on survivors
    if report.survived > 0:
        try:
            ids_result = _run(["mutmut", "results", "--survived"])
            for line in ids_result.stdout.strip().splitlines():
                line = line.strip()
                if not line.isdigit():
                    continue
                mutant_id = int(line)
                detail = _run(["mutmut", "show", str(mutant_id)])
                report.survivors.append(Mutant(
                    id=mutant_id,
                    status="survived",
                    source_file="calculator.py",
                    description=detail.stdout.strip()[:200],
                ))
        except Exception:
            pass  # best-effort

    return report


def main() -> None:
    print("Analyzing mutation testing results ...\n")
    report = parse_mutmut_results()
    print(report.summary())

    if report.total == 0:
        print("\nNo mutmut results found.  Run mutmut first:")
        print("  mutmut run --paths-to-mutate=calculator.py --tests-dir=tests/")
        sys.exit(1)

    if report.score < 1.0:
        print(f"\nTarget:  100% mutation score")
        print(f"Current: {report.score:.1%}")
        print(f"Action:  Add tests for the {report.survived} surviving mutant(s)")
        sys.exit(1)
    else:
        print("\nMutation score target met!")


if __name__ == "__main__":
    main()
