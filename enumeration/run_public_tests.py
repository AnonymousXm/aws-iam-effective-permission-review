#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from effective_permissions import evaluate


BASE = Path(__file__).resolve().parents[1]


def run_fixture(fixture_path: Path) -> list[dict]:
    tests = json.loads(fixture_path.read_text(encoding="utf-8"))["tests"]
    results = []

    for test in tests:
        decision = evaluate(test)
        actual = "allowed" if decision.allowed else "denied"
        expected = test["expected"]

        results.append(
            {
                "id": test["id"],
                "expected": expected,
                "actual": actual,
                "passed": actual == expected,
                "reason": decision.reason,
            }
        )

    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run an IAM effective-permission fixture."
    )
    parser.add_argument(
        "fixture",
        type=Path,
        help="Path to a JSON fixture containing a 'tests' array",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=BASE / "artifacts" / "test-results.json",
        help="Output JSON path",
    )
    args = parser.parse_args()

    fixture = args.fixture.resolve()
    output = args.output.resolve()

    if not fixture.is_file():
        print(f"Fixture not found: {fixture}")
        return 2

    results = run_fixture(fixture)
    failed = [result for result in results if not result["passed"]]

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"results": results}, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"passed={len(results) - len(failed)} failed={len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
