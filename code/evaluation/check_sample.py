"""Fail if the auditor does not reproduce dataset/sample_output.csv."""

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import ROOT, evaluate_requests, load_world


def _canon(steps):
    return [
        (
            step["step_no"],
            step["phase"],
            step["system_id"],
            step["resource_id"],
            step["operation"],
            step["state"],
            step["evidence_id"],
        )
        for step in steps
    ]


def main():
    world = load_world()
    sample_ids = [
        row["case_id"]
        for row in csv.DictReader((ROOT / "dataset" / "sample_deletion_requests.csv").open(encoding="utf-8"))
    ]
    wanted = {row["case_id"]: row for row in world[3] if row["case_id"] in set(sample_ids)}
    # Sample requests are the contract. Use those rows so the text and timestamps match.
    sample_cases = list(csv.DictReader((ROOT / "dataset" / "sample_deletion_requests.csv").open(encoding="utf-8")))
    got = {row["case_id"]: row for row in evaluate_requests(sample_cases, world)}
    expected = {
        row["case_id"]: row
        for row in csv.DictReader((ROOT / "dataset" / "sample_output.csv").open(encoding="utf-8"))
    }
    mismatches = 0
    for case_id in sample_ids:
        exp = expected[case_id]
        actual = got[case_id]
        exp_steps = json.loads(exp["steps_json"])
        if actual["deletion_status"] != exp["deletion_status"] or _canon(actual["steps_json"]) != _canon(exp_steps):
            mismatches += 1
            if mismatches <= 8:
                print(f"\n{case_id} got {actual['deletion_status']} expected {exp['deletion_status']}")
                print(" expected", _canon(exp_steps))
                print(" got     ", _canon(actual["steps_json"]))
    print(f"\n{mismatches} mismatched sample cases out of {len(sample_ids)}")
    if mismatches:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
