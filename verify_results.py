#!/usr/bin/env python3
"""Audit archived exhaustive-validation results and optional deterministic replays.

Run: python verify_results.py [--rerun-dir rerun]
Only standard-library modules are required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FILES = {
    "replay_results.json": (0, (0, 7)),
    "real_low2.json": (0, (0, 1)),
    "real_high2.json": (0, (6, 7)),
    "real_col1.json": (1, (0, 7)),
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def check(cond: bool, what: str) -> None:
    if not cond:
        raise AssertionError(what)


def stable(obj):
    """Ignore wall-clock time only; all cryptographic/results fields must match."""
    if isinstance(obj, dict):
        return {k: stable(v) for k, v in obj.items() if k != "seconds"}
    if isinstance(obj, list):
        return [stable(v) for v in obj]
    return obj


def validate_archive(result_dir: Path) -> None:
    reference_hash = hashlib.sha256((ROOT / "kalyna_reference.py").read_bytes()).hexdigest()
    real_total = real_wrong = real_correct = 0
    for filename, (column, byte_positions) in FILES.items():
        path = result_dir / filename
        check(path.is_file(), f"Missing {path}")
        data = load(path)
        check(data.get("model_statement") == "Toy model and actual Kalyna are DIFFERENT experiments", filename)
        r = data["real"]
        check(r["trials"] == 4 and r["tested_per_trial"] == 65536, f"Unexpected real trial count in {filename}")
        check(r["total_tested"] == 262144, f"Wrong total in {filename}")
        check(r["incorrect_total_tested"] == 262140, f"Wrong incorrect total in {filename}")
        check(r["correct_retained"] == 4, f"Correct key not retained in {filename}")
        check(r["wrong_survived_first"] == r["wrong_survived_both"] == 0, f"Wrong candidate in {filename}")
        check(len(r["per_trial"]) == 4, f"Missing trial records in {filename}")
        for trial in r["per_trial"]:
            check(trial["reference_sha256"] == reference_hash, f"Reference implementation does not match {filename}")
            check(trial["column"] == column and tuple(trial["positions"]) == byte_positions,
                  f"Slice mismatch in {filename}")
            check(trial["tested"] == 65536 and trial["incorrect_tested"] == 65535,
                  f"Incomplete key enumeration in {filename}")
            check(trial["correct_retained"] and trial["incorrect_survived_both"] == 0,
                  f"Candidate retention failure in {filename}")
        real_total += r["total_tested"]
        real_wrong += r["incorrect_total_tested"]
        real_correct += r["correct_retained"]
        print(f"PASS {filename}: column {column}, bytes {byte_positions}, 4 x 65,536 candidates")

    check((real_total, real_wrong, real_correct) == (1048576, 1048560, 16), "Real totals mismatch")
    toy = load(result_dir / "replay_results.json")["toy"]
    check(toy["trials"] == 256 and toy["keys_tested"] == 16777216, "Toy total mismatch")
    check(toy["correct_retained"] == 256 and toy["trials_with_nonunique_survivors"] == 256,
          "Toy correct-key or nonunique-trial mismatch")
    check(toy["incorrect_survived_first"] == 1974 and toy["incorrect_survived_both"] == 772,
          "Toy wrong-key survivor totals mismatch")
    check(len(toy["per_trial"]) == 256, "Missing toy per-trial records")
    check(sum(t["wrong_first"] for t in toy["per_trial"]) == 1974, "Toy first totals inconsistent")
    check(sum(t["wrong_both"] for t in toy["per_trial"]) == 772, "Toy both totals inconsistent")
    print("PASS 16-bit toy: 256 x 65,536 candidates; 772 wrong survivors after two multisets")
    print("PASS actual Kalyna: 16 x 65,536 candidates; 0 wrong survivors in tested slices")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rerun-dir", type=Path, help="Compare four freshly rerun JSON files to archived results")
    args = parser.parse_args()
    baseline = ROOT / "results"
    validate_archive(baseline)
    if args.rerun_dir:
        fresh = args.rerun_dir.resolve()
        validate_archive(fresh)
        for filename in FILES:
            check(stable(load(baseline / filename)) == stable(load(fresh / filename)),
                  f"Deterministic replay mismatch: {filename}")
        print("PASS all replayed results match the archived results (excluding elapsed seconds)")


if __name__ == "__main__":
    main()
