"""Run every scenario in every mode and write results/. Exit 1 on any mismatch."""
import csv
import sys
import tempfile
from pathlib import Path

from .expected import EXPECTED
from .latex import goals_table, scenarios_table
from .outcomes import MODES
from .scenarios import SCENARIOS

RESULTS = Path(__file__).resolve().parents[1] / "results"


def main() -> int:
    RESULTS.mkdir(exist_ok=True)
    results: dict[str, dict[str, str]] = {}
    mismatches = []
    for sid, (title, fn) in SCENARIOS.items():
        results[sid] = {}
        for mode in MODES:
            with tempfile.TemporaryDirectory() as tmp:
                outcome = fn(mode, Path(tmp))
            results[sid][mode] = outcome
            flag = "" if outcome == EXPECTED[sid][mode] else "   <-- MISMATCH"
            if flag:
                mismatches.append((sid, mode, outcome, EXPECTED[sid][mode]))
            print(f"{sid:4} {mode:10} {outcome:10}{flag}")
    with (RESULTS / "scenarios.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "title", "mode", "outcome", "expected"])
        for sid, (title, _) in SCENARIOS.items():
            for mode in MODES:
                w.writerow([sid, title, mode, results[sid][mode], EXPECTED[sid][mode]])
    titles = {sid: title for sid, (title, _) in SCENARIOS.items()}
    (RESULTS / "scenarios.tex").write_text(scenarios_table(results, titles))
    (RESULTS / "goals.tex").write_text(goals_table(results))
    for sid, mode, got, want in mismatches:
        print(f"MISMATCH {sid} {mode}: got {got}, expected {want}", file=sys.stderr)
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
