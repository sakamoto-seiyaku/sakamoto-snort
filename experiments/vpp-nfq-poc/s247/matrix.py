#!/usr/bin/env python3
"""Sequential registered cells; stop the batch at the first HOLD."""
import argparse
import importlib.util
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent / "evidence"
spec = importlib.util.spec_from_file_location("s247_verifier", HERE / "verify.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
GROUPS = {
    "sync": [("sync", p, 4) for p in (1, 2, 4)],
    "credit": [("burst", 4, c) for c in (1, 2, 4)],
    "paired": [("burst", 1, 1), ("burst", 2, 2)],
    "tail": [("delay", 4, 4), ("stop", 4, 4)],
}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("group", choices=GROUPS)
    args = parser.parse_args()
    for pattern, pool, credit in GROUPS[args.group]:
        before = set(EVIDENCE.glob("s247-*"))
        subprocess.run(["python", str(HERE / "run.py"), pattern, "--pbuf", str(pool), "--credit", str(credit)], check=True)
        created = set(EVIDENCE.glob("s247-*")) - before
        assert len(created) == 1, created
        directory = created.pop()
        result = verifier.verify(directory)
        print(f"{directory.name}: {result['status']} joint_peak={result['pbuf_joint_peak']} overlap={result['input_output_overlap_peak']} errors={result['errors']}", flush=True)
        if result["status"] != "PASS":
            raise SystemExit(1)
