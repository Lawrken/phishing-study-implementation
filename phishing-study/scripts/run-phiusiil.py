"""Run an offline external-data baseline; never visit the supplied URLs."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from study.phiusiil import SEED, run_dataset


def main():
    os.umask(0o077)
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        os.environ.setdefault(name, "2")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="fresh output directory")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    try:
        result = run_dataset(args.input, args.output, args.seed, args.audit_only)
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}))
        return 2
    print(json.dumps({key: result.get(key) for key in ("status", "rows", "retained_rows", "excluded_rows",
                                                     "elapsed_seconds", "endpoint_visits")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
