#!/usr/bin/env python3
"""Dedicated-VM owned-control verifier. Incomplete prerequisites exit 2."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from study.deployment_checks import combine_evidence, root_readonly, run_phase


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--output", required=True, help="fresh phase directory or aggregate JSON path")
    parser.add_argument("--phase", choices=("normal", "dns-blocked"))
    parser.add_argument("--nonce", help="32 lowercase hexadecimal characters shared by both fresh phases")
    parser.add_argument("--combine", nargs=2, metavar=("NORMAL_REPORT", "BLOCKED_REPORT"))
    parser.add_argument("--receipt", help="root-owned matching owned-receiver/DNS/counter receipt")
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.combine:
        if args.phase or not args.receipt:
            parser.error("--combine requires --receipt and excludes --phase")
        paths = [args.deployment, *args.combine, args.receipt]
        if sys.platform != "linux" or os.geteuid() != 0 or not all(root_readonly(path) for path in paths):
            print(json.dumps({"status": "incomplete", "network_isolation_verified": False,
                              "reason": "aggregation requires root-owned immutable evidence on the dedicated Linux VM"}))
            return 2
        manifest, normal, blocked, receipt = [json.loads(Path(path).read_text()) for path in paths]
        report = combine_evidence(manifest, normal, blocked, receipt)
        output = Path(args.output)
        if output.exists():
            parser.error("aggregate output must be fresh")
        output.write_text(json.dumps(report, indent=2) + "\n")
        os.chmod(output, 0o644)
    else:
        if not args.phase or not args.nonce:
            parser.error("phase verification requires --phase and --nonce")
        report = asyncio.run(run_phase(args.deployment, args.output, args.phase, args.nonce))
    print(json.dumps(report, indent=2))
    return 0 if report["status"] in {"passed", "phase-passed"} else 2


if __name__ == "__main__":
    sys.exit(main())
