#!/usr/bin/env bash
# Called inside the prepared image with --network none and /workspace mounted.
set -euo pipefail
umask 077
output="${1:-validation/linux-$(date -u +%Y%m%dT%H%M%SZ)}"
if [[ -e "$output/test-report.json" || -e "$output/selftest" ]]; then
  echo 'Use a fresh validation output directory.' >&2
  exit 2
fi
mkdir -p -- "$output"
uname -a > "$output/platform.txt"
python -m pip freeze > "$output/dependencies.txt"
python scripts/verify.py --require-browser --output="$output" | tee "$output/verify-console.txt"
python -m study selftest --output="$output/selftest" | tee "$output/selftest-console.txt"
# This is a prerequisite report, not a public visit or isolation attestation.
set +e
python -m study --config configs/pilot.toml doctor --output "$output/doctor-live.json" | tee "$output/doctor-live-console.txt"
doctor_status=${PIPESTATUS[0]}
set -e
if [[ "$doctor_status" != 0 && "$doctor_status" != 2 ]]; then
  exit "$doctor_status"
fi
echo "Linux fixture validation completed: $output"
