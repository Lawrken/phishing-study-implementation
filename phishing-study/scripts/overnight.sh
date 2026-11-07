#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ $# -lt 1 ]]; then
  echo 'Usage: bash scripts/overnight.sh /path/to/reviewed-legitimate.csv [data-directory]' >&2
  exit 2
fi
study_data="${2:-data/overnight}"
mkdir -p "$study_data"
python -m study.unattended --config configs/overnight.toml --data "$study_data" \
  --legitimate-csv "$1" --source openphish 2>&1 | tee -a "$study_data/run.log"
