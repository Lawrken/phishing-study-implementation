#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo 'Run as root on the dedicated deployment VM.' >&2; exit 2; }
systemctl is-active --quiet study-pilot.service && { echo 'Stop collection before fixture validation.' >&2; exit 2; }
export PYTHONPATH=/opt/phishing-study/app
export PYTHONDONTWRITEBYTECODE=1
export PLAYWRIGHT_BROWSERS_PATH=/opt/phishing-study/browsers
python=/opt/phishing-study/venv/bin/python
output=/opt/phishing-study/fixture-validation-$(date -u +%Y%m%dT%H%M%SZ)
[[ ! -e $output ]] || exit 2
mkdir -m 0700 "$output"
"$python" -c 'from study.deployment import source_hash; print(source_hash("/opt/phishing-study/app"))' > "$output/source-before.txt"
# Root fixture mode has owned loopback fixtures and no Chromium sandbox. The live
# study UID remains blocked from loopback. This is a separate validation unit.
systemd-run --quiet --wait --pipe --collect --unit=study-fixture-suite \
  --property=CPUQuota=200% --property=MemoryMax=4G --property=TasksMax=512 \
  --property=PrivateNetwork=yes \
  --setenv=PYTHONPATH="$PYTHONPATH" --setenv=PYTHONDONTWRITEBYTECODE=1 --setenv=PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" \
  "$python" /opt/phishing-study/app/scripts/verify.py --require-browser --output "$output/suite"
systemd-run --quiet --wait --pipe --collect --unit=study-fixture-selftest \
  --property=CPUQuota=200% --property=MemoryMax=4G --property=TasksMax=512 \
  --property=PrivateNetwork=yes \
  --setenv=PYTHONPATH="$PYTHONPATH" --setenv=PYTHONDONTWRITEBYTECODE=1 --setenv=PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" \
  "$python" -m study selftest --output "$output/selftest"
install -o root -g root -m 0644 "$output/suite/test-report.json" /etc/phishing-study/fixture-test-report.json
install -o root -g root -m 0644 "$output/selftest/fixture-report.json" /etc/phishing-study/fixture-report.json
"$python" - "$output" <<'PY'
import json,sys
from pathlib import Path
from study.deployment import source_hash,file_hash
output=Path(sys.argv[1]); current=source_hash('/opt/phishing-study/app')
if current != (output/'source-before.txt').read_text().strip():
    raise SystemExit('Source changed during fixture validation')
provenance={'source_hash':current,'suite_sha256':file_hash('/etc/phishing-study/fixture-test-report.json'),
            'selftest_sha256':file_hash('/etc/phishing-study/fixture-report.json'),'artifact_directory':str(output)}
Path('/etc/phishing-study/fixture-source.json').write_text(json.dumps(provenance,indent=2))
PY
chmod 0644 /etc/phishing-study/fixture-source.json
echo "Fixture evidence preserved at $output. Live isolation still requires verification."
