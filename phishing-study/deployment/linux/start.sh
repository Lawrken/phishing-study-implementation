#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo 'Root is required to validate evidence and start the study service.' >&2; exit 2; }
systemctl is-active --quiet study-pilot.service && { echo 'Pilot is already active.' >&2; exit 2; }
export PYTHONPATH=/opt/phishing-study/app
export PYTHONDONTWRITEBYTECODE=1
export PLAYWRIGHT_BROWSERS_PATH=/opt/phishing-study/browsers
python=/opt/phishing-study/venv/bin/python
"$python" /opt/phishing-study/app/deployment/linux/deactivate.py
trap 'result=$?; if ((result)); then "$python" /opt/phishing-study/app/deployment/linux/deactivate.py; fi' EXIT
# Check isolation before ingesting; this command makes no endpoint requests.
"$python" /opt/phishing-study/app/deployment/linux/gate.py
"$python" /opt/phishing-study/app/deployment/linux/prepare-pilot.py "$@"
# Check current policy again after ingestion, immediately before service start.
"$python" /opt/phishing-study/app/deployment/linux/gate.py --activate
systemctl start study-pilot.service
systemctl show study-pilot.service --property=ActiveState --property=MainPID
