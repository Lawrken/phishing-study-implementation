#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 && $# == 1 ]] || { echo 'Usage: sudo bash recover.sh UNFINISHED_RUN_ID' >&2; exit 2; }
systemctl is-active --quiet study-pilot.service && { echo 'Stop the active service before recovery.' >&2; exit 2; }
export PYTHONPATH=/opt/phishing-study/app
export PYTHONDONTWRITEBYTECODE=1
export PLAYWRIGHT_BROWSERS_PATH=/opt/phishing-study/browsers
python=/opt/phishing-study/venv/bin/python
"$python" /opt/phishing-study/app/deployment/linux/deactivate.py
trap 'result=$?; if ((result)); then "$python" /opt/phishing-study/app/deployment/linux/deactivate.py; fi' EXIT
"$python" /opt/phishing-study/app/deployment/linux/gate.py
"$python" /opt/phishing-study/app/deployment/linux/prepare-pilot.py --resume "$1"
"$python" /opt/phishing-study/app/deployment/linux/gate.py --activate
systemctl start study-pilot.service
echo 'Only the unfinished original run is resumed; downtime counts toward its two-hour deadline.'
