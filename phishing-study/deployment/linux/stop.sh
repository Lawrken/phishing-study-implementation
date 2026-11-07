#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Root is required to stop the study service.' >&2; exit 2; }
systemctl stop study-pilot.service
PYTHONPATH=/opt/phishing-study/app /opt/phishing-study/venv/bin/python /opt/phishing-study/app/deployment/linux/deactivate.py
systemctl show study-pilot.service --property=ActiveState --property=Result
echo 'Graceful stop requested. A completed run cannot be resumed; retain its artifacts.'
