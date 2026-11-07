#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $(id -u) == 0 && $# == 2 ]] || { echo 'Usage: sudo bash combine-verification.sh NONCE ROOT_OWNED_RECEIVER_RECEIPT_JSON' >&2; exit 2; }
nonce=$1 receipt=$2
[[ $nonce =~ ^[0-9a-f]{32}$ ]] || exit 2
systemctl is-active --quiet study-pilot.service && { echo 'Stop collection before combining evidence.' >&2; exit 2; }
export PYTHONPATH=/opt/phishing-study/app PYTHONDONTWRITEBYTECODE=1
python=/opt/phishing-study/venv/bin/python
"$python" - "$receipt" "$nonce" <<'PY'
import json,os,subprocess,sys
from pathlib import Path
from study.deployment import secure_root_file,firewall_state_hash
receipt=json.loads(secure_root_file(sys.argv[1]).read_text()); nonce=sys.argv[2]
if receipt.get('nonce') != nonce: raise SystemExit('Receiver receipt nonce mismatch')
normal=json.loads(secure_root_file(f'/etc/phishing-study/evidence/{nonce}/normal/phase-report.json').read_text())
for key in ('configuration_hash','pilot_config_hash','source_hash','firewall_hash','resolver_hash'):
    receipt[key]=normal[key]
for phase in ('normal','dns-blocked'):
    snapshot=json.loads(secure_root_file(f'/etc/phishing-study/evidence/{nonce}/{phase}/runtime-after.json').read_text())
    receipt.setdefault(phase,{})['denied_counter_delta']=snapshot['denied_counter_delta']
rules=json.loads(subprocess.check_output(['nft','-j','list','table','inet','study_egress']))
receipt['restored_firewall_state_hash']=firewall_state_hash(rules)
path=Path('/etc/phishing-study/receiver-receipt.json')
path.write_text(json.dumps(receipt,indent=2)); os.chmod(path,0o644)
PY
"$python" /opt/phishing-study/app/scripts/verify-deployment.py \
  --deployment /etc/phishing-study/deployment.json \
  --combine "/etc/phishing-study/evidence/$nonce/normal/phase-report.json" "/etc/phishing-study/evidence/$nonce/dns-blocked/phase-report.json" \
  --receipt /etc/phishing-study/receiver-receipt.json --output /etc/phishing-study/deployment-evidence.json
chmod 0644 /etc/phishing-study/deployment-evidence.json
