#!/usr/bin/env bash
# Apply only to an explicitly designated dedicated Ubuntu 24.04 VM.
set -euo pipefail
umask 077
source_root='' region='' resolver='' controls='' acknowledged=0
while (($#)); do
  case "$1" in
    --dedicated-vm) acknowledged=1; shift ;;
    --source) source_root=${2:?}; shift 2 ;;
    --region) region=${2:?}; shift 2 ;;
    --resolver) resolver=${2:?}; shift 2 ;;
    --controls) controls=${2:?}; shift 2 ;;
    *) echo 'Usage: install.sh --dedicated-vm --source PROJECT --region REGION --resolver IPV4 --controls JSON' >&2; exit 2 ;;
  esac
done
[[ $(id -u) == 0 && $acknowledged == 1 ]] || { echo 'Root and explicit --dedicated-vm acknowledgement are required.' >&2; exit 2; }
[[ -n $source_root && -n $region && -n $resolver && -f $controls ]] || { echo 'Source, accurate region, approved resolver and owned controls are required.' >&2; exit 2; }
# The supported distribution's root-owned identity file is required on the VM.
# shellcheck disable=SC1091
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'This installer supports dedicated Ubuntu 24.04 VMs only.' >&2; exit 2; }
systemd-detect-virt --vm --quiet || { echo 'A dedicated VM is required; containers, WSL and bare/shared hosts are refused.' >&2; exit 2; }
for target in /opt/phishing-study /etc/phishing-study /var/lib/phishing-study; do
  [[ ! -e $target ]] || { echo "Refusing existing deployment path: $target" >&2; exit 2; }
done
if getent passwd study >/dev/null || getent group study >/dev/null; then
  echo 'Refusing an existing study account or group.' >&2; exit 2
fi
[[ $(df --output=avail -B1 /var/lib | tail -n1) -ge 15000000000 ]] || { echo 'At least 15 GB free storage is required.' >&2; exit 2; }
source_root=$(realpath -- "$source_root")
[[ -f $source_root/pyproject.toml && -f $source_root/scripts/prepare-deployment.py ]] || exit 2
# Reject incomplete or invalid operator inputs before package/account changes.
python3 - "$source_root" "$region" "$resolver" "$controls" <<'PY'
import json,sys,tempfile
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from study.deployment import prepare
with tempfile.TemporaryDirectory() as temp:
    manifest=prepare(Path(temp)/'bundle',sys.argv[2],sys.argv[3],1000,json.loads(Path(sys.argv[4]).read_text()),root=Path(sys.argv[1]))
    if manifest['status'] != 'configured':
        raise SystemExit('Required deployment inputs missing: '+', '.join(manifest['required_inputs']))
PY
apt-get update
apt-get install -y python3-venv nftables iproute2 apparmor-utils
if nft list table inet study_egress >/dev/null 2>&1; then
  echo 'Refusing an existing study_egress table; unrelated firewall tables remain untouched.' >&2; exit 2
fi
useradd --system --user-group --home-dir /var/lib/phishing-study --shell /usr/sbin/nologin study
install -d -o root -g root -m 0755 /opt/phishing-study /opt/phishing-study/app
install -d -o study -g study -m 0700 /var/lib/phishing-study
# Copy only the reviewed source-file inventory, with no dataset, credentials or symlinks.
python3 - "$source_root" <<'PY'
from pathlib import Path
import shutil, sys
root=Path(sys.argv[1]); sys.path.insert(0,str(root))
from study.deployment import source_files
for source in source_files(root):
    if source.is_symlink() or not source.resolve().is_relative_to(root):
        raise SystemExit('Source inventory contains a symlink or escape')
    destination=Path('/opt/phishing-study/app')/source.relative_to(root)
    destination.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source,destination)
PY
python3 -m venv /opt/phishing-study/venv
/opt/phishing-study/venv/bin/python -m pip install --no-cache-dir '/opt/phishing-study/app[analysis]'
PLAYWRIGHT_BROWSERS_PATH=/opt/phishing-study/browsers /opt/phishing-study/venv/bin/python -m playwright install --with-deps chromium
uid=$(id -u study)
ip -j address show > /var/lib/phishing-study/install-addresses.json
ip -j route show > /var/lib/phishing-study/install-routes.json
/opt/phishing-study/venv/bin/python - "$region" "$resolver" "$uid" "$controls" <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,'/opt/phishing-study/app')
from study.deployment import parse_network_snapshot, prepare
addresses=json.loads(Path('/var/lib/phishing-study/install-addresses.json').read_text())
routes=json.loads(Path('/var/lib/phishing-study/install-routes.json').read_text())
topology=parse_network_snapshot(addresses,routes)
local,gateways=topology['local_ipv4'],topology['gateways_ipv4']
manifest=prepare('/etc/phishing-study',sys.argv[1],sys.argv[2],int(sys.argv[3]),json.loads(Path(sys.argv[4]).read_text()),local,gateways,root=Path('/opt/phishing-study/app'))
if manifest['status'] != 'configured':
    raise SystemExit('Deployment remains incomplete: '+', '.join(manifest['required_inputs']))
PY
# Ubuntu 24.04 may restrict unprivileged user namespaces through AppArmor.
# Permit userns for the pinned Chromium executables only; never alter global sysctls.
if aa-enabled --quiet; then
  /opt/phishing-study/venv/bin/python - <<'PY'
from pathlib import Path
from playwright.sync_api import sync_playwright
import os
os.environ['PLAYWRIGHT_BROWSERS_PATH']='/opt/phishing-study/browsers'
with sync_playwright() as p:
    executable=Path(p.chromium.executable_path).resolve()
    if not executable.is_relative_to('/opt/phishing-study/browsers'):
        raise SystemExit('Unexpected Chromium executable')
    # Playwright's default headless channel can use its matching shell executable.
    executables=sorted({executable,*Path('/opt/phishing-study/browsers').glob('chromium_headless_shell-*/chrome-headless-shell-linux*/chrome-headless-shell')})
    profiles=[]
    for index,binary in enumerate(executables):
        if binary.is_file():
            profiles.append(f'profile study-chromium-{index} "{binary}" flags=(unconfined) {{\n  userns,\n}}\n')
    Path('/etc/apparmor.d/phishing-study-chromium').write_text('\n'.join(profiles))
PY
  apparmor_parser -r /etc/apparmor.d/phishing-study-chromium
fi
chown -R root:root /opt/phishing-study /etc/phishing-study
# Installation uses umask 077. Grant study read/traverse access to immutable
# code and binaries while preserving executable bits and denying all writes.
chmod -R a+rX,go-w /opt/phishing-study
chmod -R go-w /etc/phishing-study
find /etc/phishing-study -type d -exec chmod 0755 {} +
find /etc/phishing-study -type f -exec chmod 0644 {} +
nft --check --file /etc/phishing-study/collector.nft
install -o root -g root -m 0644 /opt/phishing-study/app/deployment/linux/study-pilot.service /etc/systemd/system/study-pilot.service
install -o root -g root -m 0644 /opt/phishing-study/app/deployment/linux/study-egress.service /etc/systemd/system/study-egress.service
systemctl daemon-reload
systemctl enable --now study-egress.service
PYTHONPATH=/opt/phishing-study/app /opt/phishing-study/venv/bin/python - <<'PY'
import json,subprocess
from pathlib import Path
from study.deployment import file_hash,firewall_state_hash
rules=json.loads(subprocess.check_output(['nft','-j','list','table','inet','study_egress']))
baseline={'firewall_hash':file_hash('/etc/phishing-study/collector.nft'),
          'normal_firewall_state_hash':firewall_state_hash(rules)}
Path('/etc/phishing-study/firewall-baseline.json').write_text(json.dumps(baseline,indent=2))
PY
chmod 0644 /etc/phishing-study/firewall-baseline.json
# No automatic start or boot enable: fixture and deployment evidence gates come first.
/opt/phishing-study/venv/bin/python -m pip freeze > /etc/phishing-study/dependencies.txt
echo 'Installed. Isolation remains unverified. Run fixture validation, then verify.sh with owned controls.'
