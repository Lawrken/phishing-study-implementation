#!/usr/bin/env bash
# Only invoked by PrepareResearchVM.py inside its freshly created Ubuntu VM.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
umask 022
[[ $(id -u) == 0 && $(hostname) == phishing-study-ubuntu ]] || exit 2
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || exit 2
systemd-detect-virt --vm --quiet || exit 2
[[ ! -e /var/lib/phishing-study-setup-complete.json ]] || exit 2
apt-get update
apt-get install -y python3-venv nftables iproute2 apparmor-utils ca-certificates curl procps
for task_account in study-fixture study-public study-public-dns; do
    getent passwd "$task_account" >/dev/null || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin "$task_account"
done
install -d -m 0755 /opt/phishing-study-fixtures /var/lib/phishing-study-public
install -d -m 0755 /var/lib/phishing-study-public-originals-20261026-01
python3 -m venv /opt/phishing-study-fixtures/venv
task_python=/opt/phishing-study-fixtures/venv/bin/python
"$task_python" -m pip install --no-cache-dir -r /var/tmp/research-setup/requirements-guest.txt
export PLAYWRIGHT_BROWSERS_PATH=/opt/phishing-study-fixtures/browsers
# Installation downloads have a separate finite connection budget. This does
# not alter navigation, collection, browser-close or service-stop deadlines.
export PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT=120000
"$task_python" -m playwright install --with-deps chromium
"$task_python" - <<'PY'
import json,os,platform,subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright
if platform.python_version() != '3.12.3':
    raise SystemExit('Pinned guest Python 3.12.3 is required; preserve the setup log and review the image.')
with sync_playwright() as p:
    executable=Path(p.chromium.executable_path).resolve()
    if not executable.is_relative_to('/opt/phishing-study-fixtures/browsers'):
        raise SystemExit('Unexpected browser path')
    executables=sorted({executable,*Path('/opt/phishing-study-fixtures/browsers').glob('chromium_headless_shell-*/chrome-headless-shell-linux*/chrome-headless-shell')})
profiles=[]
for index,binary in enumerate(executables):
    if binary.is_file():
        profiles.append(f'profile research-chromium-{index} "{binary}" flags=(unconfined) {{\n  userns,\n}}\n')
profile=Path('/etc/apparmor.d/phishing-study-chromium')
profile.write_text('\n'.join(profiles))
if subprocess.run(['aa-enabled','--quiet']).returncode==0:
    subprocess.run(['apparmor_parser','-r',str(profile)],check=True)
PY
chown -R root:root /opt/phishing-study-fixtures
chmod -R a+rX,go-w /opt/phishing-study-fixtures
python3 - <<'PY'
import hashlib,json,shutil
from pathlib import Path
manifest=json.loads(Path('/var/tmp/research-setup/inputs-manifest.json').read_text())
target=Path('/var/lib/phishing-study-public-originals-20261026-01')
for name,entry in manifest['files'].items():
    p=Path('/var/tmp/research-setup')/name
    with p.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
    if actual!=entry['sha256'] or p.stat().st_size!=entry['bytes']:raise SystemExit('Changed input: '+name)
    q=target/name
    shutil.copyfile(p,q);q.chmod(0o444)
PY
"$task_python" -m pip freeze > /var/lib/research-setup-packages.txt
dpkg-query -W > /var/lib/research-setup-os-packages.txt
systemctl is-active --quiet systemd-resolved
[[ -z $(nft list ruleset) ]] || { echo 'Unexpected base firewall rules'; exit 2; }
python3 - <<'PY'
from pathlib import Path
import json,datetime
Path('/var/lib/phishing-study-setup-complete.json').write_text(json.dumps({
 'prepared_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'collection_activation':False,'deployment_verified':False,'dataset_visits':0,
 'origin':'fresh official Ubuntu cloud image; per-machine SSH identities'}))
PY
sync
echo 'SETUP COMPLETE. No dataset website was visited. Fresh deployment verification is still required.'
