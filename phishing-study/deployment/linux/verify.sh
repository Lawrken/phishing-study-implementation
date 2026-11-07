#!/usr/bin/env bash
# Test only explicitly supplied owned controls; no research candidate intake.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo 'Root is required for immutable policy snapshots and bounded service setup.' >&2; exit 2; }
systemctl is-active --quiet study-pilot.service && { echo 'Stop collection before verification.' >&2; exit 2; }
phase='' nonce='' output=''
while (($#)); do
  case "$1" in
    --phase) phase=${2:?}; shift 2 ;;
    --nonce) nonce=${2:?}; shift 2 ;;
    --output) output=${2:?}; shift 2 ;;
    *) echo 'Usage: verify.sh --phase normal|dns-blocked --nonce 32_HEX_DIGITS --output FRESH_DIRECTORY' >&2; exit 2 ;;
  esac
done
[[ $phase == normal || $phase == dns-blocked ]] || exit 2
[[ $nonce =~ ^[0-9a-f]{32}$ && -n $output && ! -e $output ]] || exit 2
output=$(realpath -m -- "$output")
[[ $output == /var/lib/phishing-study/verification/* ]] || { echo 'Verification output must be under /var/lib/phishing-study/verification/.' >&2; exit 2; }
export PYTHONPATH=/opt/phishing-study/app PYTHONDONTWRITEBYTECODE=1
export PLAYWRIGHT_BROWSERS_PATH=/opt/phishing-study/browsers
python=/opt/phishing-study/venv/bin/python
resolver=$("$python" -c 'import json; print(json.load(open("/etc/phishing-study/deployment.json"))["approved_resolver"])')
normal_hash=$("$python" -c 'import json,subprocess; from study.deployment import firewall_state_hash; print(firewall_state_hash(json.loads(subprocess.check_output(["nft","-j","list","table","inet","study_egress"]))))')
# Called by the EXIT trap, including failed verification phases.
# shellcheck disable=SC2317
restore_dns() {
  if [[ $phase == dns-blocked ]]; then
    # Restore only our dedicated DNS chain, even after a failed verifier.
    nft flush chain inet study_egress dns_allow
    nft add rule inet study_egress dns_allow ip daddr "$resolver" udp dport 53 accept
    nft add rule inet study_egress dns_allow ip daddr "$resolver" tcp dport 53 accept
  fi
}
trap restore_dns EXIT
if [[ $phase == dns-blocked ]]; then nft flush chain inet study_egress dns_allow; fi
"$python" /opt/phishing-study/app/deployment/linux/runtime-snapshot.py --phase "$phase" --nonce "$nonce" --normal-state-hash "$normal_hash"
install -d -o study -g study -m 0700 "$(dirname -- "$output")"
result=0
systemd-run --quiet --wait --pipe --collect --unit="study-verify-$phase" \
  --property=User=study --property=Group=study --property=CPUQuota=200% \
  --property=MemoryMax=4G --property=TasksMax=512 --property=UMask=0077 \
  --property=WorkingDirectory=/opt/phishing-study/app --property=ProtectSystem=strict \
  --property=ProtectHome=true --property=ReadWritePaths=/var/lib/phishing-study \
  --property=PrivateTmp=true --property=NoNewPrivileges=true --property=RestrictSUIDSGID=true \
  --property='RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK' \
  --property='BindReadOnlyPaths=/etc/phishing-study/resolver/resolv.conf:/etc/resolv.conf /etc/phishing-study/resolver/nsswitch.conf:/etc/nsswitch.conf' \
  --setenv=PYTHONPATH="$PYTHONPATH" --setenv=PYTHONDONTWRITEBYTECODE=1 \
  --setenv=PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" --setenv=HOME=/var/lib/phishing-study \
  "$python" /opt/phishing-study/app/scripts/verify-deployment.py \
  --deployment /etc/phishing-study/deployment.json --phase "$phase" --nonce "$nonce" --output "$output" || result=$?
"$python" /opt/phishing-study/app/deployment/linux/runtime-snapshot.py --phase "$phase" --nonce "$nonce" --normal-state-hash "$normal_hash" --after
# Freeze phase evidence away from the study-owned output directory before combining.
frozen="/etc/phishing-study/evidence/$nonce/$phase"
[[ ! -e $frozen ]] || { echo 'Preserve existing phase evidence; use a fresh nonce.' >&2; exit 2; }
install -d -o root -g root -m 0755 "$frozen"
if [[ -f $output/phase-report.json && ! -L $output/phase-report.json ]]; then
  install -o root -g root -m 0644 "$output/phase-report.json" "$frozen/phase-report.json"
fi
install -o root -g root -m 0644 "/etc/phishing-study/runtime-$phase.json" "$frozen/runtime-before.json"
install -o root -g root -m 0644 "/etc/phishing-study/runtime-after-$phase.json" "$frozen/runtime-after.json"
echo "Phase preserved at $frozen. Supply owned receiver/DNS logs before combine-verification.sh."
exit "$result"
