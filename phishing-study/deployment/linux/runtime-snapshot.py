#!/usr/bin/env python3
"""Root-only immutable before/after nft/resolver/source snapshot."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

from study.config import load
from study.deployment import (APP, ETC, check_network_snapshot, file_hash,
                              firewall_state_hash, secure_root_file, source_hash)


def denied_counter(rules):
    packets = 0
    for entry in rules.get('nftables', []):
        rule = entry.get('rule', {})
        expressions = rule.get('expr', [])
        if any('reject' in expression for expression in expressions):
            packets += sum(expression.get('counter', {}).get('packets', 0) for expression in expressions)
    return packets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=['normal', 'dns-blocked'])
    parser.add_argument('--nonce', required=True)
    parser.add_argument('--after', action='store_true')
    parser.add_argument('--normal-state-hash')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Only root can produce runtime policy evidence')
    manifest = json.loads(secure_root_file(f'{ETC}/deployment.json').read_text())
    rules = json.loads(subprocess.check_output(['nft', '-j', 'list', 'table', 'inet', 'study_egress']))
    baseline = json.loads(secure_root_file(f'{ETC}/firewall-baseline.json').read_text())
    normal_hash = args.normal_state_hash or firewall_state_hash(rules)
    if baseline['firewall_hash'] != file_hash(f'{ETC}/collector.nft') or baseline['normal_firewall_state_hash'] != normal_hash:
        raise ValueError('Firewall changed from the installed policy')
    topology = check_network_snapshot(manifest)
    config = load(secure_root_file(f'{ETC}/pilot.template.toml'))
    snapshot = {'schema_version': 1, 'nonce': args.nonce, 'phase': args.phase,
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'configuration_hash': manifest['configuration_hash'], 'pilot_config_hash': config.fingerprint,
                'source_hash': source_hash(APP), 'firewall_hash': file_hash(f'{ETC}/collector.nft'),
                'firewall_state_hash': firewall_state_hash(rules),
                'normal_firewall_state_hash': normal_hash,
                'resolver_hash': file_hash(f'{ETC}/resolver/resolv.conf'),
                'dns_blocked': args.phase == 'dns-blocked', 'firewall_ruleset': rules,
                **topology,
                'restrict_address_families': ['AF_UNIX', 'AF_INET', 'AF_NETLINK'],
                'service_unit_hash': file_hash(f'{APP}/deployment/linux/study-pilot.service'),
                'denied_counter': denied_counter(rules)}
    fixture = Path(f'{ETC}/fixture-source.json')
    if fixture.exists():
        snapshot['fixture_source_hash'] = json.loads(secure_root_file(fixture).read_text())['source_hash']
    if args.after:
        before = json.loads(secure_root_file(f'{ETC}/runtime-{args.phase}.json').read_text())
        if before['nonce'] != args.nonce:
            raise ValueError('Before/after nonce mismatch')
        snapshot['denied_counter_delta'] = snapshot['denied_counter'] - before['denied_counter']
    path = Path(f'{ETC}/runtime-{"after-" if args.after else ""}{args.phase}.json')
    path.write_text(json.dumps(snapshot, indent=2))
    os.chmod(path, 0o644)
    print(snapshot['normal_firewall_state_hash'])


if __name__ == '__main__':
    main()
