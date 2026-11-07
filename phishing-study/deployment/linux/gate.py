#!/usr/bin/env python3
"""Check immutable evidence immediately before finite pilot activation."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

from study.config import load
from study.deployment import (APP, ETC, check_evidence, file_hash, firewall_state_hash,
                              secure_root_file, source_hash, toml_config, check_network_snapshot)


def read(path):
    return json.loads(secure_root_file(path).read_text())


def fixture_gate(manifest):
    from study.deployment_checks import fixture_evidence
    suite = read(f'{ETC}/fixture-test-report.json')
    fixture = read(f'{ETC}/fixture-report.json')
    provenance = read(f'{ETC}/fixture-source.json')
    if not fixture_evidence(suite, fixture):
        raise ValueError('Strict deployment-machine fixture suite/selftest did not pass')
    if provenance.get('source_hash') != manifest['source_hash'] or provenance.get('suite_sha256') != file_hash(f'{ETC}/fixture-test-report.json') or provenance.get('selftest_sha256') != file_hash(f'{ETC}/fixture-report.json'):
        raise ValueError('Fixture evidence does not match the current source/reports')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', action='store_true')
    parser.add_argument('--activate', action='store_true')
    args = parser.parse_args()
    manifest = read(f'{ETC}/deployment.json')
    if manifest.get('verification_profile') == 'local-public-web-v1':
        raise ValueError('Public-web collection requires its source-bound public runtime gate; legacy activation is not applicable')
    if manifest.get('schema_version', 1) != 1 or manifest.get('verification_profile', 'external-controls-v1') != 'external-controls-v1':
        raise ValueError('Preview or unknown verification profile cannot activate research collection')
    evidence = read(f'{ETC}/deployment-evidence.json')
    config = load(secure_root_file(f'{ETC}/pilot.template.toml'))
    secure_root_file('/etc/systemd/system/study-pilot.service')
    if file_hash('/etc/systemd/system/study-pilot.service') != file_hash(f'{APP}/deployment/linux/study-pilot.service'):
        raise ValueError('Installed pilot unit changed')
    if file_hash(secure_root_file(f'{ETC}/resolver/nsswitch.conf')) != manifest['nsswitch_hash']:
        raise ValueError('Resolver NSS policy changed since preparation')
    fixture_gate(manifest)
    # An unchanged ruleset cannot block a newly assigned public VM address or
    # gateway unless it was part of the verified deny set. Check both as root
    # before activation and as study immediately before the collector starts.
    check_network_snapshot(manifest)
    if args.service:
        from study.deployment_checks import resource_limits
        if os.geteuid() != manifest['study_uid'] or not resource_limits().get('ok'):
            raise ValueError('Service UID or measured resource ceilings do not match deployment')
        if file_hash('/etc/resolv.conf') != file_hash(f'{ETC}/resolver/resolv.conf') or file_hash('/etc/nsswitch.conf') != manifest['nsswitch_hash']:
            raise ValueError('Service resolver bindings do not match deployment')
        activation = read(f'{ETC}/activation.json')
        generated = datetime.fromisoformat(activation['generated_at'])
        elapsed = (datetime.now(timezone.utc) - generated).total_seconds()
        if not 0 <= elapsed <= 120:
            raise ValueError('Fresh root activation check required')
        if activation.get('configuration_hash') != manifest['configuration_hash']:
            raise ValueError('Activation belongs to a different deployment configuration')
        rules_hash = activation['normal_firewall_state_hash']
        active = load(secure_root_file(f'{ETC}/pilot.toml'))
        config.network_isolation_verified = True
        if active.fingerprint != config.fingerprint:
            raise ValueError('Activated pilot does not match the verified template')
        config.network_isolation_verified = False
    else:
        if os.geteuid() != 0:
            raise ValueError('Root must inspect live nftables before activation')
        families = subprocess.check_output(['systemctl', 'show', 'study-pilot.service', '--property=RestrictAddressFamilies', '--value'], text=True).split()
        if set(families) != {'AF_UNIX', 'AF_INET', 'AF_NETLINK'}:
            raise ValueError('Installed service address-family policy changed')
        rules = json.loads(subprocess.check_output(['nft', '-j', 'list', 'table', 'inet', 'study_egress']))
        rules_hash = firewall_state_hash(rules)
    check_evidence(manifest, evidence, source_hash(APP), file_hash(secure_root_file(f'{ETC}/collector.nft')),
                   rules_hash, file_hash(secure_root_file(f'{ETC}/resolver/resolv.conf')), config)
    baseline = read(f'{ETC}/firewall-baseline.json')
    if baseline['normal_firewall_state_hash'] != rules_hash or baseline['firewall_hash'] != file_hash(f'{ETC}/collector.nft'):
        raise ValueError('Current firewall no longer matches the installed policy')
    if not args.service and args.activate:
        Path(f'{ETC}/activation.json').write_text(json.dumps({'generated_at': datetime.now(timezone.utc).isoformat(),
            'normal_firewall_state_hash': rules_hash, 'configuration_hash': manifest['configuration_hash']}, indent=2))
        os.chmod(f'{ETC}/activation.json', 0o644)
        config.network_isolation_verified = True
        Path(f'{ETC}/pilot.toml').write_text(toml_config(config))
        os.chmod(f'{ETC}/pilot.toml', 0o644)


if __name__ == '__main__':
    main()
