"""Source-bound approval for a finite public-web collection service.

This profile combines the installed policy's disconnected kernel controls with
owned Internet positive/blackout/restoration measurements. It does not claim
externally operated receiver logs, authoritative DNS queries or current labels.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from .config import Config, load

PROFILE = 'local-public-web-v1'
ASSURANCE = 'local-kernel-plus-owned-internet-v1'
OBSERVATION_PROFILE = 'local-dataset-observation-v1'
OBSERVATION_ASSURANCE = 'local-kernel-with-dataset-outcomes-v1'
SCHEMA_VERSION = 3
NFT_TABLE = 'study_public_egress'
LISTEN = '127.0.0.153'
UPSTREAM = '127.0.0.53'
OWNED_URL = 'https://d-tx-t.vercel.app/'
RESOURCES = {'memory_max_bytes': 2147483648, 'cpu_quota_percent': 200,
             'tasks_max': 512, 'workers': 1, 'initial_free_disk_bytes': 15000000000}
DNS_RESOURCES = {'memory_max_bytes': 134217728, 'cpu_quota_percent': 20,
                 'tasks_max': 32, 'max_log_bytes': 67108864}
RUNTIME_PINS = {'python': '3.12.3', 'playwright': '1.63.0', 'tldextract': '5.4.0',
                'dnspython': '2.9.0', 'pyarrow': '26.0.0'}
CHROMIUM_VERSION = '153.0.8010.12'
ARTIFACTS = frozenset(('pilot.template.toml', 'resolver/resolv.conf',
    'resolver/nsswitch.conf', 'resolver/config.json', 'collector.service',
    'resolver.service', 'collector.nft'))
IDENTITY_KEYS = ('schema_version', 'verification_profile', 'assurance_model',
    'configuration_hash', 'source_hash', 'pilot_config_hash', 'service_hash',
    'resolver_config_hash', 'resolver_code_hash', 'nsswitch_hash', 'firewall_hash',
    'intake_manifest_hash', 'upstream_config_hash')
KERNEL_CASES = frozenset(('private_ipv4_tcp', 'public_shaped_nonweb_tcp',
    'ipv6_tcp', 'alternate_dns_tcp', 'alternate_dns_udp', 'nonweb_udp_443',
    'redirect', 'resolver_web_tcp'))
KERNEL_CHECKS = frozenset(('namespace_disconnected', 'normal_http_200',
    'restored_http_200', 'normal_dns_udp', 'normal_dns_tcp', 'restored_dns_udp',
    'restored_dns_tcp', 'native_dns_blackout', 'blackout_zero_dns_queries',
    'firewall_restored', 'resolver_stub_allowed', 'resolver_replies_allowed'))
CONNECTED_CHECKS = frozenset(('normal_logged_owned_query', 'restored_logged_owned_query',
    'blackout_zero_resolver_queries', 'dns_policy_restored', 'receivers_stopped',
    'resolver_service_exit_zero', 'resolver_logged_clean_shutdown',
    'accounts_idle', 'outer_firewall_restored', 'outer_dns_nss_hosts_unchanged',
    'source_unchanged', 'generated_service_stop_clean'))
SERVICE_STOP_CHECKS = frozenset(('operation_cancelled', 'contexts_closed', 'guard_clean',
    'no_fixture_resource_hits', 'browser_lifecycle_clean', 'owned_browser_gone',
    'renderer_sandbox', 'signal_received'))
CLEANUP_CHECKS = frozenset(('accounts_idle', 'listeners_stopped', 'outer_firewall_restored',
    'outer_dns_nss_hosts_unchanged', 'source_unchanged'))
HASH = re.compile(r'^[a-f0-9]{64}$')


def _hash(value, label):
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        raise ValueError('actual SHA-256 required: ' + label)
    return value


def _uid(value, label, optional=False):
    if optional and value is None:
        return None
    if type(value) is not int or not 100 <= value < 2 ** 31:
        raise ValueError('dedicated non-root UID required: ' + label)
    return value


def _topology(values):
    if not isinstance(values, (list, tuple)) or any(not isinstance(v, str) for v in values):
        raise ValueError('literal IPv4 topology list required')
    return sorted({str(ipaddress.IPv4Address(v)) for v in values})


def collection_config(region, max_attempts=400, usable_per_class=50, completion=None, continuation=None):
    if not isinstance(region, str) or region != region.strip() or region.lower() in {'', 'unknown', 'unspecified', 'todo'}:
        raise ValueError('operator-confirmed physical collection region required')
    if completion is not None:
        from .phiusiil_completion import validate_completion
        from .campaign_continuation import remaining_phishing_target
        validate_completion(completion)
        if type(max_attempts) is not int or not 1 <= max_attempts <= 800:
            raise ValueError('completion_attempt_budget_must_be_between_1_and_800')
        target = remaining_phishing_target(continuation, max_attempts)
        if type(max_attempts) is not int or not 1 <= max_attempts <= 800 or type(usable_per_class) is not int or usable_per_class != target:
            raise ValueError('completion_requires_remaining_phishing_quota_and_original_800_budget')
        config = Config(workers=1, max_hours=2, max_attempts=max_attempts, usable_per_class=target,
                        route_id='direct-ipv4', region=region)
        config.validate()
        return config
    if type(max_attempts) is not int or not 1 <= max_attempts <= 400:
        raise ValueError('attempt_budget_must_be_between_1_and_400')
    if type(usable_per_class) is not int or usable_per_class not in (50, 75):
        raise ValueError('authorized_class_target_must_be_50_or_75')
    config = Config(workers=1, max_hours=2, max_attempts=max_attempts, usable_per_class=usable_per_class,
                    route_id='direct-ipv4', region=region)
    config.validate()
    return config


def allowed_public_egress(address, protocol, port, resolver=LISTEN,
                          local_ipv4=(), gateways_ipv4=()):
    """Pure specification of collector rules; IPv6 is always denied."""
    from .deployment import public_ipv4
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return False
    if ip.version != 4:
        return False
    if str(ip) == resolver and protocol in {'tcp', 'udp'} and port == 53:
        return True
    return (public_ipv4(str(ip)) and str(ip) not in {*local_ipv4, *gateways_ipv4}
            and protocol == 'tcp' and port in {80, 443})


def render_firewall(uid, dnsuid, local_ipv4=(), gateways_ipv4=()):
    from .deployment import DENIED_IPV4
    _uid(uid, 'collector')
    _uid(dnsuid, 'resolver')
    if uid == dnsuid:
        raise ValueError('collector and resolver identities must differ')
    blocked = ', '.join([*DENIED_IPV4, *_topology(local_ipv4), *_topology(gateways_ipv4)])
    return f'''# Apply only to the dedicated collection VM and these exact account IDs.
table inet {NFT_TABLE} {{
    set denied_v4 {{ type ipv4_addr; flags interval; auto-merge; elements = {{ {blocked} }}; }}
    chain dns_allow {{
        ip daddr {LISTEN} udp dport 53 counter accept
        ip daddr {LISTEN} tcp dport 53 counter accept
    }}
    chain workload {{
        meta nfproto ipv6 counter reject
        jump dns_allow
        ip daddr @denied_v4 counter reject
        meta l4proto tcp tcp dport {{ 80, 443 }} counter accept
        counter reject
    }}
    chain resolver {{
        meta nfproto ipv6 counter reject
        ip daddr {UPSTREAM} udp dport 53 counter accept
        ip daddr {UPSTREAM} tcp dport 53 counter accept
        ip saddr {LISTEN} ip daddr 127.0.0.0/8 ct state established udp sport 53 counter accept
        ip saddr {LISTEN} ip daddr 127.0.0.0/8 ct state established tcp sport 53 counter accept
        counter reject
    }}
    chain output {{
        type filter hook output priority -10; policy accept;
        meta skuid {uid} jump workload
        meta skuid {dnsuid} jump resolver
    }}
}}
'''


def service_templates(root, bundle, uid, dnsuid):
    env = 'Environment=' + json.dumps('PYTHONPATH=' + str(root)) + '\n'
    common = ('Type=exec\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=true\n'
        'ProtectHome=true\nProtectSystem=strict\nRestart=no\n' + env)
    collector = ('[Unit]\nDescription=Finite source-labelled public-web pilot\n'
        'Requires=@@DNS_UNIT@@\nBindsTo=@@DNS_UNIT@@\nAfter=@@DNS_UNIT@@\n\n[Service]\n' + common
        + 'User=' + str(uid if uid is not None else '@@STUDY_UID@@') + '\n'
        'CPUQuota=200%\nMemoryMax=2G\nMemorySwapMax=0\nTasksMax=512\n'
        'KillMode=mixed\n'
        'TimeoutStopSec=60\nRuntimeMaxSec=7260\n'
        'RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\n'
        'BindReadOnlyPaths=' + str(bundle / 'resolver/resolv.conf') + ':/etc/resolv.conf '
        + str(bundle / 'resolver/nsswitch.conf') + ':/etc/nsswitch.conf\n'
        'ExecStart=@@PYTHON@@ @@RUNNER@@ --bundle @@BUNDLE@@ --output @@OUTPUT@@\n')
    resolver = ('[Service]\n' + common
        + 'User=' + str(dnsuid if dnsuid is not None else '@@RESOLVER_UID@@') + '\n'
        'CPUQuota=20%\nMemoryMax=128M\nMemorySwapMax=0\nTasksMax=32\n'
        'KillMode=control-group\n'
        'TimeoutStopSec=10\nRuntimeMaxSec=7260\n'
        'RestrictAddressFamilies=AF_UNIX AF_INET\n'
        'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n'
        'ExecStart=@@PYTHON@@ -m study.logging_resolver --mode public-web --listen ' + LISTEN
        + ' --upstream ' + UPSTREAM + ' --max-log-bytes 67108864'
        ' --log @@DNS_LOG@@ --ready @@DNS_READY@@ --phase-file @@PHASE_FILE@@\n')
    return collector, resolver


def prepare_public_web(output, region, uid, resolver_uid, root,
                       local_ipv4=(), gateways_ipv4=(), intake_manifest_hash=None,
                       upstream_config_hash=None, max_attempts=400, usable_per_class=50, continuation=None,
                       completion=None, live_view=False, dataset_observation=False):
    from .deployment import NSSWITCH, digest_json, file_hash, manifest_hash, source_files, source_hash, toml_config
    output, root = Path(output), Path(root).resolve()
    if output.exists():
        raise ValueError('fresh output required; preserve existing evidence')
    _uid(uid, 'collector', optional=True)
    _uid(resolver_uid, 'resolver', optional=True)
    if uid is not None and uid == resolver_uid:
        raise ValueError('collector and resolver identities must differ')
    config = collection_config(region, max_attempts, usable_per_class, completion, continuation)
    if type(live_view) is not bool:
        raise ValueError('live_view_must_be_boolean')
    if type(dataset_observation) is not bool or dataset_observation and completion:
        raise ValueError('observation_requires_explicit_boolean_and_standard_intake')
    from .campaign_continuation import validate_continuation
    validate_continuation(continuation,max_attempts,attempt_limit=800 if completion else 400)
    local, gateways = _topology(local_ipv4), _topology(gateways_ipv4)
    missing = [name for name, value in (('study_uid', uid), ('resolver_uid', resolver_uid),
        ('intake_manifest_hash', intake_manifest_hash), ('upstream_config_hash', upstream_config_hash)) if value is None]
    for name, value in (('intake_manifest_hash', intake_manifest_hash), ('upstream_config_hash', upstream_config_hash)):
        if value is not None:
            _hash(value, name)
    resolver = {'mode': 'public-web', 'listen': LISTEN, 'upstream': UPSTREAM,
                'uid': resolver_uid, 'port': 53, 'transports': ['udp', 'tcp'],
                'max_log_bytes': DNS_RESOURCES['max_log_bytes']}
    collector, dns_service = service_templates(root, output.resolve(), uid, resolver_uid)
    content = {'pilot.template.toml': toml_config(config),
        'resolver/resolv.conf': 'nameserver ' + LISTEN + '\noptions timeout:1 attempts:1\n',
        'resolver/nsswitch.conf': NSSWITCH,
        'resolver/config.json': json.dumps(resolver, indent=2) + '\n',
        'collector.service': collector, 'resolver.service': dns_service,
        'collector.nft': render_firewall(uid, resolver_uid, local, gateways) if uid is not None and resolver_uid is not None
            else '# INCOMPLETE: dedicated account IDs required\n'}
    hashes = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in content.items()}
    manifest = {'schema_version': SCHEMA_VERSION,
        'verification_profile': OBSERVATION_PROFILE if dataset_observation else PROFILE,
        'assurance_model': OBSERVATION_ASSURANCE if dataset_observation else ASSURANCE, 'dedicated_vm': True,
        'status': 'incomplete' if missing else 'configured', 'required_inputs': sorted(missing),
        'activation_allowed': False, 'network_isolation_verified': False,
        'region': region, 'route_id': 'direct-ipv4', 'region_confirmed': True,
        'max_attempts': max_attempts,
        'live_view_enabled': live_view,
        'usable_per_class': usable_per_class,
        'continuation': continuation,
        'source_root': str(root), 'study_uid': uid, 'resolver': resolver,
        'nft_table': NFT_TABLE, 'owned_controls': {} if dataset_observation else {'https_url': OWNED_URL},
        'local_ipv4': local, 'gateways_ipv4': gateways, 'resources': dict(RESOURCES),
        'dns_resources': dict(DNS_RESOURCES), 'intake_profile': 'phiusiil-revisit-v1',
        'runtime_pins': dict(RUNTIME_PINS), 'chromium_version': CHROMIUM_VERSION,
        'intake_manifest_hash': intake_manifest_hash, 'upstream_config_hash': upstream_config_hash,
        'source_hash': source_hash(root), 'pilot_config_hash': config.fingerprint,
        'artifact_hashes': hashes,
        'service_hash': digest_json({name: hashes[name] for name in ('collector.service', 'resolver.service')}),
        'resolver_config_hash': hashes['resolver/config.json'],
        'resolver_code_hash': file_hash(root / 'study/logging_resolver.py'),
        'nsswitch_hash': hashes['resolver/nsswitch.conf'], 'resolver_hash': hashes['resolver/resolv.conf'],
        'firewall_hash': hashes['collector.nft'],
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'claims': {'authoritative_dns_verified': False, 'dnssec_verified': False,
            'external_receiver_logs_verified': False, 'labels_currently_verified': False}}
    if completion is not None:
        from .phiusiil_completion import PROFILE as COMPLETION_PROFILE
        manifest.update(completion=completion, intake_profile=COMPLETION_PROFILE)
    manifest['configuration_hash'] = manifest_hash(manifest)
    output.mkdir(parents=True)
    (output / 'resolver').mkdir()
    for name, value in content.items():
        (output / name).write_text(value, encoding='utf-8', newline='\n')
    (output / 'deployment.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    (output / 'source-hashes.json').write_text(json.dumps({p.relative_to(root).as_posix(): file_hash(p)
        for p in source_files(root)}, indent=2) + '\n', encoding='utf-8')
    return manifest


def validate_public_manifest(manifest, require_ready=True):
    from .deployment import digest_json, manifest_hash
    if (not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int
            or manifest['schema_version'] != SCHEMA_VERSION
            or (manifest.get('verification_profile'), manifest.get('assurance_model')) not in {
                (PROFILE, ASSURANCE), (OBSERVATION_PROFILE, OBSERVATION_ASSURANCE)}):
        raise ValueError('public-web schema/profile/assurance identity required')
    if manifest.get('configuration_hash') != manifest_hash(manifest):
        raise ValueError('public-web manifest identity changed')
    if type(manifest.get('live_view_enabled', False)) is not bool:
        raise ValueError('live_view_must_be_boolean')
    config = collection_config(manifest.get('region'), manifest.get('max_attempts', 400),
                               manifest.get('usable_per_class', 50), manifest.get('completion'), manifest.get('continuation'))
    from .campaign_continuation import validate_continuation
    validate_continuation(manifest.get('continuation'),config.max_attempts,
                          attempt_limit=800 if manifest.get('completion') else 400)
    if manifest.get('region_confirmed') is not True or manifest.get('pilot_config_hash') != config.fingerprint:
        raise ValueError('confirmed region and finite passive configuration required')
    if manifest.get('dedicated_vm') is not True or manifest.get('route_id') != 'direct-ipv4':
        raise ValueError('dedicated direct IPv4 deployment required')
    if manifest.get('network_isolation_verified') is not False or manifest.get('activation_allowed') is not False:
        raise ValueError('prepared template cannot be manually activated')
    if (manifest.get('resources') != RESOURCES or manifest.get('dns_resources') != DNS_RESOURCES
            or any(type(value) is not int for value in manifest['resources'].values())
            or any(type(value) is not int for value in manifest['dns_resources'].values())):
        raise ValueError('resource limits changed')
    expected_intake = 'phiusiil-phishing-completion-v1' if manifest.get('completion') else 'phiusiil-revisit-v1'
    if manifest.get('intake_profile') != expected_intake or manifest.get('nft_table') != NFT_TABLE:
        raise ValueError('intake or firewall profile changed')
    if manifest.get('runtime_pins') != RUNTIME_PINS or manifest.get('chromium_version') != CHROMIUM_VERSION:
        raise ValueError('pinned runtime or Chromium version changed')
    resolver = manifest.get('resolver')
    if not isinstance(resolver, dict) or any(resolver.get(k) != v for k, v in
            (('mode', 'public-web'), ('listen', LISTEN), ('upstream', UPSTREAM), ('port', 53),
             ('transports', ['udp', 'tcp']), ('max_log_bytes', DNS_RESOURCES['max_log_bytes']))):
        raise ValueError('public-web DNS configuration changed')
    if type(resolver.get('port')) is not int or type(resolver.get('max_log_bytes')) is not int:
        raise ValueError('typed DNS limits required')
    if set(manifest.get('artifact_hashes', {})) != ARTIFACTS:
        raise ValueError('generated artifact inventory incomplete')
    hashes = manifest['artifact_hashes']
    for name, value in hashes.items():
        _hash(value, name)
    expected = {'resolver_config_hash': hashes['resolver/config.json'], 'resolver_hash': hashes['resolver/resolv.conf'],
        'nsswitch_hash': hashes['resolver/nsswitch.conf'], 'firewall_hash': hashes['collector.nft'],
        'service_hash': digest_json({name: hashes[name] for name in ('collector.service', 'resolver.service')})}
    if any(manifest.get(k) != v for k, v in expected.items()):
        raise ValueError('generated artifact identities disagree')
    observation = manifest['verification_profile'] == OBSERVATION_PROFILE
    if observation and manifest.get('completion'):
        raise ValueError('observation_requires_standard_intake')
    if manifest.get('owned_controls') != ({} if observation else {'https_url': OWNED_URL}):
        raise ValueError('owned Internet control changed')
    for key in ('local_ipv4', 'gateways_ipv4'):
        if manifest.get(key) != _topology(manifest.get(key)):
            raise ValueError('topology must be normalized literal IPv4 values')
    claims = manifest.get('claims')
    if (not isinstance(claims, dict) or set(claims) != {'authoritative_dns_verified', 'dnssec_verified',
            'external_receiver_logs_verified', 'labels_currently_verified'} or any(value is not False for value in claims.values())):
        raise ValueError('unmeasured external or label claims cannot be promoted')
    if require_ready:
        if manifest.get('status') != 'configured' or manifest.get('required_inputs') != []:
            raise ValueError('public-web inputs remain incomplete')
        _uid(manifest.get('study_uid'), 'collector')
        _uid(resolver.get('uid'), 'resolver')
        if manifest['study_uid'] == resolver['uid']:
            raise ValueError('separate dedicated identities required')
        for key in ('intake_manifest_hash', 'upstream_config_hash'):
            _hash(manifest.get(key), key)
    return True


def public_identity(manifest):
    validate_public_manifest(manifest)
    identity = {key: manifest.get(key) for key in IDENTITY_KEYS}
    for key, value in identity.items():
        if key not in {'schema_version', 'verification_profile', 'assurance_model'}:
            _hash(value, key)
    return identity


def validate_public_bundle(bundle, root=None):
    from .deployment import file_hash, source_hash
    bundle = Path(bundle)
    path = bundle / 'deployment.json'
    if path.is_symlink():
        raise ValueError('manifest cannot be a symlink')
    manifest = json.loads(path.read_text(encoding='utf-8'))
    validate_public_manifest(manifest)
    for name, expected in manifest['artifact_hashes'].items():
        path = bundle / name
        if path.is_symlink() or not path.is_file() or file_hash(path) != expected:
            raise ValueError('public-web artifact changed: ' + name)
    config = load(bundle / 'pilot.template.toml')
    if config.fingerprint != manifest['pilot_config_hash'] or config.network_isolation_verified:
        raise ValueError('public-web configuration changed')
    if json.loads((bundle / 'resolver/config.json').read_text()) != manifest['resolver']:
        raise ValueError('resolver configuration changed')
    actual_root = Path(root) if root is not None else Path(manifest['source_root'])
    if source_hash(actual_root) != manifest['source_hash']:
        raise ValueError('public-web installed source changed')
    if file_hash(actual_root / 'study/logging_resolver.py') != manifest['resolver_code_hash']:
        raise ValueError('public-web resolver code changed')
    if (bundle / 'collector.nft').read_text() != render_firewall(manifest['study_uid'], manifest['resolver']['uid'], manifest['local_ipv4'], manifest['gateways_ipv4']):
        raise ValueError('firewall differs from profile specification')
    public_identity(manifest)
    return manifest


def _checks(value, required, label):
    if (not isinstance(value, dict) or not required.issubset(value)
            or any(item is not True for item in value.values())):
        raise ValueError(label + ' required measured checks did not all pass')


def _section(report, manifest, name):
    section = report.get(name)
    if not isinstance(section, dict) or section.get('source_hash') != manifest['source_hash']:
        raise ValueError('source-bound evidence section required: ' + name)
    _hash(section.get('report_sha256'), name + ' report')
    return section


def _window(start, end):
    try:
        a, b = datetime.fromisoformat(start), datetime.fromisoformat(end)
        if a.tzinfo is None or b.tzinfo is None or a > b:
            raise ValueError()
        return a, b
    except (TypeError, ValueError):
        raise ValueError('timezone-aware measurement window required') from None


def _lifecycle(result, uid):
    life = result.get('lifecycle')
    if not isinstance(life, dict):
        raise ValueError('actual lifecycle receipt required')
    if (life.get('cancelled') is not False or life.get('abandoned_stages') != []
            or type(life.get('pending_abandoned_stage_count')) is not int or life['pending_abandoned_stage_count'] != 0
            or type(life.get('pending_tasks_at_loop_close')) is not int or life['pending_tasks_at_loop_close'] != 0
            or life.get('owned_browser_process_after_cleanup', {}).get('gone') is not True
            or life.get('captured_browser_identity', {}).get('uid') != uid):
        raise ValueError('lifecycle was not graceful and quiescent')
    stages = life.get('stages')
    if not isinstance(stages, list) or not stages:
        raise ValueError('actual bounded cleanup stages required')
    names = {stage.get('name'): stage for stage in stages if isinstance(stage, dict)}
    if not {'browser_close', 'driver_stop'}.issubset(names) or len(names) != len(stages):
        raise ValueError('complete unambiguous browser/driver cleanup required')
    for stage in stages:
        duration, deadline = stage.get('duration_seconds'), stage.get('deadline_seconds')
        if (stage.get('ok') is not True or type(duration) not in (int, float) or type(deadline) not in (int, float)
                or not 0 <= duration <= deadline or deadline <= 0):
            raise ValueError('bounded lifecycle stage failed')
    if names['browser_close']['deadline_seconds'] != 12 or names['driver_stop']['deadline_seconds'] != 5:
        raise ValueError('verified browser/driver cleanup deadlines changed')


def validate_public_evidence(manifest, evidence):
    return _validate_evidence(manifest, evidence, kernel_only=False)


def validate_execution_evidence(manifest, evidence):
    return _validate_evidence(manifest, evidence,
        kernel_only=manifest.get('verification_profile') == OBSERVATION_PROFILE)


def _validate_evidence(manifest, evidence, *, kernel_only):
    identity = public_identity(manifest)
    if manifest['verification_profile'] != (OBSERVATION_PROFILE if kernel_only else PROFILE):
        raise ValueError('evidence_purpose_does_not_match_requested_gate')
    if not isinstance(evidence, dict) or any(evidence.get(k) != v for k, v in identity.items()):
        raise ValueError('public-web evidence identity does not match')
    if (evidence.get('status') != 'passed'
            or evidence.get('network_isolation_verified') is not (False if kernel_only else True)
            or evidence.get('activation_allowed') is not (False if kernel_only else True)
            or kernel_only and evidence.get('observation_allowed') is not True):
        raise ValueError('complete public-web deployment approval required')
    if type(evidence.get('research_collection_count')) is not int or evidence['research_collection_count'] != 0:
        raise ValueError('verification cannot contain dataset-site collection')
    if not isinstance(evidence.get('nonce'), str) or re.fullmatch('[a-f0-9]{32}', evidence['nonce']) is None:
        raise ValueError('fresh verification nonce required')
    start, end = _window(evidence.get('started_at'), evidence.get('finished_at'))
    for key in (('normal_firewall_state_hash',) if kernel_only else
                ('normal_firewall_state_hash', 'runtime_service_hash', 'runtime_resolver_service_hash')):
        _hash(evidence.get(key), key)
    if evidence.get('claims') != manifest['claims']:
        raise ValueError('unmeasured assurance claims changed')
    suite = _section(evidence, manifest, 'suite')
    if (suite.get('successful') is not True or suite.get('browser_verified') is not True
            or type(suite.get('tests_run')) is not int or suite['tests_run'] < 322
            or type(suite.get('passed')) is not int or suite['passed'] != suite['tests_run'] or suite.get('skipped') != []
            or any(type(suite.get(key)) is not int or suite[key] != 0 for key in ('failures', 'errors', 'expected_failures', 'unexpected_successes'))
            or type(suite.get('browser_tests', {}).get('passed')) is not int or suite['browser_tests']['passed'] < 18
            or suite.get('browser_tests', {}).get('missing') != []):
        raise ValueError('complete strict Linux and Chromium suite required')
    if suite.get('python') != RUNTIME_PINS['python'] or any(suite.get('versions', {}).get(name) != value
            for name, value in RUNTIME_PINS.items() if name != 'python'):
        raise ValueError('strict suite did not run with pinned dependencies')
    from .deployment_checks import FIXTURE_CHECKS
    fixture = _section(evidence, manifest, 'selftest')
    if fixture.get('fixture_verified') is not True or fixture.get('status') != 'passed':
        raise ValueError('fresh selftest required')
    _checks(fixture.get('checks'), FIXTURE_CHECKS, 'selftest')
    if type(fixture.get('export', {}).get('research_eligible')) is not int or fixture['export']['research_eligible'] != 0:
        raise ValueError('fixtures cannot be research rows')
    kernel = _section(evidence, manifest, 'kernel')
    if (kernel.get('status') != 'passed' or kernel.get('firewall_hash') != manifest['firewall_hash']
            or kernel.get('service_hash') != manifest['service_hash']):
        raise ValueError('kernel controls must exercise exact generated policy and service profile')
    _checks(kernel.get('checks'), KERNEL_CHECKS, 'kernel')
    cases = kernel.get('cases')
    if not isinstance(cases, dict) or set(cases) != KERNEL_CASES:
        raise ValueError('complete kernel case receipts required')
    for name, case in cases.items():
        if (not isinstance(case, dict) or type(case.get('positive_control_hits')) is not int
                or case['positive_control_hits'] <= 0 or type(case.get('workload_hits')) is not int
                or case['workload_hits'] != 0 or type(case.get('reject_counter_delta')) is not int
                or case['reject_counter_delta'] < 0
                or name != 'redirect' and case['reject_counter_delta'] <= 0):
            raise ValueError('positive receiver/zero-hit/rejection proof required: ' + name)
    if kernel_only:
        from .observation import validate_tail
        return validate_tail(manifest, evidence, start, end)
    connected = _section(evidence, manifest, 'connected')
    if connected.get('status') != 'passed' or connected.get('firewall_hash') != manifest['firewall_hash']:
        raise ValueError('installed owned-site policy verification required')
    _checks(connected.get('checks'), CONNECTED_CHECKS, 'connected')
    stop = connected.get('service_stop')
    if (not isinstance(stop, dict) or stop.get('status') != 'passed'
            or type(stop.get('worker_exit')) is not int or stop['worker_exit'] != 0
            or stop.get('source_hash') != manifest['source_hash']
            or stop.get('uid') != manifest['study_uid'] or stop.get('signal_seen') != 'SIGTERM'
            or any(stop.get(key) is not True for key in ('stop_sent', 'namespace_disconnected', 'collection_account_idle'))):
        raise ValueError('actual generated-service cancellation and clean exit required')
    _checks(stop.get('checks'), SERVICE_STOP_CHECKS, 'service stop')
    _hash(stop.get('report_sha256'), 'service stop worker report')
    _hash(stop.get('runtime_service_hash'), 'service stop runtime service')
    _lifecycle(stop, manifest['study_uid'])
    phases = connected.get('phases')
    if not isinstance(phases, list) or [p.get('phase') for p in phases if isinstance(p, dict)] != ['normal', 'blocked', 'restored']:
        raise ValueError('fresh normal/blocked/restored browser phases required')
    previous = start
    for phase in phases:
        phase_start, phase_end = _window(phase.get('started_at'), phase.get('finished_at'))
        if not previous <= phase_start <= phase_end <= end:
            raise ValueError('phase windows must be ordered within verification window')
        previous = phase_end
        if phase.get('status') != 'passed' or type(phase.get('worker_exit')) is not int or phase['worker_exit'] != 0:
            raise ValueError('owned-site worker phase did not pass')
        _hash(phase.get('report_sha256'), 'owned worker report')
        _hash(phase.get('receipt_sha256'), 'owned phase receipt')
        _lifecycle(phase, manifest['study_uid'])
        if phase.get('target') != OWNED_URL or phase.get('effective_dns_verified') is not True:
            raise ValueError('owned destination and effective local DNS evidence required')
        if phase.get('browser_version', phase.get('versions', {}).get('chromium')) != CHROMIUM_VERSION:
            raise ValueError('owned control used a different Chromium version')
        navigation, network = phase.get('navigation', {}), phase.get('network', {})
        count = phase.get('resolver_query_count')
        if type(count) is not int or count < 0:
            raise ValueError('measured DNS query count required')
        if phase['phase'] == 'blocked':
            native = navigation.get('native_dns_error')
            from .deployment_checks import dns_failure_code
            if (navigation.get('status') is not None or not dns_failure_code(native)
                    or count != 0 or type(network.get('response_count')) is not int or network['response_count'] != 0
                    or type(network.get('completed_encoded_bytes')) is not int or network['completed_encoded_bytes'] != 0
                    or type(phase.get('reject_counter_delta')) is not int or phase['reject_counter_delta'] <= 0):
                raise ValueError('native DNS blackout with zero queries/responses and kernel rejection required')
        elif (navigation.get('status') != 200 or navigation.get('error_type') is not None or count <= 0
                or phase.get('capture_eligible') is not True or phase.get('dns_metadata', {}).get('measured') is not True
                or phase.get('tls_metadata', {}).get('measured') is not True
                or phase['tls_metadata'].get('validation') != 'system_trust_verified'
                or type(network.get('response_count')) is not int or network['response_count'] <= 0):
            raise ValueError('actual owned capture with system-trusted TLS and DNS extraction required')
    trials = evidence.get('lifecycle_trials')
    if not isinstance(trials, list) or len(trials) != 10:
        raise ValueError('ten consecutive successful lifecycle trials required')
    if not {'normal', 'redirect'}.issubset({trial.get('phase') for trial in trials if isinstance(trial, dict)}):
        raise ValueError('lifecycle trials must include both normal and redirect controls')
    for trial in trials:
        if not isinstance(trial, dict) or trial.get('status') != 'passed' or trial.get('source_hash') != manifest['source_hash']:
            raise ValueError('source-bound lifecycle trial did not pass')
        _hash(trial.get('report_sha256'), 'lifecycle trial report')
        _lifecycle(trial, manifest['study_uid'])
    _checks(evidence.get('cleanup'), CLEANUP_CHECKS, 'cleanup')
    files = evidence.get('evidence_files')
    if not isinstance(files, dict) or not {'suite', 'selftest', 'kernel', 'connected', 'lifecycle'}.issubset(files):
        raise ValueError('root-frozen underlying report identities required')
    for name, entry in files.items():
        if not isinstance(entry, dict) or not isinstance(entry.get('path'), str) or not Path(entry['path']).is_absolute():
            raise ValueError('absolute root-frozen evidence path required')
        _hash(entry.get('sha256'), name + ' evidence file')
        if name in {'suite', 'selftest', 'kernel', 'connected'} and entry['sha256'] != evidence[name]['report_sha256']:
            raise ValueError('underlying section/file identity mismatch: ' + name)
    return True


def validate_public_evidence_files(evidence):
    """Root/service gate verifies protected actual files, not only copied fields."""
    from .deployment import file_hash, secure_root_file
    for name, entry in evidence['evidence_files'].items():
        path = secure_root_file(entry['path'])
        if file_hash(path) != entry['sha256']:
            raise ValueError('frozen underlying report changed: ' + name)
        if name in {'suite', 'selftest', 'kernel', 'connected'}:
            actual = json.loads(path.read_text(encoding='utf-8'))
            expected = {key: value for key, value in evidence[name].items()
                        if key != 'report_sha256'}
            if not isinstance(actual, dict) or actual != expected:
                raise ValueError('underlying report content differs from approval: ' + name)
        elif name == 'lifecycle':
            actual = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(actual, dict) or actual.get('trials') != evidence['lifecycle_trials']:
                raise ValueError('lifecycle aggregate differs from approval')
        elif name == 'service_stop':
            if json.loads(path.read_text()) != evidence.get('service_stop'):
                raise ValueError('service stop aggregate differs from observation evidence')
    return True


def check_public_activation(manifest, evidence, current_source_hash, current_firewall_hash,
                            current_state_hash, current_resolver_hash, config,
                            current_upstream_hash, current_intake_hash):
    return _check_execution_activation(manifest, evidence, current_source_hash, current_firewall_hash,
        current_state_hash, current_resolver_hash, config, current_upstream_hash, current_intake_hash,
        kernel_only=False)


def _check_execution_activation(manifest, evidence, current_source_hash, current_firewall_hash,
                            current_state_hash, current_resolver_hash, config,
                            current_upstream_hash, current_intake_hash, *, kernel_only):
    _validate_evidence(manifest, evidence, kernel_only=kernel_only)
    _hash(current_upstream_hash, 'current upstream configuration')
    _hash(current_intake_hash, 'current intake manifest')
    expected = {'source_hash': current_source_hash, 'firewall_hash': current_firewall_hash,
        'normal_firewall_state_hash': current_state_hash, 'resolver_hash': current_resolver_hash,
        'upstream_config_hash': current_upstream_hash, 'intake_manifest_hash': current_intake_hash}
    if any((evidence if key == 'normal_firewall_state_hash' else manifest).get(key) != value for key, value in expected.items()):
        raise ValueError('installed source/firewall/resolver/upstream/intake no longer matches verified evidence')
    if (config.fingerprint != manifest['pilot_config_hash'] or config.network_isolation_verified
            or config.region != manifest['region'] or config.route_id != 'direct-ipv4'
            or config.proxy_required or config.interaction != 'none'
            or (config.workers, config.max_hours) != (1, 2)
            or config.usable_per_class != manifest.get('usable_per_class', 50)
            or config.max_attempts != manifest.get('max_attempts', 400)):
        raise ValueError('finite passive public-web collection template changed')
    return True


def public_gate(bundle, evidence_path, intake_path, *, root=None,
                upstream_path='/run/systemd/resolve/resolv.conf'):
    return execution_gate(bundle, evidence_path, intake_path, root=root,
                          upstream_path=upstream_path, kernel_only=False)


def execution_gate(bundle, evidence_path, intake_path, *, root=None,
                upstream_path='/run/systemd/resolve/resolv.conf', kernel_only=False):
    """Root remeasurement immediately before a separately bounded pilot launch.

    This returns the still-inactive template. The caller must start/monitor the
    verified service under its recorded UID and retain runtime health checks.
    """
    import os
    import subprocess
    from .deployment import (file_hash, firewall_state_hash, network_snapshot,
                             secure_root_file, source_files, source_hash)
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        raise ValueError('root must remeasure installed public-web policy')
    bundle = Path(bundle)
    manifest = validate_public_bundle(bundle, root=root)
    source_root = Path(root) if root is not None else Path(manifest['source_root'])
    for path in (bundle / 'deployment.json', *[bundle / name for name in ARTIFACTS], *source_files(source_root)):
        secure_root_file(path)
    evidence_path = secure_root_file(evidence_path)
    intake_path = secure_root_file(intake_path)
    evidence = json.loads(evidence_path.read_text(encoding='utf-8'))
    _validate_evidence(manifest, evidence, kernel_only=kernel_only)
    validate_public_evidence_files(evidence)
    validate_runtime_pins()
    actual_topology = network_snapshot()
    if actual_topology != {key: manifest[key] for key in ('local_ipv4', 'gateways_ipv4')}:
        raise ValueError('VM addresses/gateways changed; regenerate and reverify')
    rules = json.loads(subprocess.check_output(['nft', '-j', 'list', 'table', 'inet', NFT_TABLE], text=True, timeout=5))
    config = load(secure_root_file(bundle / 'pilot.template.toml'))
    _check_execution_activation(manifest, evidence, source_hash(source_root), file_hash(bundle / 'collector.nft'),
        firewall_state_hash(rules), file_hash(bundle / 'resolver/resolv.conf'), config,
        file_hash(upstream_path), file_hash(intake_path), kernel_only=kernel_only)
    return config


def validate_runtime_pins():
    """Remeasure pinned dependencies before activation; this never installs them."""
    import importlib.metadata
    import platform
    measured = {'python': platform.python_version()}
    for name in RUNTIME_PINS:
        if name != 'python':
            try:
                measured[name] = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                raise ValueError('pinned dependency missing: ' + name) from None
    if measured != RUNTIME_PINS:
        raise ValueError('installed dependency versions changed since verification')
    return measured
