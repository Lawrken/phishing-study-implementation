"""A separately authorised phishing-only completion reserve; never visits URLs."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from . import phiusiil_intake as base
from .urls import canonical_url, domain_group, digest

PROFILE = 'phiusiil-phishing-completion-v1'
CAMPAIGN = 'phishing-completion-20261031-v1'
ORDER = 'original sha256 seed/group/url order; exclude all previous 200-per-class reserve groups; phishing only'
CONTRACT_KEYS = frozenset(('campaign_id', 'target_label', 'target_usable', 'attempt_limit',
    'max_hours', 'prior_usable_counts', 'prior_summary_sha256', 'prior_capture_csv_sha256', 'prior_audit_sha256'))


def validate_completion(value):
    if (not isinstance(value, dict) or set(value) != CONTRACT_KEYS
            or value.get('campaign_id') != CAMPAIGN or value.get('target_label') != 'phishing'
            or type(value.get('target_usable')) is not int or value['target_usable'] != 59
            or type(value.get('attempt_limit')) is not int or value['attempt_limit'] != 800
            or type(value.get('max_hours')) is not int or value['max_hours'] != 2
            or value.get('prior_usable_counts') != {'legitimate': 79, 'phishing': 16}
            or any(type(v) is not int for v in value['prior_usable_counts'].values())):
        raise ValueError('explicit_800_attempt_two_hour_59_phishing_completion_contract_required')
    for key in ('prior_summary_sha256', 'prior_capture_csv_sha256', 'prior_audit_sha256'):
        base._hash(value[key], key)
    return value


def _build(source, membership, audit, completion, reserve=800):
    validate_completion(completion)
    base._integer(reserve, 1, 800, 'completion_reserve')
    manifest, chosen = base._population(source, membership, audit, base.SEED)
    if min(len(chosen[label]) for label in ('legitimate', 'phishing')) < 200:
        raise ValueError('previous_200_per_class_reserve_cannot_be_reconstructed')
    previous = []
    for rank in range(200):
        for label in ('legitimate', 'phishing'):
            previous.append({**chosen[label][rank], 'order': len(previous) + 1, 'class_order': rank + 1})
    excluded = sorted(row['domain_group_hash'] for row in previous)
    candidates = [row for row in chosen['phishing'] if row['domain_group_hash'] not in set(excluded)]
    if len(candidates) < reserve:
        raise ValueError('insufficient_new_homogeneous_phishing_training_groups')
    selected = [{**row, 'order': index + 1, 'class_order': index + 1}
                for index, row in enumerate(candidates[:reserve])]
    manifest.update(intake_profile=PROFILE, completion=completion, reserve=reserve, ordering=ORDER,
        previous_reserve_per_class=200, previous_selection_sha256=base.digest_json(previous),
        excluded_domain_group_hashes=excluded, selected=selected,
        selection_sha256=base.digest_json(selected))
    manifest['census']['selected_per_class'] = {'legitimate': 0, 'phishing': reserve}
    return manifest


def prepare(source, membership, audit, output, completion, reserve=800):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('fresh completion output required; preserve earlier evidence')
    manifest = _build(source, membership, audit, completion, reserve)
    data = base._csv_bytes(manifest)
    manifest.update(csv_sha256=hashlib.sha256(data).hexdigest(), csv_bytes=len(data),
                    prepared_at=datetime.now(timezone.utc).isoformat())
    manifest['manifest_sha256'] = base.manifest_hash(manifest)
    output.mkdir(parents=True, mode=0o700)
    (output / 'candidates.csv').write_bytes(data)
    (output / 'intake-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    for name in ('candidates.csv', 'intake-manifest.json'):
        os.chmod(output / name, 0o600)
    return manifest


def validate_intake(csv_path, manifest_path, source=None, membership=None, audit=None):
    csv_path, manifest_path = Path(csv_path), Path(manifest_path)
    if any(not path.is_file() or path.is_symlink() for path in (csv_path, manifest_path)):
        raise ValueError('regular completion files required')
    if manifest_path.stat().st_size > 8_000_000 or csv_path.stat().st_size > 4_000_000:
        raise ValueError('completion intake size exceeded')
    m = json.loads(manifest_path.read_text(encoding='utf-8'))
    if (not isinstance(m, dict) or type(m.get('schema_version')) is not int or m['schema_version'] != 1
            or m.get('intake_profile') != PROFILE or m.get('manifest_sha256') != base.manifest_hash(m)):
        raise ValueError('completion profile or manifest identity changed')
    validate_completion(m.get('completion'))
    reserve = base._integer(m.get('reserve'), 1, 800, 'completion_reserve')
    for key in ('source_sha256', 'membership_sha256', 'offline_audit_sha256', 'selection_sha256',
                'csv_sha256', 'previous_selection_sha256'):
        base._hash(m.get(key), key)
    excluded = m.get('excluded_domain_group_hashes')
    if (not isinstance(excluded, list) or len(excluded) != 400 or excluded != sorted(set(excluded))
            or any(not isinstance(value, str) or not base.HASH.fullmatch(value) for value in excluded)):
        raise ValueError('all_400_previous_reserve_groups_must_be_excluded')
    if (type(m.get('seed')) is not int or m['seed'] != base.SEED or m.get('partition') != 'train'
            or m.get('previous_reserve_per_class') != 200 or m.get('ordering') != ORDER
            or m.get('one_endpoint_per_group') is not True or m.get('mixed_label_groups') != 'excluded'
            or m.get('reachability_screened') is not False or type(m.get('endpoint_visits')) is not int
            or m['endpoint_visits'] != 0 or m.get('label_confidence') != 'dataset'
            or m.get('label_observed_at') != 'unknown' or m.get('label_mapping') != {'0': 'phishing', '1': 'legitimate'}
            or m.get('csv_file') != 'candidates.csv'):
        raise ValueError('completion_protocol_changed')
    try:
        prepared = datetime.fromisoformat(m['prepared_at'])
        if prepared.tzinfo is None or prepared > datetime.now(timezone.utc):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ValueError('actual_completion_preparation_time_required') from None
    selected = m.get('selected')
    if not isinstance(selected, list) or len(selected) != reserve or base.digest_json(selected) != m['selection_sha256']:
        raise ValueError('completion_selection_changed')
    groups, urls, ordinals = set(), set(), set()
    for index, row in enumerate(selected):
        if not isinstance(row, dict):
            raise ValueError('invalid_completion_row')
        number = base._integer(row.get('source_row'), 1, 10_000_000, 'source_row')
        url = canonical_url(row.get('url', ''))
        group = domain_group(url)
        if (type(row.get('source_label')) is not int or row['source_label'] != 0 or row.get('label') != 'phishing'
                or row.get('order') != index + 1 or type(row.get('order')) is not int
                or row.get('class_order') != index + 1 or type(row.get('class_order')) is not int
                or row.get('split') != 'train' or row.get('url') != url or row.get('url_hash') != digest(url)
                or row.get('row_id') != digest(m['source_sha256'] + ':' + str(number))
                or row.get('domain_group') != group or row.get('domain_group_hash') != digest(group)
                or digest(group) in excluded or group in groups or url in urls or number in ordinals):
            raise ValueError('completion_row_label_identity_or_group_changed')
        groups.add(group); urls.add(url); ordinals.add(number)
    actual = csv_path.read_bytes()
    if (actual != base._csv_bytes(m) or hashlib.sha256(actual).hexdigest() != m['csv_sha256']
            or len(actual) != m.get('csv_bytes')):
        raise ValueError('completion_csv_changed')
    if any(v is not None for v in (source, membership, audit)):
        if not all(v is not None for v in (source, membership, audit)):
            raise ValueError('all_original_completion_inputs_required')
        replay = _build(source, membership, audit, m['completion'], reserve)
        if any(m.get(key) != value for key, value in replay.items()):
            raise ValueError('completion_differs_from_original_input_replay')
    return m
