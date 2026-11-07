"""Freeze a deterministic pilot from historically dataset-labelled URLs.

Only the supplied CSV and frozen offline split ledger are read. No candidate
endpoint is contacted, and no published label becomes a current verified label.
"""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re

from .urls import canonical_url, digest, domain_group

PROFILE = 'phiusiil-revisit-v1'
SOURCE = 'phiusiil-dataset'
SEED = 20261010
FIELDS = ('url', 'label', 'confidence', 'source', 'source_id', 'observed_at')
MEMBERSHIP_FIELDS = ('source_row', 'row_id', 'url_hash', 'domain_group_hash',
                     'component_id', 'page_vector_hash', 'split', 'truth_phishing')
LABELS = {0: 'phishing', 1: 'legitimate'}
HASH = re.compile(r'^[a-f0-9]{64}$')
ORDER = 'sha256(seed:group:domain_group_hash), then sha256(seed:url:url_hash); interleave legitimate,phishing'


def sha256_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def digest_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def manifest_hash(manifest):
    return digest_json({key: value for key, value in manifest.items() if key != 'manifest_sha256'})


def _integer(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(name + ' is outside the supported bounds')
    return value


def _hash(value, name):
    if not isinstance(value, str) or HASH.fullmatch(value) is None:
        raise ValueError(name + ' must be a SHA-256 digest')
    return value


def _inputs(source_csv, membership_csv, audit_json):
    source_csv, membership_csv, audit_json = map(Path, (source_csv, membership_csv, audit_json))
    for path in (source_csv, membership_csv, audit_json):
        if not path.is_file() or path.is_symlink():
            raise ValueError('original inputs must be regular files, not symlinks')
    audit_bytes = audit_json.read_bytes()
    audit = json.loads(audit_bytes)
    if not isinstance(audit, dict) or not isinstance(audit.get('source'), dict) or not isinstance(audit.get('artifact_hashes'), dict):
        raise ValueError('a completed offline audit object is required')
    audit_hash = hashlib.sha256(audit_bytes).hexdigest()
    source_hash = sha256_file(source_csv)
    membership_hash = sha256_file(membership_csv)
    expected = audit.get('source', {})
    if (audit.get('status') != 'baseline_complete' or audit.get('external_dataset_only') is not True
            or audit.get('source_unchanged_after_run') is not True
            or expected.get('sha256') != source_hash or expected.get('bytes') != source_csv.stat().st_size
            or audit.get('artifact_hashes', {}).get('split-membership.csv') != membership_hash):
        raise ValueError('source or frozen membership does not match the completed offline audit')
    mapping = expected.get('label_mapping', {})
    if not isinstance(mapping, dict):
        raise ValueError('audited PhiUSIIL label convention is required')
    if mapping.get('source_0') != 'phishing' or mapping.get('source_1') != 'legitimate':
        raise ValueError('audited PhiUSIIL label convention does not match 0=phishing,1=legitimate')
    return source_csv, membership_csv, audit_json, audit, source_hash, membership_hash, audit_hash


def _clean(source_csv, source_hash):
    """Use the existing canonicalization/group semantics without loading features."""
    from .phiusiil import EXPECTED_COLUMNS
    by_url = {}
    raw_counts = Counter()
    invalid, rows = 0, 0
    with source_csv.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        header = reader.fieldnames or []
        if len(header) != len(set(header)) or set(header) != set(EXPECTED_COLUMNS):
            raise ValueError('the original PhiUSIIL schema is required')
        for number, raw in enumerate(reader, 1):
            rows += 1
            if None in raw or any(value is None for value in raw.values()):
                raise ValueError('malformed original CSV row')
            token = raw['label'].strip()
            if token not in ('0', '1'):
                raise ValueError('label must be the original token 0 or 1')
            label = int(token)
            raw_counts[str(label)] += 1
            try:
                url = canonical_url(raw['URL'])
                group = domain_group(url)
                if not group:
                    raise ValueError('empty domain group')
            except (ValueError, UnicodeError, TypeError):
                invalid += 1
                continue
            if url in by_url:
                state = by_url[url]
                state['count'] += 1
                state['label_mask'] |= 1 << label
                continue
            by_url[url] = {'count': 1, 'label_mask': 1 << label,
                'record': {'source_row': number, 'row_id': digest(source_hash + ':' + str(number)),
                    'url': url, 'url_hash': digest(url), 'domain_group': group,
                    'domain_group_hash': digest(group), 'source_label': label, 'label': LABELS[label]}}
    if rows == 0:
        raise ValueError('the source has no rows')
    retained, duplicate, conflict = {}, 0, 0
    for state in by_url.values():
        if state['label_mask'] == 3:
            conflict += state['count']
        else:
            duplicate += state['count'] - 1
            record = state['record']
            retained[record['source_row']] = record
    del by_url
    census = {'rows': rows, 'source_label_counts': dict(sorted(raw_counts.items())),
              'retained_rows': len(retained),
              'retained_class_counts': dict(sorted(Counter(r['label'] for r in retained.values()).items())),
              'exclusion_counts': {'invalid_canonical_url': invalid, 'canonical_url_label_conflict': conflict,
                                   'duplicate_url_same_label': duplicate}}
    return retained, census


def _membership(path, retained):
    seen, splits = set(), Counter()
    with path.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != MEMBERSHIP_FIELDS:
            raise ValueError('unexpected frozen split ledger schema')
        for raw in reader:
            if None in raw or any(value is None for value in raw.values()):
                raise ValueError('malformed split ledger row')
            try:
                number = int(raw['source_row'])
            except (TypeError, ValueError):
                raise ValueError('invalid source ordinal in frozen split ledger') from None
            record = retained.get(number)
            if record is None or number in seen:
                raise ValueError('unknown or repeated source row in frozen split ledger')
            if (raw['row_id'] != record['row_id'] or raw['url_hash'] != record['url_hash']
                    or raw['domain_group_hash'] != record['domain_group_hash']
                    or raw['truth_phishing'] != str(1 - record['source_label'])
                    or raw['split'] not in ('train', 'validation', 'test')):
                raise ValueError('frozen split identity or label does not match original CSV')
            seen.add(number)
            record['split'] = raw['split']
            splits[raw['split']] += 1
    if seen != set(retained):
        raise ValueError('frozen split ledger does not cover all cleaned rows')
    group_splits = defaultdict(set)
    for record in retained.values():
        group_splits[record['domain_group_hash']].add(record['split'])
    if any(len(value) != 1 for value in group_splits.values()):
        raise ValueError('a domain group crosses frozen partitions')
    return dict(sorted(splits.items()))


def _population(source_csv, membership_csv, audit_json, seed):
    _integer(seed, 0, 2 ** 32 - 1, 'seed')
    source_csv, membership_csv, audit_json, audit, source_hash, membership_hash, audit_hash = _inputs(source_csv, membership_csv, audit_json)
    retained, census = _clean(source_csv, source_hash)
    for name in ('rows', 'source_label_counts', 'retained_rows', 'retained_class_counts', 'exclusion_counts'):
        if census[name] != audit.get(name):
            raise ValueError('reconstructed cleaning differs from frozen offline audit: ' + name)
    census['split_rows'] = _membership(membership_csv, retained)
    group_labels = defaultdict(set)
    for record in retained.values():
        group_labels[record['domain_group_hash']].add(record['label'])
    mixed = {group for group, labels in group_labels.items() if len(labels) != 1}
    groups = defaultdict(list)
    for record in retained.values():
        if record['split'] == 'train' and record['domain_group_hash'] not in mixed:
            groups[record['domain_group_hash']].append(record)
    chosen = defaultdict(list)
    for group in sorted(groups, key=lambda value: digest(str(seed) + ':group:' + value)):
        record = min(groups[group], key=lambda value: digest(str(seed) + ':url:' + value['url_hash']))
        chosen[record['label']].append(record)
    available = {label: len(chosen[label]) for label in ('legitimate', 'phishing')}
    census['mixed_label_groups_excluded'] = len(mixed)
    census['homogeneous_train_groups'] = available
    if (sha256_file(source_csv) != source_hash or sha256_file(membership_csv) != membership_hash
            or sha256_file(audit_json) != audit_hash):
        raise ValueError('original inputs changed during pilot preparation')
    return {'schema_version': 1, 'intake_profile': PROFILE, 'dataset': 'PhiUSIIL Phishing URL Dataset',
            'source_sha256': source_hash, 'source_bytes': source_csv.stat().st_size,
            'membership_sha256': membership_hash, 'offline_audit_sha256': audit_hash,
            'seed': seed, 'partition': 'train',
            'ordering': ORDER, 'one_endpoint_per_group': True, 'mixed_label_groups': 'excluded',
            'reachability_screened': False, 'endpoint_visits': 0, 'label_confidence': 'dataset',
            'label_observed_at': 'unknown', 'label_mapping': {'0': 'phishing', '1': 'legitimate'},
            'census': census, 'csv_file': 'candidates.csv'}, chosen


def _build(source_csv, membership_csv, audit_json, reserve_per_class, seed):
    _integer(reserve_per_class, 1, 200, 'reserve_per_class')
    manifest, chosen = _population(source_csv, membership_csv, audit_json, seed)
    if min(len(chosen[label]) for label in ('legitimate', 'phishing')) < reserve_per_class:
        raise ValueError('not enough homogeneous training groups for the requested frozen reserve')
    selected = []
    for rank in range(reserve_per_class):
        for label in ('legitimate', 'phishing'):
            selected.append({**chosen[label][rank], 'order': len(selected) + 1, 'class_order': rank + 1})
    manifest['census']['selected_per_class'] = {label: reserve_per_class for label in ('legitimate', 'phishing')}
    manifest.update(reserve_per_class=reserve_per_class, selected=selected, selection_sha256=digest_json(selected))
    return manifest


def records_from_manifest(manifest):
    for row in manifest['selected']:
        yield {'url': row['url'], 'label': row['label'], 'confidence': 'dataset',
               'source': SOURCE, 'source_id': row['row_id'], 'observed_at': 'unknown'}


def _csv_bytes(manifest):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator='\n')
    writer.writeheader()
    writer.writerows(records_from_manifest(manifest))
    return stream.getvalue().encode('utf-8')


def prepare(source_csv, membership_csv, audit_json, output, reserve_per_class=200, seed=SEED):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError('use a fresh output directory; earlier evidence must be preserved')
    manifest = _build(source_csv, membership_csv, audit_json, reserve_per_class, seed)
    csv_bytes = _csv_bytes(manifest)
    manifest.update({'csv_sha256': hashlib.sha256(csv_bytes).hexdigest(),
                     'csv_bytes': len(csv_bytes), 'prepared_at': datetime.now(timezone.utc).isoformat()})
    manifest['manifest_sha256'] = manifest_hash(manifest)
    output.mkdir(parents=True, mode=0o700)
    (output / 'candidates.csv').write_bytes(csv_bytes)
    (output / 'intake-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    for path in (output / 'candidates.csv', output / 'intake-manifest.json'):
        os.chmod(path, 0o600)
    return manifest


def validate_intake(csv_path, manifest_path, source_csv=None, membership_csv=None, audit_json=None):
    """Validate frozen rows; replay all originals before root first seals intake.

Without originals this checks protected-sidecar identity and exact CSV content,
not an independent reconstruction of the publication's source labels.
"""
    csv_path, manifest_path = Path(csv_path), Path(manifest_path)
    if any(path.is_symlink() or not path.is_file() for path in (csv_path, manifest_path)):
        raise ValueError('intake and manifest must be regular files, not symlinks')
    if manifest_path.stat().st_size > 8_000_000 or csv_path.stat().st_size > 4_000_000:
        raise ValueError('pilot intake exceeds its bounded size')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if isinstance(manifest, dict) and manifest.get('intake_profile') == 'phiusiil-phishing-completion-v1':
        from .phiusiil_completion import validate_intake as validate_completion_intake
        return validate_completion_intake(csv_path, manifest_path, source_csv, membership_csv, audit_json)
    if not isinstance(manifest, dict):
        raise ValueError('intake manifest must be an object')
    if (manifest.get('schema_version') != 1 or manifest.get('intake_profile') != PROFILE
            or manifest.get('manifest_sha256') != manifest_hash(manifest)):
        raise ValueError('wrong intake profile or altered manifest')
    for name in ('source_sha256', 'membership_sha256', 'offline_audit_sha256', 'selection_sha256', 'csv_sha256'):
        _hash(manifest.get(name), name)
    reserve = _integer(manifest.get('reserve_per_class'), 1, 200, 'reserve_per_class')
    _integer(manifest.get('seed'), 0, 2 ** 32 - 1, 'seed')
    if (manifest.get('partition') != 'train' or manifest.get('label_confidence') != 'dataset'
            or manifest.get('label_observed_at') != 'unknown' or manifest.get('label_mapping') != {'0': 'phishing', '1': 'legitimate'}
            or manifest.get('one_endpoint_per_group') is not True or manifest.get('mixed_label_groups') != 'excluded'
            or manifest.get('reachability_screened') is not False or type(manifest.get('endpoint_visits')) is not int
            or manifest['endpoint_visits'] != 0 or manifest.get('ordering') != ORDER or manifest.get('csv_file') != 'candidates.csv'):
        raise ValueError('intake no longer preserves the dataset-label operational-pilot protocol')
    try:
        prepared = datetime.fromisoformat(manifest['prepared_at'])
        if prepared.tzinfo is None or prepared > datetime.now(timezone.utc):
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ValueError('actual timezone-aware preparation time is required') from None
    selected = manifest.get('selected')
    if not isinstance(selected, list) or len(selected) != 2 * reserve or digest_json(selected) != manifest['selection_sha256']:
        raise ValueError('selected reserve is missing or altered')
    domains, urls, source_rows = set(), set(), set()
    for index, row in enumerate(selected):
        if not isinstance(row, dict):
            raise ValueError('invalid selected record')
        number = _integer(row.get('source_row'), 1, 10_000_000, 'source_row')
        _integer(row.get('order'), 1, 400, 'order')
        _integer(row.get('class_order'), 1, 200, 'class_order')
        label = row.get('source_label')
        url = canonical_url(row.get('url', ''))
        group = domain_group(url)
        if (type(label) is not int or label not in LABELS or row.get('label') != LABELS[label]
                or row.get('label') != ('legitimate' if index % 2 == 0 else 'phishing')
                or row.get('split') != 'train' or row.get('order') != index + 1 or row.get('class_order') != index // 2 + 1
                or row.get('url') != url or row.get('url_hash') != digest(url)
                or row.get('row_id') != digest(manifest['source_sha256'] + ':' + str(number))
                or row.get('domain_group') != group or row.get('domain_group_hash') != digest(group)
                or group in domains or url in urls or number in source_rows):
            raise ValueError('selected row identity, group, class order or historical label changed')
        domains.add(group)
        urls.add(url)
        source_rows.add(number)
    actual = csv_path.read_bytes()
    if (actual != _csv_bytes(manifest) or hashlib.sha256(actual).hexdigest() != manifest['csv_sha256']
            or len(actual) != manifest.get('csv_bytes')):
        raise ValueError('CSV is not the exact frozen dataset-label reserve')
    originals = (source_csv, membership_csv, audit_json)
    if any(value is not None for value in originals):
        if not all(value is not None for value in originals):
            raise ValueError('supply all three original inputs for deterministic replay')
        replay = _build(source_csv, membership_csv, audit_json, reserve, manifest['seed'])
        if any(manifest.get(key) != value for key, value in replay.items()):
            raise ValueError('intake selection or provenance differs from deterministic original-input replay')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('prepare')
    for name in ('source', 'membership', 'audit', 'output'):
        build.add_argument('--' + name, required=True)
    build.add_argument('--reserve-per-class', type=int, default=200)
    build.add_argument('--seed', type=int, default=SEED)
    verify = commands.add_parser('validate')
    verify.add_argument('--csv', required=True)
    verify.add_argument('--manifest', required=True)
    for name in ('source', 'membership', 'audit'):
        verify.add_argument('--' + name)
    args = parser.parse_args(argv)
    try:
        if args.command == 'prepare':
            result = prepare(args.source, args.membership, args.audit, args.output, args.reserve_per_class, args.seed)
        else:
            result = validate_intake(args.csv, args.manifest, args.source, args.membership, args.audit)
        print(json.dumps({'status': 'intake-validated', 'intake_profile': PROFILE,
                          'rows': len(result['selected']), 'manifest_sha256': result['manifest_sha256'],
                          'endpoint_visits': 0}))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({'status': 'failed', 'error_type': type(error).__name__, 'reason': str(error)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
