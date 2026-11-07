#!/usr/bin/env python3
"""Freeze reviewed local intake and initiate/resume only the finite pilot."""
import argparse
from contextlib import closing
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import uuid

from study.config import load
from study.deployment import ETC, DATA, file_hash, secure_root_file
from study.sources import records
from study.urls import canonical_url


def receipt(source, feed, path):
    secure_root_file(feed)
    document = json.loads(secure_root_file(path).read_text())
    if document.get('source') != source or document.get('sha256') != file_hash(feed):
        raise ValueError('Feed receipt does not identify the supplied local feed')
    retrieved_at = document.get('retrieved_at', document.get('downloaded_at'))
    downloaded = datetime.fromisoformat(retrieved_at.replace('Z', '+00:00'))
    if downloaded.tzinfo is None or downloaded.utcoffset().total_seconds() != 0:
        raise ValueError('Feed retrieval time must be an explicit UTC timestamp')
    age = (datetime.now(timezone.utc) - downloaded).total_seconds()
    if not 0 <= age <= {'openphish': 43200, 'phishtank': 3600}[source]:
        raise ValueError('Feed is not fresh for its documented source refresh interval')
    return {'source': source, 'sha256': document['sha256'], 'retrieved_at': retrieved_at}


def archive_unstarted_preparation(data, etc=ETC):
    """Retain interrupted intake only after proving no collector run exists."""
    data, etc = Path(data), Path(etc)
    state_path = secure_root_file(etc / 'pilot-intake-state.json')
    state = json.loads(state_path.read_text())
    database = data / 'study.sqlite'
    if data.is_symlink() or database.is_symlink() or state.get('status') not in {'preparing', 'prepared'}:
        raise ValueError('Existing pilot dataset is not an interrupted preparation')
    if database.exists():
        with closing(sqlite3.connect(f'file:{database}?mode=ro', uri=True)) as connection:
            has_runs = connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='runs'").fetchone()[0]
            if has_runs and connection.execute('SELECT COUNT(*) FROM runs').fetchone()[0]:
                raise ValueError('Pilot has a run; recover an unfinished run or review completed evidence')
    suffix = uuid.uuid4().hex
    archive = data.with_name('dataset.preparation-' + suffix)
    data.rename(archive)
    intake = etc / 'intake'
    if intake.exists():
        intake.rename(intake.with_name('intake.preparation-' + suffix))
    state_path.rename(state_path.with_name('pilot-intake-state.preparation-' + suffix + '.json'))
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--legitimate-csv')
    parser.add_argument('--review-manifest')
    parser.add_argument('--openphish-file')
    parser.add_argument('--openphish-receipt')
    parser.add_argument('--phishtank-file')
    parser.add_argument('--phishtank-receipt')
    parser.add_argument('--resume')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Root is required to freeze intake and pilot activation')
    data = Path(DATA) / 'dataset'
    config = load(secure_root_file(f'{ETC}/pilot.template.toml'))
    config.network_isolation_verified = True  # Match the activated run fingerprint; not persisted here.
    if args.resume:
        if not re.fullmatch(r'[0-9a-f]{32}', args.resume):
            raise ValueError('Expected the exact unfinished run ID')
        database = data / 'study.sqlite'
        if database.is_symlink() or not database.is_file():
            raise ValueError('Expected the existing pilot database')
        with closing(sqlite3.connect(f'file:{database}?mode=ro', uri=True)) as connection:
            row = connection.execute('SELECT config_hash,finished FROM runs WHERE id=?', (args.resume,)).fetchone()
        if row is None or row[1] is not None or row[0] != config.fingerprint:
            raise ValueError('Only an unfinished run with the original frozen configuration can resume')
        request = {'resume': args.resume}
    else:
        if data.exists():
            # Interrupted preparation has no collector run to resume. Preserve it
            # intact and retry only when immutable preparation provenance exists.
            archive_unstarted_preparation(data)
        if not args.legitimate_csv or not args.review_manifest:
            raise ValueError('Reviewed legitimate CSV and its export audit are required')
        from study.review_workflow import validate_export
        secure_root_file(args.legitimate_csv)
        secure_root_file(args.review_manifest)
        reviewed = validate_export(args.legitimate_csv, args.review_manifest)
        if reviewed.get('domain_or_tenant_groups', 0) < 50:
            raise ValueError('At least 50 independently reviewed legitimate domain/tenant groups are required')
        legitimate = list(records('csv', args.legitimate_csv))
        if any(r['label'] != 'legitimate' or r['confidence'] != 'verified' for r in legitimate):
            raise ValueError('Legitimate CSV must contain independently reviewed verified endpoints only')
        if len({canonical_url(r['url']) for r in legitimate}) < 50:
            raise ValueError('At least 50 distinct reviewed legitimate candidates are required')
        phishing, sources = [], []
        for source in ('openphish', 'phishtank'):
            feed, evidence = getattr(args, f'{source}_file'), getattr(args, f'{source}_receipt')
            if not feed and not evidence:
                continue
            if not feed or not evidence:
                raise ValueError('A local feed and its root-owned receipt are both required')
            metadata = receipt(source, feed, evidence)
            rows = list(records(source, feed))
            if source == 'openphish':
                for row in rows:
                    row['observed_at'] = metadata['retrieved_at']
            phishing.extend(rows)
            sources.append(metadata)
        if len({canonical_url(r['url']) for r in phishing}) < 50:
            raise ValueError('At least 50 distinct fresh phishing source candidates are required')
        if shutil.disk_usage(DATA).free < 15000000000:
            raise ValueError('At least 15 GB free storage is required before the initial pilot')
        intake = Path(ETC) / 'intake'
        if intake.exists():
            # A previous preparation may have stopped before it created a DB.
            state = json.loads(secure_root_file(f'{ETC}/pilot-intake-state.json').read_text())
            if state.get('status') not in {'preparing', 'prepared'} or intake.is_symlink():
                raise ValueError('Refusing an unrecognized existing intake directory')
            intake.rename(intake.with_name('intake.preparation-' + uuid.uuid4().hex))
        preparation = Path(f'{ETC}/pilot-intake-state.json')
        preparation.write_text(json.dumps({'status': 'preparing', 'created_at': datetime.now(timezone.utc).isoformat()}))
        os.chmod(preparation, 0o644)
        intake.mkdir(mode=0o750)
        group = __import__('grp').getgrnam('study').gr_gid
        os.chown(intake, 0, group)
        fields = ('url', 'label', 'confidence', 'source', 'source_id', 'observed_at')
        for name, rows in (('legitimate', legitimate), ('phishing', phishing)):
            path = intake / f'{name}.csv'
            with path.open('w', newline='', encoding='utf-8') as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
            os.chown(path, 0, group)
            os.chmod(path, 0o640)
        audit_path = intake / 'legitimate.review-audit.json'
        shutil.copyfile(args.review_manifest, audit_path)
        os.chown(audit_path, 0, group)
        os.chmod(audit_path, 0o640)
        request = {'resume': None, 'created_at': datetime.now(timezone.utc).isoformat(),
                   'review_export_sha256': file_hash(args.legitimate_csv),
                   'review_audit_sha256': file_hash(audit_path), 'review_audit_path': str(audit_path), 'feed_receipts': sources,
                   'legitimate_candidates': len(legitimate), 'phishing_candidates': len(phishing)}
        for name in ('legitimate', 'phishing'):
            subprocess.run(['runuser', '-u', 'study', '--', '/opt/phishing-study/venv/bin/python', '-m', 'study',
                            '--data', str(data), 'ingest', 'csv', '--file', str(intake / f'{name}.csv')], check=True)
        preparation.write_text(json.dumps({'status': 'prepared', 'created_at': request['created_at'],
                                           'review_export_sha256': request['review_export_sha256']}))
    Path(f'{ETC}/pilot-request.json').write_text(json.dumps(request, indent=2))
    os.chmod(f'{ETC}/pilot-request.json', 0o644)


if __name__ == '__main__':
    main()
