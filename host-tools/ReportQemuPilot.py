"""Verify a frozen transfer and export/describe captures without training models."""
import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import sys
import tarfile
sys.dont_write_bytecode = True

def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def run(folder, recovery=None):
    folder=folder.resolve()
    frozen_folder=folder if recovery is None else recovery.resolve()
    receipt=json.loads((frozen_folder/'guest-export.json').read_text())
    result=json.loads((folder/'result.json').read_text())
    archive=frozen_folder/'guest-evidence.tar.gz'
    assert sha(archive)==receipt['sha256']
    extracted=frozen_folder/'guest-export'
    if not extracted.exists():
        with tarfile.open(archive,'r:gz') as stream:
            for member in stream.getmembers():
                path=PurePosixPath(member.name)
                assert path.parts and path.parts[0]=='guest' and not path.is_absolute() and '..' not in path.parts
                assert all(':' not in part and '\\' not in part for part in path.parts)
                assert member.isfile() or member.isdir()
            stream.extractall(extracted,filter='data')
    root=extracted/'guest'
    inventory=json.loads((root/'inventory.json').read_text())
    errors=[]
    for name,entry in inventory.items():
        path=root/name
        if not path.is_file() or path.stat().st_size!=entry['bytes'] or sha(path)!=entry['sha256']:errors.append(name)
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    assert not errors and actual==set(inventory)|{'inventory.json'}
    verification={'utc':datetime.now(timezone.utc).isoformat(),'archive_sha256':receipt['sha256'],
        'files_checked':len(inventory),'mismatches':errors,'passed':True}
    (folder/'transfer-verification.json').write_text(json.dumps(verification,indent=2))
    run_id=result['run_id']
    pilot=root/('pilot-'+run_id)
    if recovery is None:
        report=json.loads((pilot/'pilot-report.json').read_text())
        data=pilot/'dataset'
    else:
        recovered=json.loads((root/'recovery-summary.json').read_text())
        assert recovered['source_hash']==result['source_hash'] and recovered['collection_started_by_recovery'] is False
        assert recovered['accounts_idle'] is True and recovered['sqlite_integrity_check']=='ok'
        data=root/recovered['dataset_path_in_export']
        operational=json.loads((data/'operational-result.json').read_text())
        assert operational['identity']['source_hash']==result['source_hash']
        life=[json.loads(p.read_text()) for p in (data/'lifecycle').glob('*.json')]
        assert life and all(item['status']=='passed' for item in life)
        report={**recovered['counts'],'status':'failed','collection_activation':recovered['counts']['attempts']>0,
            'checks':{'worker_finished_on_signal':recovered['counts']['collector_stop_reason']=='signal',
                      'worker_browser_lifecycle_passed':True,'recovery_started_no_collection':True,
                      'root_controller_final_receipt_available':False},
            'stop_reason':'host_transport_failure_then_guest_poweroff',
            'cleanup_errors':[{'step':'root_controller_final_receipt_missing'}]}
    assessment=root/('assessment-'+run_id)
    deployment=json.loads((assessment/'assessment-result.json').read_text())
    source=json.loads((assessment/'bundle/deployment.json').read_text())
    suite=json.loads((assessment/'suite/test-report.json').read_text())
    assert data.is_dir()
    output=folder/'analysis';output.mkdir()
    stage=output/'sqlite-read-copy';stage.mkdir()
    for path in data.glob('study.sqlite*'):shutil.copyfile(path,stage/path.name)
    database_hash_before=sha(data/'study.sqlite')

    class ReadOnlyQueue:
        root=data
        @contextmanager
        def connect(self):
            connection=sqlite3.connect((stage/'study.sqlite').as_uri()+'?mode=ro',uri=True)
            connection.row_factory=sqlite3.Row
            try:yield connection
            finally:connection.close()

    queue=ReadOnlyQueue()
    sys.path.insert(0,str(root/'app'))
    from study.export import export
    from study.deployment import source_hash
    assert source_hash(root/'app')==result['source_hash']
    manifest=export(queue,output/'export',fmt='csv')
    with queue.connect() as db:
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        counts={'attempts':db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0],
            'distinct_urls_attempted':db.execute('SELECT COUNT(DISTINCT candidate_id) FROM attempts').fetchone()[0],
            'failed_attempts':db.execute('SELECT COUNT(*) FROM attempts WHERE finished IS NOT NULL AND eligible=0').fetchone()[0],
            'unfinished_attempts':db.execute('SELECT COUNT(*) FROM attempts WHERE finished IS NULL').fetchone()[0],
            'usable_per_class':{},'attempt_outcomes':{},'attempted_urls_per_class':{}}
        for label in ('legitimate','phishing'):
            counts['usable_per_class'][label]=db.execute("SELECT COUNT(*) FROM candidates WHERE label=? AND confidence='dataset' AND eligible=1 AND state='done'",(label,)).fetchone()[0]
            counts['attempted_urls_per_class'][label]=db.execute('SELECT COUNT(DISTINCT a.candidate_id) FROM attempts a JOIN candidates c ON c.id=a.candidate_id WHERE c.label=?',(label,)).fetchone()[0]
        counts['attempt_outcomes']={str(row[0]):row[1] for row in db.execute('SELECT outcome,COUNT(*) FROM attempts GROUP BY outcome')}
        runs=[dict(row) for row in db.execute('SELECT id,started,finished,stop_reason,attempts FROM runs ORDER BY started')]
        latest=[dict(row) for row in db.execute('SELECT * FROM attempts WHERE finished IS NOT NULL ORDER BY started,id')]
        reserve={row[0]:row[1] for row in db.execute('SELECT label,COUNT(*) FROM candidates GROUP BY label')}
        label_confidences={row[0]:row[1] for row in db.execute('SELECT confidence,COUNT(*) FROM candidates GROUP BY confidence')}
        candidate_labels=dict(db.execute('SELECT id,label FROM candidates'))
    for name in ('attempts','distinct_urls_attempted','failed_attempts','unfinished_attempts','usable_per_class'):
        assert counts[name]==report[name],(name,counts[name],report[name])
    if source.get('completion') is not None:
        assert source['completion']==result['completion']
        assert source['intake_profile']=='phiusiil-phishing-completion-v1'
        assert reserve=={'phishing':800} and counts['usable_per_class']['legitimate']==0
        assert counts['attempts']<=800 and counts['usable_per_class']['phishing']<=59
    else:
        assert reserve=={'legitimate':200,'phishing':200}
    assert set(label_confidences)=={'dataset'}
    assert manifest['research_eligible']==0
    assert manifest['dataset_label_capture_eligible']==sum(counts['usable_per_class'].values())
    latest_by_url={row['candidate_id']:row for row in latest}
    coverage=Counter();missing=Counter();regions=Counter();browsers=Counter();statuses=Counter();dispositions=Counter()
    unusable_reasons=Counter()
    for attempt in latest_by_url.values():
        label=candidate_labels[attempt['candidate_id']]
        if not attempt['artifact']:
            unusable_reasons[label+':'+str(attempt['outcome'])+':no_committed_artifact']+=1
            continue
        record=json.loads((data/attempt['artifact']).read_text())
        if not attempt['eligible']:
            reason=str(record.get('policy_reason') or record.get('error_type') or record['groups'].get('http',{}).get('status') or 'unspecified')
            if not re.fullmatch('[A-Za-z0-9_]{1,80}',reason):reason='other_categorical_reason'
            unusable_reasons[label+':'+str(attempt['outcome'])+':'+reason]+=1
            continue
        regions[record['region']]+=1;browsers[record['browser_version']]+=1
        statuses[str(record['groups'].get('http',{}).get('status'))]+=1
        for name,group in record['groups'].items():
            if group.get('measured') is True:coverage[name]+=1
            else:missing[name+':'+str(group.get('reason','not_marked_measured'))]+=1
        for flag,value in record['groups'].get('dom',{}).get('disposition_flags',{}).items():
            if value:dispositions[flag]+=1
    assert sha(data/'study.sqlite')==database_hash_before
    after_errors=[name for name,entry in inventory.items() if sha(root/name)!=entry['sha256']]
    assert not after_errors,after_errors
    timing=[]
    with (folder/'timing.jsonl').open() as stream:
        for line in stream:
            sample=json.loads(line)
            timing.append({key:sample[key] for key in ('elapsed_drift_seconds','offset_seconds',
                'roundtrip_seconds','host_available_ram_gib')})
    summary={'utc':datetime.now(timezone.utc).isoformat(),'host_result_status':result['status'],'pilot_status':report['status'],
        'collection_activation':report['collection_activation'],'verification_status':deployment['status'],
        'source_hash':result['source_hash'],'profile':source['verification_profile'],'counts':counts,'runs':runs,
        'completion':source.get('completion'),
        'frozen_archive_path':str(archive.resolve()),'frozen_export_root':str(root.resolve()),
        'recovered_after_guest_shutdown':recovery is not None,
        'reserve_per_published_class':reserve,'label_confidences':label_confidences,
        'collector_stop_reason':report.get('collector_stop_reason'),'pilot_stop_reason':report.get('stop_reason'),
        'host_stop_reason':result.get('stop_reason'),'verification_cleanup':deployment['final_cleanup'],
        'pilot_checks':report['checks'],'pilot_cleanup_errors':report.get('cleanup_errors',[]),
        'export_manifest':manifest,'sqlite_integrity_check':'ok','input_artifacts_unchanged_after_export':True,
        'regions':dict(regions),'browser_versions':dict(browsers),'usable_http_status_counts':dict(statuses),
        'usable_group_measurement_counts':dict(coverage),'usable_group_missing_counts':dict(missing),
        'usable_disposition_flags':dict(dispositions),'timing_samples':len(timing),
        'unusable_latest_record_reasons':dict(unusable_reasons),
        'maximum_absolute_elapsed_drift_seconds':max(abs(v['elapsed_drift_seconds']) for v in timing),
        'maximum_roundtrip_seconds':max(v['roundtrip_seconds'] for v in timing),
        'guest_wall_clock_offset_seconds':{'minimum':min(v['offset_seconds'] for v in timing),
            'maximum':max(v['offset_seconds'] for v in timing)},
        'minimum_host_available_ram_gib':min(v['host_available_ram_gib'] for v in timing),
        'host_timing_failures':result['host_timing_failures'],'archive_verification':verification,
        'models_retrained':False,'labels_currently_independently_verified':False,
        'export_hashes':{p.name:sha(p) for p in (output/'export').iterdir() if p.is_file()}}
    (output/'summary.json').write_text(json.dumps(summary,indent=2))
    lines=['# Supervised live pilot: '+run_id,'',
        'This pilot revisited frozen PhiUSIIL training endpoints and retained their historical published labels. No model was retrained.',
        '',f"Verification: {deployment['status']}. Pilot: {report['status']}. Collection activated: {report['collection_activation']}.",'',
        '| Measure | Actual result |','| --- | ---: |',
        *[f'| {name.replace("_"," ")} | {counts[name]} |' for name in ('attempts','distinct_urls_attempted','failed_attempts','unfinished_attempts')],
        f"| Usable legitimate-labelled captures | {counts['usable_per_class']['legitimate']} |",
        f"| Usable phishing-labelled captures | {counts['usable_per_class']['phishing']} |",'',
        f"Collector stop: {summary['collector_stop_reason']}. Pilot controller: {summary['pilot_stop_reason']}. Host supervisor: {summary['host_stop_reason']}.",
        '',f"The complete fresh suite ran {suite['tests_run']} tests including {suite['browser_tests']['passed']} Chromium cases, followed by selftest and kernel/lifecycle controls. Verification purpose: {source['verification_profile']}. "
           + ('No owned-site visits were made; website availability is recorded as a dataset outcome. ' if source['verification_profile']=='local-dataset-observation-v1' else 'Installed owned-site DNS/TLS controls also passed. ')
           + f"Source identity: {result['source_hash']}.",
        '',f"Transferred archive: {receipt['sha256']}; all {len(inventory)} inventory files verified. SQLite integrity check passed. Exporting left the frozen input files unchanged.",
        '',f"The canonical CSV export has {manifest['rows']} latest committed observations with artifacts, {manifest['dataset_label_capture_eligible']} usable historical-label captures and {manifest['research_eligible']} independently verified-label research rows.",
        '',f"Host monitoring saved {len(timing)} samples; maximum absolute elapsed drift {summary['maximum_absolute_elapsed_drift_seconds']:.3f} seconds, maximum probe roundtrip {summary['maximum_roundtrip_seconds']:.3f} seconds, minimum available host RAM {summary['minimum_host_available_ram_gib']:.3f} GiB.",
        '', 'These observations establish execution and measured capture quality under this configuration. They do not establish current phishing status, authoritative DNS control, live classifier accuracy or reliability beyond the measured run.',
        '', 'See analysis/summary.json for per-outcome counts, metadata coverage, exact stopping reasons, cleanup checks and export hashes. The export is under analysis/export/.']
    if recovery is not None:
        lines += ['', 'The initial freeze was taken while services were still running. This analysis uses a separately hashed post-shutdown recovery archive. '
            'Recovery used an Internet-blocked overlay and did not start collection. The collector committed its final signal stop and clean browser lifecycle, '
            'but the root controller final report is absent. This remains a failed supervised phase; no controller cleanup approval is inferred from a later cold boot.']
    (folder/'PILOT_REPORT.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({k:summary[k] for k in ('pilot_status','collection_activation','counts','collector_stop_reason','export_manifest','timing_samples')},indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path)
    parser.add_argument('--recovery',type=Path)
    args=parser.parse_args()
    run(args.folder,args.recovery)
