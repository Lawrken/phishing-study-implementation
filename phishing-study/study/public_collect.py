"""Unprivileged entry point for the separately approved, source-labelled pilot."""
import argparse
import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import pwd
import time

from .deployment import file_hash, secure_root_file, source_files
from .deployment_checks import resolver_valid, resource_limits
from .public_web import LISTEN, public_identity, validate_public_bundle, validate_public_evidence, validate_public_evidence_files
from .public_web import PROFILE, OBSERVATION_PROFILE, validate_execution_evidence

APP = Path(__file__).resolve().parents[1]
DATA = Path('/var/lib/phishing-study-public')


def health_receipt(path, identity, *, now=None):
    """The collector cannot write this root-owned, short-lived receipt."""
    path = secure_root_file(path)
    value = json.loads(path.read_text())
    now = time.time() if now is None else now
    return (value.get('identity') == identity and value.get('healthy') is True
        and type(value.get('timestamp')) in (int, float)
        and 0 <= now - value['timestamp'] <= 5
        and isinstance(value.get('checks'), dict) and bool(value['checks'])
        and all(item is True for item in value['checks'].values()))


async def execute(bundle, output, activation_path, *, observation=False):
    from .queue import Queue
    from .sources import read_dataset_intake
    from .runner import collect
    from .export import export
    from .analysis import dataset_label_report
    manifest = validate_public_bundle(bundle, root=APP)
    if manifest['verification_profile'] != (OBSERVATION_PROFILE if observation else PROFILE):
        raise ValueError('collector_entry_point_purpose_mismatch')
    for path in (bundle / 'deployment.json', *source_files(APP)):
        secure_root_file(path)
    activation = json.loads(secure_root_file(activation_path).read_text())
    identity = public_identity(manifest)
    if (activation.get('identity') != identity or activation.get('activation_allowed') is not True
            or not 0 <= time.time() - activation.get('created', 0) <= 300):
        raise ValueError('fresh_root_activation_required')
    evidence = json.loads(secure_root_file(activation['evidence']).read_text())
    validate_execution_evidence(manifest, evidence)
    validate_public_evidence_files(evidence)
    if file_hash(activation['evidence']) != activation['evidence_sha256']:
        raise ValueError('activation_evidence_changed')
    uid = manifest['study_uid']
    if (os.geteuid() != uid or os.getegid() != pwd.getpwuid(uid).pw_gid or 0 in os.getgroups()):
        raise ValueError('dedicated_unprivileged_collection_account_required')
    resources = resource_limits()
    if not resources['ok'] or int(resources.get('memory_max', '0')) > 2147483648:
        raise ValueError('verified_resource_bounds_required')
    if not resolver_valid(Path('/etc/resolv.conf').read_text(), Path('/etc/nsswitch.conf').read_text(), LISTEN):
        raise ValueError('bound_local_resolver_required')
    intake = secure_root_file(activation['intake'])
    csv = secure_root_file(activation['candidates'])
    if file_hash(intake) != manifest['intake_manifest_hash']:
        raise ValueError('frozen_intake_changed')
    health = Path(activation['health'])
    async def healthy():
        return health_receipt(health, identity)
    deadline = time.monotonic() + 8
    while not await healthy() and time.monotonic() < deadline:
        await asyncio.sleep(.05)
    if not await healthy():
        raise ValueError('working_logged_dns_and_guard_required_before_browser')
    if output.exists() or not output.resolve().is_relative_to(DATA):
        raise ValueError('fresh_dedicated_dataset_required')
    queue = Queue(output)
    queue.ingest(read_dataset_intake(csv, intake))
    from .config import load
    config = replace(load(bundle / 'pilot.template.toml'), network_isolation_verified=True)
    config.validate()
    if manifest.get('continuation') is not None:
        from .campaign_continuation import mark_prior_attempts
        mark_prior_attempts(queue,manifest['continuation'],config.max_attempts,
                            attempt_limit=800 if manifest.get('completion') else 400)
    try:
        rid = await collect(queue, config, health_check=healthy)
    finally:
        exported = export(queue, output / 'export')
        dataset_label_report(queue, output / 'export/features.parquet', output / 'quality')
        (output / 'operational-result.json').write_text(json.dumps({
            'status': queue.status(), 'export': exported, 'identity': identity,
            'research_eligible_policy': 'unchanged; published labels are separate',
            'models_retrained': False}, indent=2))
    return rid


def main(argv=None, *, observation=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    activation = os.environ.get('STUDY_PUBLIC_ACTIVATION')
    if not activation:
        parser.error('root activation receipt required')
    from .browser_lifecycle import run_bounded
    report = {'checks': {}}
    try:
        run_bounded(execute(args.bundle, args.output, Path(activation), observation=observation), timeout=7200, cleanup_seconds=60, report=report)
    finally:
        if args.output.exists():
            (args.output / 'supervisor-report.json').write_text(json.dumps(report, indent=2))
    if report.get('lifecycle', {}).get('pending_tasks_at_loop_close') != 0:
        raise RuntimeError('collector_event_loop_not_quiescent')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
