"""Bound prior attempted identities into a continuation of the same reserve.

All prior attempted URLs are excluded equally, irrespective of outcome. No new
candidate, prediction, feature value or preliminary reachability is consulted.
Prior evidence remains separate; this phase never fabricates prior captures.
"""
import re

HASH = re.compile(r'^[a-f0-9]{64}$')

def validate_continuation(value, max_attempts, allowed_ids=None, *, attempt_limit=400):
    if value is None:
        return ()
    keys = {'schema_version','attempts_used','attempt_limit','candidate_ids','receipts'}
    if attempt_limit == 800:
        keys.add('usable_phishing')
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('typed_continuation_record_required')
    used, limit = value['attempts_used'], value['attempt_limit']
    ids, receipts = value['candidate_ids'], value['receipts']
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or type(used) is not int or type(limit) is not int or limit != attempt_limit
            or type(attempt_limit) is not int or attempt_limit not in (400,800)
            or not 1 <= used < limit or not 1 <= max_attempts <= limit-used
            or not isinstance(ids,list) or not ids or len(ids)>used or len(ids)>limit
            or any(not isinstance(item,str) or not HASH.fullmatch(item) for item in ids)
            or ids != sorted(set(ids)) or not isinstance(receipts,list) or not receipts):
        raise ValueError('continuation_exceeds_original_budget_or_has_invalid_ids')
    receipt_keys = {'run_id','source_hash','archive_sha256','attempts'}
    if attempt_limit == 800:
        receipt_keys.add('usable_phishing')
    for receipt in receipts:
        if (not isinstance(receipt,dict) or set(receipt) != receipt_keys
                or not isinstance(receipt['run_id'],str) or not re.fullmatch('[a-zA-Z0-9-]{1,50}',receipt['run_id'])
                or any(not isinstance(receipt[key],str) or not HASH.fullmatch(receipt[key]) for key in ('source_hash','archive_sha256'))
                or type(receipt['attempts']) is not int or receipt['attempts']<=0):
            raise ValueError('frozen_prior_phase_receipts_required')
    if sum(item['attempts'] for item in receipts) != used or len({r['run_id'] for r in receipts}) != len(receipts):
        raise ValueError('prior_attempt_total_or_phase_identity_changed')
    if attempt_limit == 800:
        usable = value['usable_phishing']
        if (type(usable) is not int or not 0 <= usable < 59 or usable > len(ids)
                or any(type(r['usable_phishing']) is not int or not 0 <= r['usable_phishing'] <= r['attempts'] for r in receipts)
                or sum(r['usable_phishing'] for r in receipts) != usable):
            raise ValueError('completion_usable_progress_or_receipt_total_changed')
    if allowed_ids is not None and not set(ids).issubset(allowed_ids):
        raise ValueError('prior_attempt_id_outside_frozen_reserve')
    return tuple(ids)


def remaining_phishing_target(continuation, max_attempts):
    validate_continuation(continuation, max_attempts, attempt_limit=800)
    return 59 - (continuation['usable_phishing'] if continuation is not None else 0)

def mark_prior_attempts(queue, continuation, max_attempts, *, attempt_limit=400):
    """Mark completed work in a fresh queue, without copying old measurements."""
    with queue.transaction() as db:
        if db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0] or db.execute('SELECT COUNT(*) FROM runs').fetchone()[0]:
            raise ValueError('continuation_requires_a_fresh_phase_queue')
        ids=validate_continuation(continuation,max_attempts,{r[0] for r in db.execute('SELECT id FROM candidates')},attempt_limit=attempt_limit)
        if db.execute("SELECT COUNT(*) FROM candidates WHERE confidence!='dataset' OR state!='pending'").fetchone()[0]:
            raise ValueError('continuation_requires_unchanged_fresh_dataset_intake')
        db.executemany("UPDATE candidates SET state='done',eligible=0,outcome='previous_phase_attempted' WHERE id=?",[(item,) for item in ids])
    return len(ids)
