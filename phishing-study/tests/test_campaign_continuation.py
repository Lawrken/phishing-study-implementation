import copy
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from study.campaign_continuation import validate_continuation,mark_prior_attempts,remaining_phishing_target
from study.config import Config
from study.queue import Queue
from study.urls import digest,canonical_url

class ContinuationTests(unittest.TestCase):
    def completion(self):
        value=copy.deepcopy(self.value)
        value.update(attempt_limit=800,usable_phishing=1)
        value['receipts'][0]['usable_phishing']=1
        return value

    def test_completion_remaining_quota_is_bound_to_preserved_successes(self):
        from study.public_web import collection_config
        try:
            from .test_phiusiil_completion import contract
        except ImportError:
            from test_phiusiil_completion import contract
        value=self.completion()
        value['usable_phishing']=value['receipts'][0]['usable_phishing']=14
        value['candidate_ids']=sorted(set(value['candidate_ids'])|{digest('prior-'+str(i)) for i in range(14)})
        self.assertEqual(remaining_phishing_target(value,628),45)
        self.assertEqual(collection_config('Laoag City, Philippines',628,45,contract(),value).usable_per_class,45)
        with self.assertRaises(ValueError):collection_config('Laoag City, Philippines',628,59,contract(),value)

    def test_completion_progress_receipts_cannot_change_total_or_type(self):
        for progress in (True,15,59,-1):
            value=self.completion();value['usable_phishing']=progress
            with self.assertRaises(ValueError):remaining_phishing_target(value,628)

    def test_completion_attempt_cap_is_cumulative_and_old_route_rejects_it(self):
        value=self.completion()
        with self.assertRaises(ValueError):validate_continuation(value,629,attempt_limit=800)
        with self.assertRaises(ValueError):validate_continuation(value,228)

    def test_completion_marking_never_fabricates_earlier_captures(self):
        mark_prior_attempts(self.queue,self.completion(),628,attempt_limit=800)
        with self.queue.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM candidates WHERE eligible=1').fetchone()[0],0)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]);self.addCleanup(self.temp.cleanup)
        self.queue=Queue(Path(self.temp.name)/'dataset')
        self.rows=[{'url':'https://example.com/'+name,'label':label,'confidence':'dataset',
            'source':'phiusiil-dataset','source_id':char*64,'observed_at':'unknown'}
            for name,label,char in [('a','legitimate','a'),('b','phishing','b'),('c','legitimate','c')]]
        with patch('study.queue.domain_group',return_value='example.com'):
            self.queue.ingest(self.rows)
        self.ids=[digest(canonical_url(row['url'])) for row in self.rows]
        self.value={'schema_version':1,'attempts_used':172,'attempt_limit':400,
            'candidate_ids':sorted(self.ids[:2]),'receipts':[{'run_id':'prior-1','source_hash':'a'*64,
                'archive_sha256':'b'*64,'attempts':172}]}

    def test_continuation_uses_only_new_urls_without_fabricating_prior_captures(self):
        self.assertEqual(mark_prior_attempts(self.queue,self.value,228),2)
        with self.queue.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM candidates WHERE eligible=1').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM provenance').fetchone()[0],3)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM candidates WHERE state='done' AND outcome='previous_phase_attempted'").fetchone()[0],2)
        config=Config(max_attempts=228,domain_cooldown_seconds=0)
        rid=self.queue.start_run(config)
        self.assertEqual(self.queue.claim(rid,config)['id'],self.ids[2])

    def test_original_attempt_ceiling_and_typed_receipts_are_required(self):
        self.assertEqual(validate_continuation(self.value,228),tuple(sorted(self.ids[:2])))
        with self.assertRaises(ValueError):validate_continuation(self.value,229)
        for key,value in [('attempts_used',True),('attempt_limit',401),('schema_version',True),
                          ('candidate_ids',[self.ids[0],self.ids[0]]),('receipts',[])]:
            changed={**self.value,key:value}
            with self.subTest(key=key),self.assertRaises(ValueError):validate_continuation(changed,228)

    def test_changed_receipt_totals_source_identity_or_duplicate_phases_fail(self):
        for mutation in ('total','hash','duplicate'):
            value=copy.deepcopy(self.value)
            if mutation=='total':value['receipts'][0]['attempts']=171
            elif mutation=='hash':value['receipts'][0]['archive_sha256']='unverified'
            else:value['receipts']*=2
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):validate_continuation(value,228)

    def test_unknown_candidate_does_not_partially_change_queue(self):
        value={**self.value,'candidate_ids':['f'*64]}
        with self.assertRaisesRegex(ValueError,'outside_frozen_reserve'):
            mark_prior_attempts(self.queue,value,228)
        with self.queue.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM candidates WHERE state='pending'").fetchone()[0],3)

    def test_continuation_cannot_be_applied_twice_or_to_an_existing_run(self):
        mark_prior_attempts(self.queue,self.value,228)
        with self.assertRaises(ValueError):mark_prior_attempts(self.queue,self.value,228)
        self.queue.start_run(Config())
        with self.assertRaises(ValueError):mark_prior_attempts(self.queue,self.value,228)

if __name__=='__main__':unittest.main()
