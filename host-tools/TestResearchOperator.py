"""Host control regressions; these never boot a VM or open a website."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ResearchOperator as operator


class OperatorControlTests(unittest.TestCase):
    def test_first_run_creates_missing_output_parent_and_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parent, preparation = operator.prepare_run_directory(root, 'operator-new')
            self.assertTrue(parent.is_dir())
            self.assertTrue(preparation.is_dir())
            (preparation/'preserved.txt').write_text('original')
            with self.assertRaises(FileExistsError):
                operator.prepare_run_directory(root, 'operator-new')
            self.assertEqual((preparation/'preserved.txt').read_text(), 'original')

    def test_continuation_preserves_all_attempted_ids_and_receipts(self):
        prior = operator.continuation_record(None, 'operator-first', 'a'*64, 'b'*64,
                                             10, ['c'*64, 'd'*64], 10)
        continued = operator.continuation_record(prior, 'operator-second', 'e'*64, 'f'*64,
                                                 10, ['0'*64], 10)
        self.assertEqual(continued['attempts_used'], 20)
        self.assertEqual(set(continued['candidate_ids']), {'c'*64, 'd'*64, '0'*64})
        self.assertEqual(len(continued['receipts']), 2)

    def test_continuation_rejects_repeat_endpoints_and_budget_expansion(self):
        prior = operator.continuation_record(None, 'operator-first', 'a'*64, 'b'*64,
                                             10, ['c'*64], 10)
        with self.assertRaises(ValueError):
            operator.continuation_record(prior, 'operator-second', 'e'*64, 'f'*64,
                                         10, ['c'*64], 10)
        with self.assertRaises(ValueError):
            operator.continuation_record(None, 'operator-first', 'a'*64, 'b'*64,
                                         395, ['c'*64], 10)

    def test_completed_controller_counts_survive_dataset_freezing(self):
        final = {'attempts': 10, 'distinct_urls_attempted': 10, 'failed_attempts': 5,
                 'unfinished_attempts': 0, 'usable_per_class': {'legitimate': 4, 'phishing': 1},
                 'collector_stop_reason': 'attempt_budget'}
        self.assertEqual(operator.supervisor.reconcile_counts({'pilot_counts': {'attempts': 0},
                         'pilot_report': final}), final)

    def test_incomplete_report_does_not_replace_live_counts(self):
        counts = {'attempts': 3}
        self.assertEqual(operator.supervisor.reconcile_counts({'pilot_counts': counts,
                         'pilot_report': {'status': 'running'}}), counts)

    def test_attempt_limits_cannot_be_expanded_or_untyped(self):
        for value in (0, 401, -1, True, 1.0, '10', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                operator.bounded_attempts(value)
        for value in (1, 10, 400):
            self.assertEqual(operator.bounded_attempts(value), value)

    def test_current_run_pointer_cannot_escape_validation_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            control = root / '.operator'; control.mkdir()
            (control / 'current.json').write_text(json.dumps({'folder': '../outside', 'run_id': 'operator-test'}))
            with patch.object(operator, 'ROOT', root), patch.object(operator, 'CONTROL', control), self.assertRaises(ValueError):
                operator.current()

    def test_stop_uses_own_run_request_and_does_not_stop_other_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            control = root / '.operator'; control.mkdir()
            folder = root / 'phishing-study/validation/operator-test'; folder.mkdir(parents=True)
            (control / 'current.json').write_text(json.dumps({'folder': str(folder.relative_to(root)), 'run_id': 'operator-test'}))
            with patch.object(operator, 'ROOT', root), patch.object(operator, 'CONTROL', control), patch('sys.argv', ['operator', 'stop']):
                self.assertEqual(operator.main(), 0)
            self.assertTrue((folder / 'operator-stop.request').is_file())

    def test_stopping_finished_run_does_not_add_stop_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            control = root / '.operator'; control.mkdir()
            folder = root / 'phishing-study/validation/operator-test'; folder.mkdir(parents=True)
            (folder / 'result.json').write_text('{}')
            (control / 'current.json').write_text(json.dumps({'folder': str(folder.relative_to(root)), 'run_id': 'operator-test'}))
            with patch.object(operator, 'ROOT', root), patch.object(operator, 'CONTROL', control), patch('sys.argv', ['operator', 'stop']):
                self.assertEqual(operator.main(), 0)
            self.assertFalse((folder / 'operator-stop.request').exists())


if __name__ == '__main__': unittest.main()
