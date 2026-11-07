"""Offline assignment invariants. No real dataset, browser or network needed."""
from copy import deepcopy
import unittest

from split_dataset import assign_groups, check_assignments, ordered_records


def row(index, group, label='legitimate', partition='train'):
    return {'source_row':index,'row_id':str(index),'url_hash':'url-'+str(index),
        'domain_group_hash':group,'label':label,'split':partition}


class SplitTests(unittest.TestCase):
    def test_groups_and_mixed_labels_stay_together_and_every_row_is_covered(self):
        rows=[row(1,'same','legitimate'),row(2,'same','phishing')]
        rows += [row(i,'g'+str(i),'phishing' if i%2 else 'legitimate') for i in range(3,55)]
        assignments,details=assign_groups(rows,20261010)
        checks=check_assignments(assignments,rows)
        self.assertTrue(checks['cleaned_population_covered_exactly'])
        self.assertEqual(details['mixed_label_domain_groups'],1)
        owners=[slot for slot,shard in enumerate(assignments) for r in shard if r['domain_group_hash']=='same']
        self.assertEqual(len(set(owners)),1)

    def test_assignment_does_not_depend_on_input_order(self):
        rows=[row(i,'g'+str(i//3),'phishing' if i%2 else 'legitimate') for i in range(30)]
        a,_=assign_groups(rows,20261010);b,_=assign_groups(list(reversed(rows)),20261010)
        self.assertEqual([{r['row_id'] for r in x} for x in a],[{r['row_id'] for r in x} for x in b])
        self.assertEqual([[r['row_id'] for r in ordered_records(x,20261010)] for x in a],
                         [[r['row_id'] for r in ordered_records(x,20261010)] for x in b])

    def test_balanced_prefix_order_retains_all_majority_rows(self):
        rows=[row(i,'g'+str(i),'legitimate' if i<7 else 'phishing') for i in range(10)]
        ordered=list(ordered_records(rows,20261010))
        self.assertEqual([r['label'] for r in ordered[:6]],['legitimate','phishing']*3)
        self.assertEqual(len(ordered),10)
        self.assertEqual({r['row_id'] for r in ordered},{r['row_id'] for r in rows})

    def test_partition_and_published_labels_are_unchanged(self):
        rows=[row(i,'g'+str(i),'phishing' if i%2 else 'legitimate',
                  ('train','validation','test')[i%3]) for i in range(60)]
        before=deepcopy(rows);assignments,_=assign_groups(rows,20261010)
        self.assertEqual(rows,before)
        originals={r['row_id']:r for r in rows}
        for shard in assignments:
            for r in shard:
                self.assertEqual(r['split'],originals[r['row_id']]['split'])
                self.assertEqual(r['label'],originals[r['row_id']]['label'])

    def test_overlap_or_missing_rows_are_rejected(self):
        rows=[row(1,'a'),row(2,'b')]
        for assignments in (([rows[0]],[rows[0],rows[1]]),([rows[0]],[])):
            with self.assertRaises(ValueError):check_assignments(assignments,rows)


if __name__=='__main__':unittest.main()
