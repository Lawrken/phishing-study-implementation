"""Statistical code-path checks with temporary synthetic rows; no research claims."""
import json
from pathlib import Path
import tempfile
import unittest
from study.analysis import analyze, train
from study.features import FEATURES


class StatisticalTests(unittest.TestCase):
    def make_data(self, path, per_class=40, mixed=False):
        import numpy as np
        import pandas as pd
        rng = np.random.default_rng(7)
        rows = []
        for label in ("legitimate","phishing"):
            for i in range(per_class):
                for repeat in range(2):
                    row = {"candidate_id":f"synthetic-{label}-{i}-{repeat}","label":label,"profile":"live", "research_eligible":True,
                           "capture_eligible":True,"outcome":"captured","config_hash":"config2" if mixed and i==0 else "config1",
                           "split_group":f"synthetic-{label}-{i}"}
                    row.update({feature: float(rng.normal() + (label=="phishing")) for feature in FEATURES})
                    rows.append(row)
        pd.DataFrame(rows).to_parquet(path,index=False)

    def test_descriptive_comparisons_group_resampling(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/"synthetic.parquet"
            self.make_data(p,per_class=12)
            report = analyze(p,Path(temp)/"out",bootstrap=30)
            self.assertEqual(report["status"],"descriptive_comparisons")
            self.assertEqual(report["comparisons"][0]["legitimate_groups"],12)
            self.assertTrue(all(0<=row["fdr_q_value"]<=1 for row in report["comparisons"]))

    def test_mixed_protocols_are_not_combined(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/"synthetic.parquet"
            self.make_data(p,per_class=12,mixed=True)
            report = analyze(p,Path(temp)/"out",bootstrap=10)
            self.assertEqual(report["status"],"mixed_configurations_analyze_separately")
            self.assertEqual(report["comparisons"],[])

    def test_models_use_disjoint_groups(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/"synthetic.parquet"
            self.make_data(p)
            result = train(p,Path(temp)/"out")
            split = json.loads((Path(temp)/"out/holdout.json").read_text())
            a = {value.rsplit("-",1)[0] for value in split["train"]}
            b = {value.rsplit("-",1)[0] for value in split["test"]}
            self.assertFalse(a & b)
            self.assertEqual(len(result["models"]),2)

    def test_mixed_label_groups_are_not_treated_as_independent(self):
        import pandas as pd
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/"synthetic.parquet"
            self.make_data(p,per_class=12)
            df = pd.read_parquet(p)
            df.loc[df["split_group"].eq("synthetic-phishing-0"),"split_group"] = "synthetic-legitimate-0"
            df.to_parquet(p,index=False)
            result = analyze(p,Path(temp)/"out",bootstrap=10)
            self.assertEqual(result["mixed_label_groups_excluded_from_comparisons"],1)
            self.assertEqual(result["independent_groups"]["phishing"],11)

    def test_empty_export(self):
        import pandas as pd
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/"empty.parquet"
            pd.DataFrame({"candidate_id":[],"label":[]}).to_parquet(p)
            self.assertEqual(analyze(p,Path(temp)/"out")["status"],"no_observations")
