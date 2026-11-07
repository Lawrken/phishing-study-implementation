import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
import pandas as pd

from study.phiusiil import (EXPECTED_COLUMNS, FEATURE_SETS, NUMERIC_COLUMNS, PAGE_FEATURES,
                           REFERENCE_FEATURES, assign_components, build_pipeline, clean_urls,
                           load_and_audit, log1p_values, make_splits, metrics, run_dataset)


def source_rows(count=120):
    rows = []
    for i in range(count):
        label = i % 2
        row = {name: "1" for name in EXPECTED_COLUMNS}
        row.update(FILENAME=f"file-{i}.txt", URL=f"https://site{i}.com/account?secret=marker-{i}",
                   Domain=f"site{i}.com", TLD="com", Title=f"Raw private title marker-{i}",
                   label=str(label), LineOfCode=str(200 + i), LargestLineLength=str(10 + i),
                   HasPasswordField=str(label), NoOfJS=str(i % 7))
        rows.append(row)
    return rows


def save_source(path, rows):
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=EXPECTED_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def prepared_frame(path, rows=None):
    save_source(path, source_rows() if rows is None else rows)
    frame, _, _ = load_and_audit(path)
    frame, _ = clean_urls(frame)
    frame, _ = assign_components(frame)
    return frame


class PhiusiilAuditTests(unittest.TestCase):
    def test_documented_schema_and_leaky_features_excluded(self):
        self.assertEqual(len(EXPECTED_COLUMNS), 56)
        self.assertEqual(len(NUMERIC_COLUMNS), 50)
        self.assertEqual(len(PAGE_FEATURES), 26)
        self.assertEqual(len(FEATURE_SETS["combined"]), 45)
        for features in FEATURE_SETS.values():
            self.assertFalse(set(features) & set(REFERENCE_FEATURES + ("URL", "Domain", "label", "FILENAME", "Title", "TLD")))

    def test_label_tokens_and_duplicate_schema_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.csv"
            for label in ("2", "", "0.0", "phishing"):
                rows = source_rows(2)
                rows[0]["label"] = label
                save_source(path, rows)
                with self.assertRaisesRegex(ValueError, "documented integer"):
                    load_and_audit(path)
            path.write_text("URL,URL,label\nhttps://example.com,https://example.com,0\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected dataset schema"):
                load_and_audit(path)

    def test_missing_invalid_nonfinite_negative_are_distinguished(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.csv"
            rows = source_rows(4)
            for row, value in zip(rows, ("", "oops", "inf", "-1")):
                row["NoOfJS"] = value
            save_source(path, rows)
            _, audit, summaries = load_and_audit(path)
            summary = next(value for value in summaries if value["column"] == "NoOfJS")
            self.assertEqual((summary["missing"], summary["invalid_numeric"], summary["nonfinite"], summary["negative"]), (1, 1, 1, 1))
            self.assertEqual(audit["numeric_violations"], ["NoOfJS"])
            output = Path(temporary) / "failed-output"
            with self.assertRaisesRegex(ValueError, "nonfinite or negative"):
                run_dataset(path, output, audit_only=True)
            self.assertEqual(json.loads((output / "audit.json").read_text())["status"], "failed")
            self.assertTrue((output / "column-summary.json").exists())

    def test_canonical_conflicts_all_quarantined_and_same_label_deduplicated(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.csv"
            rows = source_rows(7)
            rows[0]["URL"] = "https://CONFLICT.com:443/a#fragment"
            rows[1]["URL"] = "https://conflict.com/a"
            rows[2]["URL"] = "https://duplicate.com/#one"
            rows[2]["label"] = "0"
            rows[3]["URL"] = "https://duplicate.com/#two"
            rows[3]["label"] = "0"
            rows[4]["URL"] = "file:///private/secret"
            save_source(path, rows)
            frame, _, _ = load_and_audit(path)
            cleaned, exclusions = clean_urls(frame)
            self.assertEqual(len(cleaned), 3)
            self.assertEqual([row["reason"] for row in exclusions], ["canonical_url_label_conflict",
                             "canonical_url_label_conflict", "duplicate_url_same_label", "invalid_canonical_url"])
            self.assertTrue(all(len(row["url_hash"]) == 64 for row in exclusions))
            self.assertFalse(any("URL" in row for row in exclusions))

    def test_label_remapping_phishing_is_positive(self):
        with tempfile.TemporaryDirectory() as temporary:
            frame = prepared_frame(Path(temporary) / "source.csv")
            self.assertTrue(frame.loc[frame["label"].eq(0), "target"].eq(1).all())
            self.assertTrue(frame.loc[frame["label"].eq(1), "target"].eq(0).all())
        result = metrics([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9])
        self.assertEqual(result["confusion_matrix"], [[2, 0], [0, 2]])
        self.assertEqual(result["recall_phishing"], 1.0)

    def test_source_mutation_invalidates_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.csv"
            output = Path(temporary) / "output"
            save_source(source, source_rows(2))
            original = assign_components

            def mutate(frame):
                with source.open("a", encoding="utf-8") as handle:
                    handle.write("\n")
                return original(frame)

            with patch("study.phiusiil.assign_components", side_effect=mutate):
                with self.assertRaisesRegex(ValueError, "source bytes changed"):
                    run_dataset(source, output, audit_only=True)
            audit = json.loads((output / "audit.json").read_text())
            self.assertEqual(audit["status"], "failed")
            self.assertFalse(audit["source_unchanged_after_run"])


class PhiusiilGroupingTests(unittest.TestCase):
    def test_domain_vector_transitive_components_and_private_tenants(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.csv"
            rows = source_rows(120)
            rows[0]["URL"] = "https://first.example.com/a"
            rows[1]["URL"] = "https://second.example.com/b"
            rows[2]["URL"] = "https://different.com/a"
            for name in PAGE_FEATURES:
                rows[2][name] = rows[1][name]
            rows[3]["URL"] = "https://tenant-one.blogspot.com/a"
            rows[4]["URL"] = "https://tenant-two.blogspot.com/a"
            frame = prepared_frame(path, rows)
            self.assertEqual(len(set(frame.iloc[:3]["component_id"])), 1)
            self.assertNotEqual(frame.iloc[3]["domain_group_hash"], frame.iloc[4]["domain_group_hash"])

    def test_grouped_split_repeatable_and_no_url_or_domain_overlap(self):
        with tempfile.TemporaryDirectory() as temporary:
            frame = prepared_frame(Path(temporary) / "source.csv")
            first, report = make_splits(frame)
            second, _ = make_splits(frame)
            for split in first:
                np.testing.assert_array_equal(first[split], second[split])
            self.assertEqual(sum(len(value) for value in first.values()), len(frame))
            self.assertEqual(len(report["overlap_assertions"]), 6)
            self.assertTrue(all(report["overlap_assertions"].values()))
            different, _ = make_splits(frame, 20261011)
            self.assertFalse(np.array_equal(first["test"], different["test"]))

    def test_too_few_independent_groups_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            frame = prepared_frame(Path(temporary) / "source.csv", source_rows(20))
            with self.assertRaisesRegex(ValueError, "thirty independent"):
                make_splits(frame)

    def test_coarse_vector_component_is_audited_without_overmerging_domain_split(self):
        with tempfile.TemporaryDirectory() as temporary:
            rows = source_rows(120)
            for row in rows:
                for name in PAGE_FEATURES:
                    row[name] = "1"
            frame = prepared_frame(Path(temporary) / "source.csv", rows)
            self.assertEqual(frame["component_id"].nunique(), 1)
            _, report = make_splits(frame)
            self.assertEqual(report["strict_component_sensitivity"]["status"], "not_run")
            self.assertTrue(report["strict_component_sensitivity"]["large_component_above_30_percent"])
            self.assertTrue(all(report["overlap_assertions"].values()))
            self.assertEqual(report["additional_overlap_counts"]["train_test_page_vector_hash"], 1)


class PhiusiilModelTests(unittest.TestCase):
    def test_imputation_and_scaling_fit_training_rows_only(self):
        model = build_pipeline("majority")
        model.fit(pd.DataFrame({"feature": [1.0, 3.0, np.nan]}), [0, 1, 0])
        statistics = model.named_steps["imputer"].statistics_.copy()
        mean = model.named_steps["scaler"].mean_.copy()
        model.predict_proba(pd.DataFrame({"feature": [1000000.0, np.nan]}))
        np.testing.assert_allclose(statistics, [(np.log(2) + np.log(4)) / 2])
        np.testing.assert_allclose(model.named_steps["imputer"].statistics_, statistics)
        np.testing.assert_allclose(model.named_steps["scaler"].mean_, mean)
        for invalid in (-1, np.inf):
            with self.assertRaisesRegex(ValueError, "nonnegative and finite"):
                log1p_values(np.array([[invalid]]))

    def test_fresh_output_end_to_end_exports_no_urls_or_titles(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.csv"
            output = Path(temporary) / "output"
            save_source(source, source_rows(120))
            audit = run_dataset(source, output)
            self.assertEqual(audit["status"], "baseline_complete")
            self.assertEqual(audit["endpoint_visits"], 0)
            self.assertEqual(audit["retained_rows"], 120)
            self.assertEqual(len(json.loads((output / "metrics.json").read_text())), 3)
            selection = json.loads((output / "selected-model.json").read_text())
            self.assertEqual(selection["feature_names"], list(PAGE_FEATURES))
            self.assertFalse(selection["test_used_for_selection"])
            features = pd.read_parquet(output / "quality-features.parquet")
            self.assertFalse(set(features.columns) & {"URL", "Domain", "Title", "FILENAME", "label"})
            for artifact in output.iterdir():
                if artifact.suffix in {".json", ".csv", ".md"}:
                    text = artifact.read_text(encoding="utf-8")
                    self.assertNotIn("https://site", text)
                    self.assertNotIn("secret=marker", text)
                    self.assertNotIn("Raw private title", text)
            with self.assertRaisesRegex(ValueError, "must not already exist"):
                run_dataset(source, output)


if __name__ == "__main__":
    unittest.main()
