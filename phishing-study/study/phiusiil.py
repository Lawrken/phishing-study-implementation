"""Offline, grouped baselines for the supplied PhiUSIIL feature table.

This module does not visit URLs or create collector observations. Dataset labels
are external labels, not independent live-observation reviews.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path
import time

from .urls import canonical_url, digest, domain_group


SEED = 20261010
PROTOCOL = "phiusiil-offline-v1"
PAGE_FEATURES = (
    "LineOfCode", "LargestLineLength", "HasTitle", "HasFavicon", "Robots", "IsResponsive",
    "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription", "NoOfPopup", "NoOfiFrame",
    "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton", "HasHiddenFields",
    "HasPasswordField", "Bank", "Pay", "Crypto", "HasCopyrightInfo", "NoOfImage", "NoOfCSS",
    "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
)
URL_FEATURES = (
    "URLLength", "DomainLength", "IsDomainIP", "CharContinuationRate", "TLDLength",
    "NoOfSubDomain", "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL", "IsHTTPS",
)
REFERENCE_FEATURES = ("URLSimilarityIndex", "TLDLegitimateProb", "URLCharProb",
                      "DomainTitleMatchScore", "URLTitleMatchScore")
STRING_COLUMNS = ("FILENAME", "URL", "Domain", "TLD", "Title")
NUMERIC_COLUMNS = URL_FEATURES + PAGE_FEATURES + REFERENCE_FEATURES
EXPECTED_COLUMNS = STRING_COLUMNS + NUMERIC_COLUMNS + ("label",)
FEATURE_SETS = {"page": PAGE_FEATURES, "url": URL_FEATURES, "combined": URL_FEATURES + PAGE_FEATURES}
MODEL_NAMES = ("majority", "logistic", "hist_gradient_boosting")
EXCLUSION_FIELDS = ("source_row", "row_id", "url_hash", "reason")


def progress(stage, **details):
    print(json.dumps({"stage": stage, **details}, sort_keys=True), flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def save_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def write_csv(path, fields, rows):
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def source_identity(path):
    path = Path(path)
    return {"sha256": sha256_file(path), "bytes": path.stat().st_size,
            "filename": path.name, "dataset": "PhiUSIIL Phishing URL Dataset",
            "label_mapping": {"source_0": "phishing", "source_1": "legitimate",
                              "model_positive_1": "phishing", "model_negative_0": "legitimate"}}


def load_and_audit(path, source=None):
    """Return a typed frame, an audit and column summaries; reject unsafe types."""
    import numpy as np
    import pandas as pd

    source = source or source_identity(path)
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        header = next(csv.reader(handle), [])
    if len(header) != len(set(header)) or set(header) != set(EXPECTED_COLUMNS):
        raise ValueError("unexpected dataset schema: missing=" + str(sorted(set(EXPECTED_COLUMNS) - set(header)))
                         + "; unexpected=" + str(sorted(set(header) - set(EXPECTED_COLUMNS))))
    frame = pd.read_csv(path, encoding="utf-8-sig", dtype="string", keep_default_na=False)
    if frame.empty:
        raise ValueError("the source contains no observations")
    frame["source_row"] = np.arange(1, len(frame) + 1)
    frame["row_id"] = [digest(source["sha256"] + ":" + str(i)) for i in frame["source_row"]]
    raw_labels = frame["label"].str.strip()
    if not raw_labels.isin(["0", "1"]).all():
        raise ValueError("label must contain only the documented integer tokens 0 and 1")
    frame["label"] = raw_labels.astype("int8")
    summaries = []
    violations = []
    for name in EXPECTED_COLUMNS:
        if name == "label":
            summaries.append({"column": name, "kind": "binary_label", "missing": 0,
                              "distinct": int(frame[name].nunique())})
        elif name in STRING_COLUMNS:
            values = frame[name].str.strip()
            summaries.append({"column": name, "kind": "excluded_string", "missing": int(values.eq("").sum()),
                              "distinct": int(values.nunique())})
        else:
            text = frame[name].str.strip()
            missing = text.eq("") | text.str.lower().isin(["na", "nan", "null", "none"])
            values = pd.to_numeric(text.mask(missing), errors="coerce").astype("float64")
            invalid = ~missing & values.isna()
            nonfinite = values.notna() & ~np.isfinite(values)
            negative = values.notna() & values.lt(0)
            finite = values[np.isfinite(values)]
            summary = {"column": name, "kind": "numeric", "missing": int(missing.sum()),
                       "invalid_numeric": int(invalid.sum()), "nonfinite": int(nonfinite.sum()),
                       "negative": int(negative.sum()), "distinct": int(values.nunique()),
                       "minimum": float(finite.min()) if len(finite) else None,
                       "maximum": float(finite.max()) if len(finite) else None}
            summary["model_role"] = "excluded_reference_derived_unknown_provenance" if name in REFERENCE_FEATURES else (
                "page" if name in PAGE_FEATURES else "url")
            summary["collector_protocol_equivalence_verified"] = False
            if name == "NoOfURLRedirect":
                summary["meaning_limit"] = "Supplied binary indicator in the inspected dataset; not the collector redirect-chain hop count."
            summaries.append(summary)
            if invalid.any() or nonfinite.any() or negative.any():
                violations.append(name)
            frame[name] = values
    audit = {"source": source, "rows": len(frame), "columns": len(header),
             "source_label_counts": {str(k): int(v) for k, v in frame["label"].value_counts().sort_index().items()},
             "numeric_violations": violations, "missing_numeric_cells": sum(s.get("missing", 0)
                   for s in summaries if s["kind"] == "numeric"),
             "raw_url_exports": False, "endpoint_visits": 0,
             "external_dataset_only": True, "live_research_eligibility_assessed": False}
    return frame, audit, summaries


def clean_urls(frame):
    """Deduplicate canonical endpoints; quarantine every conflicting-label row."""
    frame = frame.copy()
    canonical = []
    exclusions = []
    for row in frame.itertuples(index=False):
        raw = row.URL
        try:
            value = canonical_url(raw)
            group = domain_group(value)
            if not group:
                raise ValueError("empty domain group")
            canonical.append((value, group))
        except (ValueError, UnicodeError, TypeError):
            canonical.append((None, None))
            exclusions.append({"source_row": int(row.source_row), "row_id": row.row_id,
                               "url_hash": digest(str(raw)), "reason": "invalid_canonical_url"})
    frame["canonical"] = [value for value, _ in canonical]
    frame["domain_group"] = [group for _, group in canonical]
    frame = frame[frame["canonical"].notna()].copy()
    conflict_urls = set(frame.groupby("canonical")["label"].nunique().loc[lambda x: x > 1].index)
    conflict = frame["canonical"].isin(conflict_urls)
    duplicates = ~conflict & frame.duplicated("canonical", keep="first")
    for row in frame[conflict | duplicates].itertuples(index=False):
        exclusions.append({"source_row": int(row.source_row), "row_id": row.row_id,
                           "url_hash": digest(row.canonical),
                           "reason": "canonical_url_label_conflict" if row.canonical in conflict_urls
                           else "duplicate_url_same_label"})
    frame = frame[~(conflict | duplicates)].reset_index(drop=True)
    frame["url_hash"] = frame["canonical"].map(digest)
    frame["domain_group_hash"] = frame["domain_group"].map(digest)
    frame["target"] = (1 - frame["label"]).astype("int8")
    return frame, sorted(exclusions, key=lambda row: row["source_row"])


class UnionFind:
    def __init__(self, size):
        self.parent = list(range(size))
        self.size = [1] * size

    def find(self, node):
        while self.parent[node] != node:
            self.parent[node] = self.parent[self.parent[node]]
            node = self.parent[node]
        return node

    def union(self, left, right):
        left, right = self.find(left), self.find(right)
        if left == right:
            return
        if self.size[left] < self.size[right]:
            left, right = right, left
        self.parent[right] = left
        self.size[left] += self.size[right]


def assign_components(frame):
    """Join shared domains and identical page vectors before creating folds."""
    import numpy as np
    components = UnionFind(len(frame))
    first_domain, first_vector = {}, {}
    vector_hashes = []
    page_values = frame[list(PAGE_FEATURES)].to_numpy(dtype="float64")
    for i, (domain, values) in enumerate(zip(frame["domain_group_hash"], page_values)):
        # Normalize signed zero and missing representations for stable equality.
        normalized = np.where(values == 0, 0.0, values).astype("<f8")
        normalized[np.isnan(normalized)] = np.nan
        fingerprint = hashlib.sha256(normalized.tobytes()).hexdigest()
        vector_hashes.append(fingerprint)
        if domain in first_domain:
            components.union(i, first_domain[domain])
        else:
            first_domain[domain] = i
        if fingerprint in first_vector:
            components.union(i, first_vector[fingerprint])
        else:
            first_vector[fingerprint] = i
    members = {}
    for i in range(len(frame)):
        members.setdefault(components.find(i), []).append(i)
    identifiers = {}
    row_ids = frame["row_id"].tolist()
    for root, indices in members.items():
        identifiers[root] = digest("|".join(sorted(row_ids[i] for i in indices)))
    frame = frame.copy()
    frame["component_id"] = [identifiers[components.find(i)] for i in range(len(frame))]
    frame["page_vector_hash"] = vector_hashes
    sizes = sorted((len(indices) for indices in members.values()), reverse=True)
    return frame, {"components": len(members), "domain_groups": len(first_domain),
                   "distinct_page_vectors": len(first_vector), "largest_component_rows": sizes[0] if sizes else 0,
                   "largest_component_fraction": sizes[0] / len(frame) if sizes else 0.0,
                   "mixed_label_components": int(frame.groupby("component_id")["target"].nunique().gt(1).sum())}


def make_splits(frame, seed=SEED):
    import numpy as np
    from sklearn.model_selection import StratifiedGroupKFold
    if frame.empty or set(frame["target"].unique()) != {0, 1}:
        raise ValueError("both classes are required after quarantine")
    for target in (0, 1):
        if frame.loc[frame["target"].eq(target), "domain_group_hash"].nunique() < 30:
            raise ValueError("at least thirty independent domain groups per class are required")
    outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    train_val, test = next(outer.split(np.zeros(len(frame)), frame["target"], groups=frame["domain_group_hash"]))
    remaining = frame.iloc[train_val]
    inner = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=seed + 1)
    train_relative, val_relative = next(inner.split(np.zeros(len(remaining)), remaining["target"],
                                                  groups=remaining["domain_group_hash"]))
    indices = {"train": train_val[train_relative], "validation": train_val[val_relative], "test": test}
    report = {"method": "StratifiedGroupKFold: first outer 5-fold test, first inner 4-fold validation",
              "seed": seed, "target_fractions": {"train": 0.6, "validation": 0.2, "test": 0.2},
              "grouping": "registered/private-PSL domain groups; canonical URLs deduplicated",
              "page_vectors": "coarse count vectors are audited, not assumed to identify page templates",
              "splits": {}, "overlap_assertions": {}, "additional_overlap_counts": {}}
    largest_component_fraction = frame["component_id"].value_counts().iloc[0] / len(frame)
    report["strict_component_sensitivity"] = {
        "status": "not_run",
        "largest_component_fraction": float(largest_component_fraction),
        "large_component_above_30_percent": bool(largest_component_fraction > 0.3),
        "reason": "Not run: coarse page-count components overmerge unrelated sites and the giant component constrains balanced five-fold evaluation. Assigning it to training could permit a different, uneven component-disjoint experiment; this report does not establish that all such experiments are infeasible." if largest_component_fraction > 0.3 else
                  "Primary grouping was fixed to domain groups before model outcomes; coarse page vectors are audited and evaluated using a novel-vector subset.",
        "primary_split_choice_made_before_model_metrics": True}
    for name, index in indices.items():
        subset = frame.iloc[index]
        if set(subset["target"].unique()) != {0, 1}:
            raise ValueError("group structure prevents a two-class " + name + " split")
        for target in (0, 1):
            minimum = 15 if name == "train" else 5
            if subset.loc[subset["target"].eq(target), "domain_group_hash"].nunique() < minimum:
                raise ValueError("too few independent domain groups in " + name)
        fraction = len(subset) / len(frame)
        if abs(fraction - report["target_fractions"][name]) > 0.1:
            raise ValueError("a large connected component prevents the prespecified split proportions")
        report["splits"][name] = {"rows": len(subset), "fraction": fraction,
                                  "components": int(subset["component_id"].nunique()),
                                  "domain_groups": int(subset["domain_group_hash"].nunique()),
                                  "phishing": int(subset["target"].sum()),
                                  "legitimate": int(len(subset) - subset["target"].sum())}
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        for column in ("url_hash", "domain_group_hash"):
            zero = not (set(frame.iloc[indices[left]][column]) & set(frame.iloc[indices[right]][column]))
            report["overlap_assertions"][f"{left}_{right}_{column}"] = zero
            if not zero:
                raise ValueError("a leakage grouping crossed the split")
        for column in ("component_id", "page_vector_hash"):
            report["additional_overlap_counts"][f"{left}_{right}_{column}"] = len(
                set(frame.iloc[indices[left]][column]) & set(frame.iloc[indices[right]][column]))
    return indices, report


def log1p_values(values):
    import numpy as np
    values = np.asarray(values, dtype="float64")
    if np.isinf(values).any() or np.any(values < 0):
        raise ValueError("features must be nonnegative and finite when measured")
    return np.log1p(values)


def build_pipeline(model, seed=SEED):
    from sklearn.dummy import DummyClassifier
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import FunctionTransformer, StandardScaler
    estimators = {"majority": lambda: DummyClassifier(strategy="most_frequent"),
                  "logistic": lambda: LogisticRegression(max_iter=1000, class_weight="balanced", random_state=seed),
                  "hist_gradient_boosting": lambda: HistGradientBoostingClassifier(
                      max_iter=150, max_leaf_nodes=15, l2_regularization=1.0,
                      early_stopping=False, random_state=seed)}
    if model not in estimators:
        raise ValueError("unknown prespecified model")
    return Pipeline([("log1p", FunctionTransformer(log1p_values, validate=False)),
                     ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
                     ("scaler", StandardScaler()), ("model", estimators[model]())])


def metrics(y, probability):
    import numpy as np
    from sklearn.metrics import (accuracy_score, average_precision_score, balanced_accuracy_score,
                                 confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score)
    prediction = np.asarray(probability) >= 0.5
    return {"accuracy": float(accuracy_score(y, prediction)),
            "balanced_accuracy": float(balanced_accuracy_score(y, prediction)),
            "f1_phishing": float(f1_score(y, prediction, zero_division=0)),
            "precision_phishing": float(precision_score(y, prediction, zero_division=0)),
            "recall_phishing": float(recall_score(y, prediction, zero_division=0)),
            "roc_auc": float(roc_auc_score(y, probability)),
            "pr_auc_average_precision": float(average_precision_score(y, probability)),
            "confusion_matrix": confusion_matrix(y, prediction, labels=[0, 1]).tolist(),
            "confusion_order": ["legitimate", "phishing"], "threshold": 0.5}


def train_baselines(frame, indices, output, seed=SEED):
    import joblib
    import numpy as np
    output = Path(output)
    results, predictions, selection = {}, {}, None
    for feature_set, names in FEATURE_SETS.items():
        results[feature_set] = {}
        for model_name in MODEL_NAMES:
            progress("model_start", feature_set=feature_set, model=model_name)
            started = time.monotonic()
            model = build_pipeline(model_name, seed)
            train = frame.iloc[indices["train"]]
            model.fit(train[list(names)], train["target"])
            record = {"fit_rows": len(train), "features": list(names), "model": model_name,
                      "fit_and_score_seconds": None}
            for split in ("validation", "test"):
                subset = frame.iloc[indices[split]]
                probability = model.predict_proba(subset[list(names)])[:, list(model.classes_).index(1)]
                record[split] = metrics(subset["target"], probability)
                predictions[(feature_set, model_name, split)] = probability
            record["fit_and_score_seconds"] = round(time.monotonic() - started, 4)
            progress("model_finished", feature_set=feature_set, model=model_name,
                     seconds=record["fit_and_score_seconds"])
            results[feature_set][model_name] = record
            # The primary page-feature family is fixed before outcomes are seen.
            if feature_set == "page":
                score = (record["validation"]["f1_phishing"], record["validation"]["pr_auc_average_precision"])
                if selection is None or score > selection[0]:
                    selection = (score, model_name)
                    joblib.dump(model, output / "selected-page-model.joblib", compress=3)
    selected = selection[1]
    rows = []
    for split in ("validation", "test"):
        subset = frame.iloc[indices[split]]
        probability = predictions[("page", selected, split)]
        for row, p in zip(subset.itertuples(index=False), probability):
            rows.append({"source_row": int(row.source_row), "row_id": row.row_id, "url_hash": row.url_hash,
                         "domain_group_hash": row.domain_group_hash, "component_id": row.component_id,
                         "split": split, "truth_phishing": int(row.target), "probability_phishing": float(p),
                         "prediction_phishing": int(p >= 0.5)})
    write_csv(output / "predictions.csv", ("source_row", "row_id", "url_hash", "domain_group_hash", "component_id",
                                          "split", "truth_phishing", "probability_phishing", "prediction_phishing"), rows)
    selection_record = {"feature_set": "page", "model": selected,
                        "protocol": PROTOCOL,
                        "criterion": "validation F1 (phishing positive), then validation average precision; fixed model order breaks ties",
                        "test_used_for_selection": False, "feature_names": list(PAGE_FEATURES),
                        "preprocessing_fit_split": "train", "refit_on_validation": False,
                        "label_mapping": {"0": "legitimate", "1": "phishing"},
                        "model_file": "selected-page-model.joblib", "model_sha256": sha256_file(output / "selected-page-model.joblib"),
                        "joblib_loading": "Load only this locally produced trusted artifact; pickle/joblib files can execute code."}
    test = frame.iloc[indices["test"]]
    stress_mask = (test["IsHTTPS"].eq(1) & test["URLLength"].le(57)
                   & test["LineOfCode"].ge(102) & test["HasTitle"].eq(1)).to_numpy()
    stress = {"purpose": "post-hoc descriptive sensitivity to dataset acquisition artifacts; not model selection",
              "definition": "IsHTTPS == 1 and URLLength <= 57 and LineOfCode >= 102 and HasTitle == 1",
              "threshold_origin": "exploratory supplied-dataset audit of legitimate-class support, before model fitting",
              "rows": int(stress_mask.sum()), "phishing": int(test.loc[stress_mask, "target"].sum()),
              "legitimate": int(stress_mask.sum() - test.loc[stress_mask, "target"].sum()),
              "metrics": None}
    if set(test.loc[stress_mask, "target"].unique()) == {0, 1}:
        stress["metrics"] = metrics(test.loc[stress_mask, "target"],
                                    predictions[("page", selected, "test")][stress_mask])
    training_vectors = set(frame.iloc[indices["train"]]["page_vector_hash"])
    novel = {"definition": "page-vector hash absent from training rows; identical vectors use all 26 page features",
             "purpose": "descriptive heldout sensitivity without fitting or model selection",
             "metrics": {}}
    for split in ("validation", "test"):
        subset = frame.iloc[indices[split]]
        mask = ~subset["page_vector_hash"].isin(training_vectors).to_numpy()
        value = {"rows": int(mask.sum()), "coverage": float(mask.mean()),
                 "phishing": int(subset.loc[mask, "target"].sum()),
                 "legitimate": int(mask.sum() - subset.loc[mask, "target"].sum()), "metrics": None}
        if set(subset.loc[mask, "target"].unique()) == {0, 1}:
            value["metrics"] = metrics(subset.loc[mask, "target"], predictions[("page", selected, split)][mask])
        novel["metrics"][split] = value
    save_json(output / "sensitivity.json", {"shared_support_posthoc": stress, "novel_page_vectors": novel})
    save_json(output / "metrics.json", results)
    save_json(output / "selected-model.json", selection_record)
    return results, selection_record


def report_markdown(audit, splits=None, results=None, selection=None):
    lines = ["# PhiUSIIL offline baseline", "", f"Source SHA-256: `{audit['source']['sha256']}`.", "",
             f"Loaded {audit['rows']:,} source rows; retained {audit.get('retained_rows', 0):,} canonical endpoints.",
             f"Quarantined/deduplicated {audit.get('excluded_rows', 0):,} rows. Endpoint visits: 0.", ""]
    if results:
        lines += ["The primary model uses 26 supplied page/DOM/resource/redirect features. Phishing is the positive class.", "",
                  "| Feature set | Model | Validation F1 | Test F1 | Test precision | Test recall | Test ROC AUC | Test AP |",
                  "|---|---|---:|---:|---:|---:|---:|---:|"]
        for family, models in results.items():
            for name, value in models.items():
                test = value["test"]
                lines.append(f"| {family} | {name} | {value['validation']['f1_phishing']:.5f} | "
                             f"{test['f1_phishing']:.5f} | {test['precision_phishing']:.5f} | "
                             f"{test['recall_phishing']:.5f} | {test['roc_auc']:.5f} | {test['pr_auc_average_precision']:.5f} |")
        lines += ["", f"Selected primary model: **{selection['model']}**, using validation F1 then average precision.",
                  "Test outcomes were not used to select or refit it.", ""]
    lines += ["This is an external feature-table experiment. It does not validate the live collector or prove performance on current websites.",
              "The table supplies no raw HTTP response headers, ordered request sequences, TLS certificates or DNS answers.",
              "NoOfURLRedirect is a supplied binary indicator in this dataset, not a measured redirect-chain hop count; acquisition details do not match the collector protocol by assumption.",
              "Acquisition times, source/brand-heldout replication, independent label re-review and collector-equivalent measurements remain unavailable.",
              "Raw URL, domain, title and filename columns, plus five reference-derived similarity/probability features, are excluded from all models.",
              "Canonical URLs are deduplicated; conflicting labels are quarantined. Registered/private-suffix domains cannot cross folds.",
              "Coarse page-count vectors are not verified template identities. Domain-plus-vector components overmerge unrelated sites, including a giant component; they are audited but are not the primary split groups. This choice preceded model metrics.",
              "Identical page-vector overlap is reported separately, with selected-model sensitivity on test vectors absent from training.",
              "The split is approximately 60/20/20 because domain groups remain intact. Imputation and scaling are fitted only on training rows.",
              "This table reports exploratory point estimates; supplementary domain-bootstrap intervals can be saved separately. Dataset collection artifacts may permit easier classification.",
              "The supplied legitimate class uses HTTPS throughout and has short URLs and much larger pages than many phishing rows; grouped heldout success can still reflect source/acquisition bias.",
              "A separate post-hoc sensitivity result restricts the test subset to HTTPS, URL length <= 57, line count >= 102 and title presence. Its thresholds came from the exploratory audit and must not be interpreted as an independent confirmatory evaluation.",
              "Hashed identifiers support audit and are not anonymization against guessing.", ""]
    return "\n".join(lines)


def run_dataset(input_path, output_path, seed=SEED, audit_only=False):
    output = Path(output_path)
    if output.exists():
        raise ValueError("output directory must not already exist")
    output.mkdir(parents=True, mode=0o700)
    started = time.monotonic()
    audit = {"status": "incomplete", "source": source_identity(input_path), "endpoint_visits": 0}
    try:
        progress("load_and_audit")
        frame, audit, columns = load_and_audit(input_path, audit["source"])
        audit["protocol"] = PROTOCOL
        audit["method_choice"] = "Primary domain/private-PSL grouping selected before model metrics because coarse identical page-count vectors overmerge unrelated sites; strict connected components remain audited."
        save_json(output / "column-summary.json", columns)
        if audit["numeric_violations"]:
            raise ValueError("invalid, nonfinite or negative numeric features: " + ", ".join(audit["numeric_violations"]))
        progress("canonicalize_and_deduplicate", source_rows=len(frame))
        frame, exclusions = clean_urls(frame)
        write_csv(output / "exclusions.csv", EXCLUSION_FIELDS, exclusions)
        audit["retained_rows"] = len(frame)
        audit["excluded_rows"] = len(exclusions)
        audit["exclusion_counts"] = {reason: sum(row["reason"] == reason for row in exclusions)
                                     for reason in sorted({row["reason"] for row in exclusions})}
        progress("audit_page_vector_components", retained_rows=len(frame))
        frame, component_report = assign_components(frame)
        audit["grouping"] = component_report
        audit["retained_class_counts"] = {"phishing": int(frame["target"].sum()),
                                          "legitimate": int(len(frame) - frame["target"].sum())}
        splits = results = selected = None
        if not audit_only:
            progress("create_grouped_splits")
            indices, splits = make_splits(frame, seed)
            progress("grouped_splits_complete", counts={name: len(rows) for name, rows in indices.items()})
            save_json(output / "split-report.json", splits)
            membership = []
            for split, index in indices.items():
                for row in frame.iloc[index].itertuples(index=False):
                    membership.append({"source_row": int(row.source_row), "row_id": row.row_id,
                                       "url_hash": row.url_hash, "domain_group_hash": row.domain_group_hash,
                                       "component_id": row.component_id, "page_vector_hash": row.page_vector_hash,
                                       "split": split, "truth_phishing": int(row.target)})
            write_csv(output / "split-membership.csv", ("source_row", "row_id", "url_hash", "domain_group_hash",
                                                       "component_id", "page_vector_hash", "split", "truth_phishing"), membership)
            partition = frame[list(URL_FEATURES + PAGE_FEATURES) + ["source_row", "row_id", "url_hash",
                              "domain_group_hash", "component_id", "page_vector_hash", "target"]].copy()
            partition["split"] = ""
            for split, index in indices.items():
                partition.loc[index, "split"] = split
            partition.to_parquet(output / "quality-features.parquet", index=False)
            results, selected = train_baselines(frame, indices, output, seed)
        audit["source_unchanged_after_run"] = sha256_file(input_path) == audit["source"]["sha256"]
        if not audit["source_unchanged_after_run"]:
            raise ValueError("source bytes changed during the offline run")
        audit["status"] = "audit_complete" if audit_only else "baseline_complete"
        audit["seed"] = seed
        audit["audit_only"] = audit_only
        audit["generated_at"] = datetime.now(timezone.utc).isoformat()
        audit["versions"] = {name: importlib.metadata.version(name)
                             for name in ("pandas", "numpy", "scikit-learn", "scipy", "tldextract", "joblib")}
        audit["python"] = platform.python_version()
        audit["implementation_sha256"] = sha256_file(__file__)
        audit["elapsed_seconds"] = round(time.monotonic() - started, 4)
        audit["artifact_hashes"] = {file.name: sha256_file(file) for file in sorted(output.iterdir()) if file.is_file()}
        save_json(output / "audit.json", audit)
        (output / "REPORT.md").write_text(report_markdown(audit, splits, results, selected), encoding="utf-8")
        progress("finished", status=audit["status"], seconds=audit["elapsed_seconds"])
        return audit
    except Exception as exc:
        audit["status"] = "failed"
        audit["failure"] = str(exc)
        audit["elapsed_seconds"] = round(time.monotonic() - started, 4)
        save_json(output / "audit.json", audit)
        raise
