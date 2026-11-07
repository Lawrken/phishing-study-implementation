"""Coverage first. Descriptive comparisons resample independent domain/template groups."""
import json
from pathlib import Path
from .features import FEATURES


def _read(path):
    import pandas as pd
    p = Path(path)
    return pd.read_parquet(p) if p.suffix == ".parquet" else pd.read_csv(p)


def bh(pvalues):
    import numpy as np
    p = np.array(pvalues, dtype=float)
    order = np.argsort(p)
    out = np.empty(len(p))
    adjusted = np.minimum.accumulate((p[order] * len(p) / np.arange(1, len(p) + 1))[::-1])[::-1]
    out[order] = np.minimum(1, adjusted)
    return out.tolist()


def analyze(path, destination, seed=20261010, bootstrap=1000):
    import numpy as np
    import pandas as pd
    from scipy.stats import mannwhitneyu
    df = _read(path)
    out = Path(destination)
    out.mkdir(parents=True, exist_ok=True)
    report = {"rows": len(df), "note": "Observational associations; no causal or detection-performance claim.", "comparisons": []}
    if df.empty:
        report["status"] = "no_observations"
    else:
        report["coverage"] = df.groupby(["label", "outcome", "capture_eligible"], dropna=False).size().reset_index(name="count").to_dict("records")
        eligible = df["research_eligible"].astype(str).str.lower().isin(["true", "1"])
        real = df[eligible & df["profile"].eq("live")].copy()
        report["real_reviewed_rows"] = len(real)
        report["missingness"] = {name: {str(label): float(g[name].isna().mean()) for label, g in df.groupby("label")} for name in FEATURES if name in df}
        report["status"] = "insufficient_reviewed_live_data"
        if not real.empty:
            configs = real["config_hash"].nunique()
            # Independent two-class group comparisons cannot resample the same
            # component independently in both classes. Report and exclude mixed groups.
            mixed = real.groupby("split_group")["label"].nunique()
            mixed = set(mixed[mixed>1].index)
            report["mixed_label_groups_excluded_from_comparisons"] = len(mixed)
            real = real[~real["split_group"].isin(mixed)]
            group_counts = real.groupby("label")["split_group"].nunique().to_dict()
            report["independent_groups"] = group_counts
            if configs != 1:
                report["status"] = "mixed_configurations_analyze_separately"
            elif min(group_counts.get("legitimate", 0), group_counts.get("phishing", 0)) >= 10:
                report["status"] = "descriptive_comparisons"
                rng = np.random.default_rng(seed)
                # Group means prevent high-volume domains from dominating.
                for feature in FEATURES:
                    values = real.groupby(["label", "split_group"])[feature].mean()
                    a = values.get("legitimate", pd.Series(dtype=float)).dropna().to_numpy()
                    b = values.get("phishing", pd.Series(dtype=float)).dropna().to_numpy()
                    if min(len(a), len(b)) < 10:
                        continue
                    difference = float(np.mean(b) - np.mean(a))
                    draws = [float(np.mean(rng.choice(b, len(b), replace=True)) - np.mean(rng.choice(a, len(a), replace=True))) for _ in range(bootstrap)]
                    u, p = mannwhitneyu(b, a, alternative="two-sided")
                    report["comparisons"].append({"feature": feature, "legitimate_groups": len(a), "phishing_groups": len(b),
                        "phishing_minus_legitimate_mean": difference, "bootstrap_95_interval": np.quantile(draws, [.025, .975]).tolist(),
                        "rank_biserial_effect": float(2*u/(len(a)*len(b))-1), "p_value": float(p)})
                q = bh([r["p_value"] for r in report["comparisons"]])
                for row, value in zip(report["comparisons"], q):
                    row["fdr_q_value"] = value
                report["status"] = "descriptive_comparisons" if report["comparisons"] else "insufficient_feature_coverage"
    (out / "analysis.json").write_text(json.dumps(report, indent=2, allow_nan=False))
    lines = ["# Collection quality and research readiness", "", f"Observations: {report['rows']}", f"Status: {report['status']}", "", report["note"], "",
             "Research comparisons require independently verified labels, an active-page review, identical configurations, and at least 10 independent groups per class. Fixture data never count as research data.", "",
             "See analysis.json for coverage, missingness, effects, confidence intervals, and FDR-adjusted tests when enough eligible data exist."]
    (out / "REPORT.md").write_text("\n".join(lines) + "\n")
    return report


def dataset_label_report(queue, export_path, destination):
    """Report operational yield using historical labels, never current-label accuracy."""
    from collections import Counter
    from datetime import datetime, timezone
    df = _read(export_path)
    destination = Path(destination)
    if destination.exists():
        raise ValueError('use a fresh dataset-label report directory')
    with queue.connect() as db:
        candidates = [dict(row) for row in db.execute('SELECT * FROM candidates ORDER BY id')]
        attempts = [dict(row) for row in db.execute('SELECT a.*,c.label FROM attempts a JOIN candidates c ON c.id=a.candidate_id ORDER BY a.started,a.id')]
        dataset_ids = {row[0] for row in db.execute("SELECT DISTINCT candidate_id FROM provenance WHERE confidence='dataset' AND source='phiusiil-dataset' AND observed_at='unknown'")}
    dataset_candidates = [row for row in candidates if row['id'] in dataset_ids]
    dataset_attempts = [row for row in attempts if row['candidate_id'] in dataset_ids]
    def counts(values):
        return {label: int(values.get(label, 0)) for label in ('legitimate', 'phishing')}
    reserve = counts(Counter(row['label'] for row in dataset_candidates))
    attempted = counts(Counter(row['label'] for row in dataset_candidates if row['attempts'] > 0))
    report = {'analysis_scope': 'phiusiil-historical-label-revisit',
        'status': 'dataset_label_operational_pilot', 'generated_at': datetime.now(timezone.utc).isoformat(),
        'note': 'New traffic is grouped by published historical labels. This is not current-threat validation or classifier accuracy.',
        'new_model_trained': False, 'dataset_labels_currently_verified': False,
        'reserve_candidates_by_label': reserve, 'attempted_unique_candidates_by_label': attempted,
        'unattempted_candidates_by_label': {label: reserve[label] - attempted[label] for label in reserve},
        'attempts_by_label': counts(Counter(row['label'] for row in dataset_attempts)),
        'finished_attempts_by_label': counts(Counter(row['label'] for row in dataset_attempts if row['finished'] is not None)),
        'attempt_outcomes': [], 'latest_candidate_outcomes': [], 'rows_exported': len(df),
        'dataset_label_usable_by_label': counts({}), 'independently_verified_research_rows': 0,
        'domain_groups_by_label': counts({}), 'missingness': {}, 'config_hashes': []}
    for (label, outcome), count in sorted(Counter((row['label'], row['outcome'] or 'unfinished') for row in dataset_attempts).items()):
        report['attempt_outcomes'].append({'label': label, 'outcome': outcome, 'count': count})
    for (label, state, outcome), count in sorted(Counter((row['label'], row['state'], row['outcome'] or 'not_attempted') for row in dataset_candidates).items()):
        report['latest_candidate_outcomes'].append({'label': label, 'state': state, 'outcome': outcome, 'count': count})
    if not df.empty:
        def yes(series):
            return series.astype(str).str.lower().isin(('true', '1'))
        if 'dataset_label_capture_eligible' not in df or 'label_confidence' not in df:
            raise ValueError('export lacks explicit dataset-label eligibility')
        published = df[df['label_confidence'].eq('dataset')].copy()
        usable = published[yes(published['dataset_label_capture_eligible'])]
        report['dataset_label_usable_by_label'] = counts(usable.groupby('label').size().to_dict())
        report['domain_groups_by_label'] = counts(usable.groupby('label')['domain_group'].nunique().to_dict())
        report['independently_verified_research_rows'] = int(yes(df['research_eligible']).sum())
        report['config_hashes'] = sorted(published['config_hash'].dropna().unique().tolist())
        report['missingness'] = {name: {str(label): {'rows': len(group), 'missing': int(group[name].isna().sum()),
                'missing_fraction': float(group[name].isna().mean())}
            for label, group in published.groupby('label')} for name in FEATURES if name in published}
        if len(report['config_hashes']) > 1:
            report['status'] = 'mixed_configurations_report_separately'
    report['usable_per_attempted_candidate'] = {label: (report['dataset_label_usable_by_label'][label] / attempted[label]
        if attempted[label] else None) for label in attempted}
    destination.mkdir(parents=True, exist_ok=False)
    (destination / 'dataset-label-report.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    lines = ['# Dataset labelled revisit pilot', '',
             'Published PhiUSIIL labels remain historical dataset labels. No current-classification accuracy or new trained model is reported.', '',
             '## Counts', '', '| Published label | Reserve URLs | Attempted unique URLs | Usable captures |',
             '|---|---:|---:|---:|']
    for label in ('legitimate', 'phishing'):
        lines.append(f"| {label} | {reserve[label]} | {attempted[label]} | {report['dataset_label_usable_by_label'][label]} |")
    lines += ['', 'Failures, blocked destinations, challenges and other outcomes remain in the machine-readable report. Missing observations are not zero-valued phishing features.',
              '', 'Source labels, capture success, active-page review and independently verified current labels are separate findings.']
    (destination / 'REPORT.md').write_text('\n'.join(lines) + '\n')
    return report


def train(path, destination, seed=20261010):
    """Optional exploratory baseline. Group holdout; preprocessing learned on training only."""
    import numpy as np
    from sklearn.model_selection import GroupShuffleSplit
    from sklearn.pipeline import make_pipeline
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import roc_auc_score, average_precision_score, confusion_matrix, precision_score, recall_score
    df = _read(path)
    if df.empty:
        raise ValueError("no observations")
    eligible = df["research_eligible"].astype(str).str.lower().isin(["true", "1"])
    df = df[eligible & df["profile"].eq("live")].copy()
    counts = df.groupby("label")["split_group"].nunique().to_dict()
    if min(counts.get("legitimate", 0), counts.get("phishing", 0)) < 30:
        raise ValueError("training needs at least 30 reviewed independent groups per class")
    if df["config_hash"].nunique() != 1:
        raise ValueError("train one standardized configuration at a time")
    # Missingness indicators are deliberately excluded from the primary baseline.
    names = [n for n in FEATURES if not n.startswith("interaction_")]
    x = df[names].astype(float)
    y = df["label"].eq("phishing").astype(int)
    groups = df["split_group"]
    a, b = next(GroupShuffleSplit(n_splits=1, test_size=.25, random_state=seed).split(x, y, groups))
    if y.iloc[a].nunique() < 2 or y.iloc[b].nunique() < 2:
        raise ValueError("group holdout lacks one class; expand dataset before training")
    assert not set(groups.iloc[a]) & set(groups.iloc[b])
    result = {"status": "exploratory_heldout_baselines", "seed": seed, "train_rows": len(a), "test_rows": len(b),
              "features": names, "train_groups": groups.iloc[a].nunique(), "test_groups": groups.iloc[b].nunique(),
              "note": "No hyperparameter tuning. Evaluate source/time-heldout replication before making a generalization claim.", "models": {}}
    for name, estimator in (("logistic_regression", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed)),
                            ("random_forest", RandomForestClassifier(n_estimators=200, max_depth=12, min_samples_leaf=5, class_weight="balanced", random_state=seed, n_jobs=2))):
        model = make_pipeline(SimpleImputer(strategy="median", keep_empty_features=True), StandardScaler(), estimator)
        model.fit(x.iloc[a], y.iloc[a])
        probability = model.predict_proba(x.iloc[b])[:,1]
        predicted = probability >= .5
        result["models"][name] = {"roc_auc": float(roc_auc_score(y.iloc[b], probability)),
             "average_precision": float(average_precision_score(y.iloc[b], probability)),
             "precision": float(precision_score(y.iloc[b], predicted, zero_division=0)),
             "recall": float(recall_score(y.iloc[b], predicted, zero_division=0)),
             "confusion_matrix": confusion_matrix(y.iloc[b], predicted, labels=[0,1]).tolist(), "threshold": .5}
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "models.json").write_text(json.dumps(result, indent=2))
    (dest / "holdout.json").write_text(json.dumps({"train": df.iloc[a]["candidate_id"].tolist(), "test": df.iloc[b]["candidate_id"].tolist()}, indent=2))
    return result
