# Two-laptop dataset assignment plan

Prepared 7 November 2026. This prepares the work files; it does not start collection.

## 1. Who gets which file

The original source has **235,795 rows**. We reproduced the existing cleaning: 10 invalid URLs, 1,106 same-label duplicate rows and two conflicting-label rows were excluded. That leaves **234,677 distinct cleaned endpoints**, all covered by these two assignments.

| Operator | Assigned CSV | Legitimate-labelled | Phishing-labelled | Total URLs |
| --- | --- | ---: | ---: | ---: |
| Lawrken / France | `assignment-lawrken.csv` | 67,425 | 49,914 | **117,339** |
| AR-AR-prog | `assignment-ar-ar-prog.csv` | 67,424 | 49,914 | **117,338** |
| Combined | Both files | 134,849 | 99,828 | **234,677** |

These are **assigned endpoints, not successful captures**. Availability is unknown until a new visit. The labels are the published PhiUSIIL labels: `0=phishing`, `1=legitimate`, with `confidence=dataset`. They are not a fresh independent judgement of the current page.

## 2. How the split was made

The seed is **20261010**. We first verified the original CSV, frozen split-membership ledger and offline audit by hash. The existing cleaning code reconstructed all retained rows and checked each row's original label, URL hash, domain-group hash and partition.

Every endpoint in a registered-domain/private-PSL tenant group stays on one laptop. We sorted the largest groups first, using a seeded SHA-256 tie-breaker, then assigned each group to balance the published class counts within each original partition. Mixed-label domain groups were preserved together; no additional rows were removed from the cleaned population. The resulting workload sizes differ by just one URL.

Within each assignment, URLs are deterministically ordered within each class, then interleaved legitimate/phishing until one class runs out. The remaining majority-class URLs stay in the file. Reachability, model predictions and feature values did not determine the assignments or order.

Verified results:

- No repeated row IDs or URL hashes within either file.
- **Zero shared URL hashes and zero shared domain groups between laptops.**
- The union contains exactly all 234,677 cleaned endpoints.
- Original labels and train/validation/test memberships match the frozen source artifacts.
- Original inputs and the existing balanced 150-capture research file remain unchanged.

The CSVs are collection assignment ledgers containing canonical URLs and provenance. They do not copy the 54 offline feature columns. Those remain in the original source CSV and can be joined using `source_row`; collector signals must not be substituted into the saved offline model.

## 3. Keep the original partitions

| Original partition | Lawrken legitimate | Lawrken phishing | AR-AR-prog legitimate | AR-AR-prog phishing |
| --- | ---: | ---: | ---: | ---: |
| Train | 40,455 | 29,948 | 40,454 | 29,948 |
| Validation | 13,485 | 9,983 | 13,485 | 9,983 |
| Test | 13,485 | 9,983 | 13,485 | 9,983 |

Laptop assignment is a workload split, not a new machine-learning train/test split. Preserve `original_partition` in every result. Do not move validation/test rows into training, tune models on them or alter the completed offline experiment. Future observation of held-out endpoints must follow the recorded collection protocol; assignment alone is not activation approval.

## 4. What happens next

1. Send AR-AR-prog the friend ZIP. It contains only their assignment CSV, an identity file, the full split manifest, this plan, the AI handoff and a standalone verifier.
2. Each person verifies their package without visiting websites. Run `python VERIFY_ASSIGNMENT.py --directory .` from the extracted package. Expected output is `status: passed`, the assigned operator, row count and class counts.
3. Clone the public source repository and read `docs/AI_DATASET_HANDOFF.md` and `docs/RELEASE_VALIDATION.md` before setup. Each computer needs its own location, VM, SSH identities and fresh verification.
4. **Implement and test assignment-aware intake before either laptop uses these files for collection.** The current operator still selects its original shared 400-URL reserve; it does not read these assignment CSVs. Running the existing command on both laptops would not automatically use these separate assignments.
5. Start with a small, explicitly bounded rehearsal on each verified computer. Keep one worker, the browser/DNS resource budgets, passive visits, failure preservation and shutdown controls. Passing a small batch does not authorize an unbounded full-dataset campaign.
6. After both rehearsals pass, set an explicit per-batch attempt/time/storage budget and a durable resume cursor for each assignment. Expand in stages, using measured runtime and disk growth. Do not set `MaxAttempts` to 117,000 or disable the current 400-attempt gate to make these files fit.

The current clean-machine setup rehearsal reached Ubuntu and installed Python packages, but its pinned Chromium download timed out. That failure remains preserved. Fresh setup and deployment verification are unfinished; this plan does not describe the friend environment as ready for collection.

## 5. How to save and compare results

Keep separate result folders using assignment ID, operator and run ID. Each attempt should retain `row_id`, `url_hash`, `domain_group_hash`, `original_partition`, published label, actual collection region, UTC times, source/configuration/browser identities, outcome, missing reasons and usable-capture flag. Save failed attempts as well as successes. Resume beyond all attempted IDs; do not silently replace failures with different URLs.

Before combining exports, verify hashes, identical assignment IDs, matching schemas/settings and zero cross-laptop URL overlap. Count attempts, distinct endpoints, usable captures and unsuccessful outcomes separately. The two new workloads remain separate from the original balanced 150 and the later 20-attempt operational checks.

Compare class coverage, DNS/HTTP outcomes, missing signal groups and observation durations using the same definitions and settings. Different URL assignments do not provide a controlled experiment about which laptop is better: hardware, location, network and collection time can all affect results. Use the same controlled fixture tests on both machines for technical calibration. Do not infer current phishing activity from the historical label or infer permanent deletion from a DNS failure.

## 6. Reproduce the assignment

From the repository, using the three original inputs from the privately supplied frozen `study-inputs-v1.zip` (not included in the public code repository):

```powershell
python -m pip install tldextract==5.4.0
python -B replication/split_dataset.py --source PATH/source.csv --membership PATH/split-membership.csv --audit PATH/audit.json --output outputs/new-assignment-replay
```

Use a fresh output directory. The CSV hashes must match `split-manifest.json`. The timestamp in a newly generated manifest can differ; the assignment ID and CSV contents are deterministic.

Dataset attribution: Arvind Prasad and Shalini Chandra, PhiUSIIL Phishing URL (Website), UCI Machine Learning Repository, CC BY 4.0. Source: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website+dataset.
