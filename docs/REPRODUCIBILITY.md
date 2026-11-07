# What replication establishes

The repository reproduces the method and software, not tomorrow's website contents. Its private release preserves the exact PhiUSIIL source CSV, frozen offline split membership and audit. SHA-256 identities are committed in `replication/inputs-manifest.json`. Source labels stay historical dataset labels; the code does not silently upgrade them to independently reviewed current labels.

The standard intake rebuilds the same 400-record reserve from original training groups using seed 20261010. Mixed-label domain groups are excluded and one endpoint is selected per distinct group. Validation/test groups are preserved. No live reachability screening, model predictions or new training determines the reserve.

Each computer builds its own Ubuntu base and records its own location, OS/package versions, SSH identity and base-disk hash. Package versions and the Ubuntu/QEMU downloads are pinned; Ubuntu apt packages come from the distribution repositories and the installed OS package list is saved. Those apt packages are not claimed to be byte-identical across installation dates. A prepared base is reused through fresh disposable overlays and checked by hash before startup.

Current-source tests, browser checks, selftest, exact disconnected generated-policy controls, ten clean browser lifecycle trials and service-stop controls run before each dataset batch. Changed source creates a new identity and needs fresh verification. The separate dataset-observation profile does not perform the older owned-site Internet test and cannot satisfy that profile's full public-verification gate. Local resolver logs are not authoritative DNS access evidence.

Results are saved per run, with failures and unfinished outcomes distinguished from successful captures. The exported CSV contains one latest committed observation per attempted URL; original attempt instances remain in SQLite. Continuation preserves receipts and excludes all already-attempted identities. Combining results across people, dates or locations must retain those provenance fields and should be decided before a main comparison; the operator does not automatically pool friends' results into the original 150.

## Evidence kept outside Git

The existing owner's data, 150-result analysis, VM disks, snapshots, SSH keys, serial logs, old failed attempts and historical documents stay on the owner's disk. `.gitignore` uses an explicit source allowlist so they cannot be added through a normal `git add .`. Do not force-add those directories. The input release is a separate 55 MiB ZIP; it contains the original published dataset and hashed partition identities, not browser captures or credentials.

Study inputs are credited to Prasad and Chandra under CC BY 4.0. Reusing the software and captures does not establish independent authorship or unaided execution. Record who ran each command and which computer/location produced each batch.

## Checks you can repeat without websites

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s host-tools -p 'Test*.py'
.\host-tools\ResearchOperator.ps1 -Mode Inspect
.\host-tools\ResearchOperator.ps1 -Mode Run -MaxAttempts 10 -VerifyOnly
```

Host tests never boot a VM or access the Internet. GitHub Actions runs host regressions and the Linux browser suite against controlled fixtures. CI does not use research URLs, download private input artifacts, start a pilot or approve a collection host.

The first setup rehearsal's measured status and any limitations are recorded in [release validation](RELEASE_VALIDATION.md). A successful setup alone is not approval to skip any deployment check.
