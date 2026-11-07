# Replication release validation

Prepared 7 November 2026. The original research evidence remains unchanged and outside Git.

Passed:

- 17 host regressions, including clone-relative paths, missing credentials, pinned SSH checking, required physical location, unchanged attempt/continuation controls, changed-download rejection and NoCloud ISO contents.
- Official pinned Ubuntu image download matches SHA-256 `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`.
- Input release archive identity and original CSV/split/audit hashes are frozen in the committed input manifest.
- Before these replication changes, the dataset-only collector passed 454 Linux tests (20 Chromium checks) and completed two separate ten-attempt batches: 20 distinct endpoints, eight usable captures and 12 unsuccessful attempts. Those runs did not visit the owned Vercel control. This is historical evidence, not approval of a fresh clone.

Pending:

- A complete clean-VM setup rehearsal and fresh source-bound deployment verification. Local rehearsal was stopped before VM startup by the unchanged 5 GiB available-RAM requirement.
- Verification on the friend's own hardware, network and actual location.

The release is a prerelease until the clean-VM rehearsal is measured. Setup and CI must not be described as proving that every dataset website is reachable or that historical phishing-labelled pages are currently active phishing sites.
