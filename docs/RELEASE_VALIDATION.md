# Replication release validation

Prepared 7 November 2026. The original research evidence remains unchanged and outside Git.

Passed:

- 18 host regressions, including clone-relative paths, first-run output folders, missing credentials, pinned SSH checking, required physical location, unchanged attempt/continuation controls, changed-download rejection and NoCloud ISO contents.
- Official pinned Ubuntu image download matches SHA-256 `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`.
- Input release archive identity and original CSV/split/audit hashes are frozen in the committed input manifest.
- Before these replication changes, the dataset-only collector passed 454 Linux tests (20 Chromium checks) and completed two separate ten-attempt batches: 20 distinct endpoints, eight usable captures and 12 unsuccessful attempts. Those runs did not visit the owned Vercel control. This is historical evidence, not approval of a fresh clone.

Failed and preserved:

- Two fresh Ubuntu setup builds booted, accepted their own SSH identities and installed Python packages. The official pinned Chromium download timed out, including the second attempt with IPv4-first lookup and a 120-second installation connection budget. Both VMs were stopped; no successful base configuration or collection activation was created. The original environment remained unchanged.
- GitHub Actions run [42349305682](https://github.com/Lawrken/phishing-study-implementation/actions/runs/42349305682) was diagnosed on 7 November: both the Windows `host` and `linux` jobs had no assigned runner and no executed steps. Both check annotations state: "The job was not started because your account is locked due to a billing issue." These are blocked hosted checks, not executed test failures or passing CI results. Earlier startup failures did not expose this cause through their available diagnostics.

The account owner must review GitHub **Settings → Billing & Licensing** to resolve the restriction. If that page offers no billing issue to resolve, GitHub's [locked-account guidance](https://docs.github.com/en/billing/how-tos/troubleshooting/locked-account) directs the owner to Support. No payment or account settings were changed by this project. Once the lock is cleared, rerun the checks; their code/dependency outcomes remain untested until actual steps execute.

Pending:

- A completed Chromium installation and fresh source-bound clean-VM deployment verification.
- Verification on the friend's own hardware, network and actual location.
- Assignment-aware intake for the separately prepared 234,677-URL two-laptop workload. The existing operator still uses the original shared 400-record reserve.

The release is a prerelease until the clean-VM rehearsal is measured. Setup and CI must not be described as proving that every dataset website is reachable or that historical phishing-labelled pages are currently active phishing sites.
