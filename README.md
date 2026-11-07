# Phishing research: browser traffic and website signals

This project visits frozen PhiUSIIL dataset endpoints inside a disposable Ubuntu VM, records browser traffic and website measurements, and preserves both successful captures and failed visits. Chromium renders the page; Playwright controls it and records request/response events. Python also measures DNS and input-origin certificate metadata.

**Start with [the two-laptop assignment plan](docs/TWO_LAPTOP_PLAN.md) and [the AI handoff](docs/AI_DATASET_HANDOFF.md).** The full dataset assignments are prepared, but the current operator does not ingest them yet. Its existing Run command still selects the original shared 400-record reserve. Do not use it on both laptops expecting the new assignments to apply.

**Setup is a prerelease:** fresh Ubuntu/SSH/Python preparation succeeded, but the pinned Chromium download timed out. See [measured release status](docs/RELEASE_VALIDATION.md). The supported operator host is Windows x64 with QEMU/WHPX. VirtualBox and a Linux desktop are not needed for this route.

## Clone and prepare

The source repository is public. Obtain the frozen `study-inputs-v1.zip` privately from the project owner; raw assignment files are also sent directly. Install [Git](https://git-scm.com/downloads/win) and [64-bit Python 3.12 or newer](https://www.python.org/downloads/windows/). Windows OpenSSH Client, firmware virtualization and Windows Hypervisor Platform must be available. GitHub CLI is optional. Setup does not change Windows features or security settings.

In PowerShell:

```powershell
git clone https://github.com/Lawrken/phishing-study-implementation.git
cd phishing-study-implementation
.\host-tools\ResearchOperator.ps1 -Mode Inspect
.\host-tools\SetupResearch.ps1 -Region 'YOUR ACTUAL CITY, COUNTRY' -InputsArchive 'PATH\study-inputs-v1.zip'
```

Replace the location with the actual collection location and the input path with the privately supplied ZIP. Setup verifies that input archive and downloads checksum-pinned QEMU and Ubuntu files. It creates new SSH identities and attempts to install the pinned Python/Chromium environment inside Ubuntu, then powers off the VM. It does not visit dataset websites. Allow several GB of downloads/installation space and time for the first setup. The unresolved Chromium installation failure is documented above.

Startup requires **5 GiB available Windows RAM and 50 GiB free disk**; 16 GB installed RAM or more is recommended. The VM receives 4 GiB RAM and two CPUs. The collector has one worker, a 2 GiB limit and a separate DNS-service budget.

## Verify, then run

First verify this computer without dataset visits:

```powershell
.\host-tools\ResearchOperator.ps1 -Mode Run -MaxAttempts 10 -VerifyOnly
```

If that passes, start a bounded batch:

```powershell
.\host-tools\ResearchOperator.ps1 -Mode Run -MaxAttempts 10
```

Open **http://127.0.0.1:8766/** while the run is active. It shows Ubuntu startup, verification, the actual Chromium page when loading succeeds, real traffic events, saved signals and visit outcomes. A DNS failure cannot show a loaded page; it is recorded and the queue continues. The monitor closes when the command ends.

From a second PowerShell window:

```powershell
.\host-tools\ResearchOperator.ps1 -Mode Status
.\host-tools\ResearchOperator.ps1 -Mode Stop
```

After a successful batch and verified export, advance beyond all attempted URLs, including failed visits:

```powershell
.\host-tools\ResearchOperator.ps1 -Mode Run -MaxAttempts 10 -Continue
.\host-tools\ResearchOperator.ps1 -Mode Report
```

Each batch reruns verification. Ten attempts may yield fewer than ten usable captures. The chain retains the frozen reserve's 400-attempt ceiling. A verification-only run is not a collection batch and cannot be the starting point for `-Continue`.

In Command Prompt (`C:\...>`), use `host-tools\ResearchOperator.cmd` in place of `.\host-tools\ResearchOperator.ps1`.

## Understand the evidence

- The published labels are historical: `0=phishing`, `1=legitimate`. A successful capture does not independently establish the current page's class or active phishing status.
- Live visits are passive. Controlled interaction is fixture-only. No credentials are supplied, forms intentionally submitted or models retrained by this operator.
- `local-dataset-observation-v1` requires local kernel/firewall, browser, DNS logging, lifecycle and cleanup checks. It performs no Vercel control visit and makes no owned-site Internet verification or full public-verification approval claim.
- Fresh VM overlays, source/configuration identities, failures, DNS logs, redacted browser events, SQLite records and hash-verified exports go under `phishing-study/validation/operator-.../` on each computer. These are excluded from Git.
- The original study's balanced 150 captures (75 per published class) remain on the owner's computer. They are not silently copied into a friend's new results. Changing websites need not produce the same availability or measurements on another day or network.

The original training/validation/test membership and input hashes are frozen in the release manifest. Reserve selection uses seed `20261010`, training groups only, one endpoint per homogeneous domain/tenant group, without selecting by reachability or model predictions.

## Find the implementation

| File or folder | Purpose |
| --- | --- |
| `host-tools/ResearchOperator.ps1` | Windows commands |
| `host-tools/ResearchOperator.py` | Operator, bounded batches and continuation |
| `host-tools/RunQemuResearch.py` | VM overlays, source installation, supervision and shutdown |
| `host-tools/PrepareResearchVM.py` | Fresh-machine setup and verified downloads |
| `phishing-study/study/collector.py` | Chromium/Playwright capture |
| `phishing-study/study/metadata.py` | DNS and direct certificate measurements |
| `phishing-study/study/runner.py` | Sequential visits and stopping rules |
| `phishing-study/study/observation.py` | Separate local verification purpose |
| `phishing-study/tests/` | Linux/browser and policy regressions |
| `replication/` | Download pins, package versions and guest setup |

For changes, fork the repository and submit a pull request; no collaborator write access is needed. Keep raw observations, VM disks and credentials out of Git. Read [replication and evidence limits](docs/REPRODUCIBILITY.md), [troubleshooting](docs/FRIEND_SETUP.md#troubleshooting) and [third-party attribution](THIRD_PARTY.md). Fresh deployment verification is mandatory on every collection host; a passing CI run or setup receipt is not deployment approval.
