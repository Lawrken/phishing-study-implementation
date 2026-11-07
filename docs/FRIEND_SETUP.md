# Set up another computer, step by step

This guide is for the friend joining the study. Run Windows commands in PowerShell unless a step says otherwise. A VM is a separate computer simulated inside your laptop; Ubuntu and Chromium run there, while Windows hosts the monitor.

## 1. Check the laptop

Use Windows x64 with at least four logical CPUs. We recommend 16 GB installed RAM or more. Before VM startup, the program requires **5 GiB available RAM** and **50 GiB free disk** on the drive holding the clone. Available RAM is the portion currently unused, so 16 GB installed does not mean 16 GB available.

Firmware virtualization and **Windows Hypervisor Platform (WHPX)** must work. Check Windows Features (`Win+R`, then `optionalfeatures`). Do not disable Memory Integrity or VBS to follow this guide. If Windows Hypervisor Platform is unavailable, ask the computer owner to review that prerequisite; setup does not change Windows features, security settings, boot options or restart the computer.

Install these ordinary prerequisites from their publishers:

| Software | Purpose | Link |
| --- | --- | --- |
| Git for Windows | Download the code and updates | https://git-scm.com/downloads/win |
| GitHub CLI (optional) | Convenience commands for forks and pull requests; not needed by setup | https://cli.github.com/ |
| Python 3.12 or newer, Windows x64 | Run the Windows supervisor and setup | https://www.python.org/downloads/windows/ |
| OpenSSH Client, a Windows optional feature | Send commands/files to the VM | https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse |

During Python installation, enable the option to add Python to PATH. Reopen PowerShell after installation. VS Code is optional; the program runs from PowerShell. VirtualBox, Docker, WSL, Node.js and a separate Linux desktop are not needed for this QEMU route.

Check the installed commands:

```powershell
git --version
python --version
Get-Command ssh, scp, ssh-keygen
```

## 2. Accept access and clone

The repository is public; no invitation or collaborator write access is needed. For code changes, fork it and submit a pull request. To clone the original:

```powershell
cd "$HOME\Downloads"
git clone https://github.com/Lawrken/phishing-study-implementation.git
cd phishing-study-implementation
.\host-tools\ResearchOperator.ps1 -Mode Inspect
```

`Inspect` reports RAM, free disk, CPU and virtualization information. It does not start a VM or collection. The presence of a Windows hypervisor alone is not a failure; this route uses WHPX. Opening the folder in VS Code is optional:

```powershell
code .
```

## 3. Prepare your own VM

Replace the sample location with your actual city and country:

```powershell
.\host-tools\SetupResearch.ps1 -Region 'YOUR ACTUAL CITY, COUNTRY'
```

The command creates a local Python environment, verifies downloads against committed checksums, builds a fresh Ubuntu 24.04 base, installs the pinned guest packages and Chromium, and copies the frozen source CSV, split membership and audit into that VM. It generates new administration and VM host SSH keys for this computer. Existing owner credentials are not downloaded.

Automatic downloads are:

| Download | Role |
| --- | --- |
| QEMU Windows 20260811 package | Runs the VM through WHPX; extracted locally, no system installer |
| 7-Zip 26.05 helpers | Extract the QEMU package locally |
| Ubuntu Noble cloud image dated 20261017 | Fresh guest operating system |
| `study-inputs-v1.zip` from the `replication-v1` release | Exact source CSV and frozen split/audit artifacts; about 55 MiB compressed |
| Python packages and matching Playwright Chromium | Guest collector/test runtime; Chromium is installed in Ubuntu |

Downloads live under `.local-vm/portable/downloads/`. VM build logs and per-machine keys live under `.local-vm/portable/build-.../`. `.operator/host.json` records their local paths and base-disk hash. All are excluded from Git. Do not upload these folders or share the private keys.

The first setup can take many minutes. It ends with the VM powered off and no dataset websites visited. A setup receipt does not approve collection. Exact download versions/hashes are in `replication/downloads.json`; original study input hashes are in `replication/inputs-manifest.json`.

To download first and build later:

```powershell
.\host-tools\SetupResearch.ps1 -Region 'YOUR ACTUAL CITY, COUNTRY' -DownloadsOnly
```

If the input ZIP was downloaded through GitHub's release page, pass its path:

```powershell
.\host-tools\SetupResearch.ps1 -Region 'YOUR ACTUAL CITY, COUNTRY' -InputsArchive "$HOME\Downloads\study-inputs-v1.zip"
```

Use one setup process at a time. If setup fails, preserve its `setup.log`, `serial.log`, `qemu-console.txt` and failure receipt. A retry creates a new build directory. Do not reuse a partially installed disk as a verified base.

## 4. Verify this computer

```powershell
.\host-tools\ResearchOperator.ps1 -Mode Run -MaxAttempts 10 -VerifyOnly
```

Open http://127.0.0.1:8766/ while it runs. Expect Ubuntu startup, source installation, Linux/Chromium tests, fixture selftest, disconnected firewall/DNS controls, ten browser lifecycle trials and shutdown verification. This command does not visit dataset candidates or the Vercel site.

The original project passed 454 Linux tests, including 20 Chromium tests, before the replication changes. That is historical evidence. Your current source must pass its own fresh verification. Any failed required check stops activation; do not edit a report to say it passed or extend shutdown deadlines to hide a stall.

## 5. Visit ten dataset endpoints

After verification passes, run:

```powershell
.\host-tools\ResearchOperator.ps1 -Mode Run -MaxAttempts 10
```

Every Run repeats fresh verification. It creates a disposable disk overlay so candidate visits do not change the prepared base. The collector uses a dedicated non-root account and Chromium's sandbox. A separate logged resolver and generated firewall limit network access. The browser has a 2 GiB ceiling and two-CPU quota; the queue has one worker. Host timing, storage, resolver logging and cleanup are monitored.

The monitor shows the actual Chromium page when loading succeeds. Playwright records browser network events and extracts DOM/forms and JavaScript-resource signals. Python helpers obtain DNS and direct certificate metadata. An unavailable candidate produces a saved failure, then the queue continues. A resolver-service or containment failure stops the run.

The terminal's **10-attempt limit counts attempts, not ten successes**. Retries also count. The command has a 60-minute overall host limit including verification and shutdown; it may stop earlier for a failed check or resource problem.

## 6. Inspect, stop and continue

From another terminal opened in the same clone:

```powershell
.\host-tools\ResearchOperator.ps1 -Mode Status
.\host-tools\ResearchOperator.ps1 -Mode Stop
```

Leave the running terminal open while Stop performs bounded cleanup and export. After a completed batch:

```powershell
.\host-tools\ResearchOperator.ps1 -Mode Report
.\host-tools\ResearchOperator.ps1 -Mode Run -MaxAttempts 10 -Continue
```

Continuation skips all previously attempted URLs in that chain, whether successful or unsuccessful, and verifies the prior frozen evidence. It does not insert another person's successful captures into your results. The standard reserve has 200 URLs per published class and a 400-attempt chain ceiling. Run without `-Continue` starts a separate batch from the beginning; do not do that when you mean to advance.

Saved reports, CSV exports, DNS/browser logs and original failures are under `phishing-study/validation/operator-.../`. To reopen a saved monitor without visiting websites:

```powershell
.\host-tools\ResearchOperator.ps1 -Mode View
```

Ctrl+C closes that saved viewer only. Close it before another Run, since both use port 8766.

## Troubleshooting

| Message or symptom | Meaning and next step |
| --- | --- |
| `5 GiB available RAM ... required` | Close unused apps yourself, check Inspect again and rerun. Nothing was collected. |
| `50 GiB ... required` | Free space on the clone's drive or move the clone before setup. Do not delete research evidence to bypass this check. |
| Python not found | Install x64 Python 3.12+, reopen PowerShell or set `PHISHING_STUDY_PYTHON` to its executable. |
| GitHub repository/release not found | Check the repository and release URL. The source repository is public. |
| Download checksum mismatch | The bytes differ from the frozen pin. Preserve the failed download and ask for a reviewed manifest update; do not disable checking. |
| `WHPX` / VM exits before SSH | Check Windows Hypervisor Platform and virtualization. Preserve QEMU/serial logs. No automatic fallback accelerator or Windows protection change occurs. |
| SSH host-key mismatch | Stop. Do not disable strict checking. Check whether the key/base/config belongs to this computer's completed setup. |
| Verification failed | Read the saved `assessment-result.json`, consoles and operator result. Candidate browsing remains disabled. |
| `dns_unavailable`, HTTP 404/403, timeout | A dataset-site outcome. The record is preserved, and the next queued endpoint can be attempted if environment health remains good. |
| No page in the monitor | A DNS failure may prevent any page loading. Also distinguish live state from stale or saved frames. |
| `Port 8766 is occupied` | Close the saved viewer with Ctrl+C. Do not terminate unrelated processes automatically. |
| `.ps1` prints nothing in CMD | Use `host-tools\ResearchOperator.cmd -Mode ...`, or open PowerShell. |

If local policy prevents PowerShell scripts, do not weaken machine policy. The equivalent Python setup commands are:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\replication\requirements-host.txt
.\.venv\Scripts\python.exe -B .\host-tools\PrepareResearchVM.py --region 'YOUR ACTUAL CITY, COUNTRY'
.\.venv\Scripts\python.exe -B .\host-tools\ResearchOperator.py run --max-attempts 10 --verify-only
```

After verification, omit `--verify-only` to run; add `--continue-previous` to advance a successfully exported collection batch. Python modes `status`, `stop`, `report` and `view` correspond to the PowerShell modes.
