# Dedicated Ubuntu deployment bundle

These scripts prepare an explicitly designated disposable Ubuntu 24.04 VM. They
do not provision a VM, purchase services, visit research candidates or change the
Windows/Docker fixture host. Install refuses containers/WSL, other Ubuntu versions,
existing deployment paths/accounts and an existing `study_egress` table.

The operator supplies an accurate region, one approved public IPv4 resolver and
owned controls. Keep `network_isolation_verified=false` in the generated template.
The installed `study` account has no sudo and no interactive shell. Root owns the
application, browser, service, resolver and evidence files; study owns only its
restricted dataset. The service binds a direct resolver and `hosts: files dns`,
rejects IPv6 socket creation, and applies nftables to every study UID connection,
including Chromium and TLS/DNS metadata. Root fixture units use PrivateNetwork
and owned loopback fixtures; they do not establish live readiness.

## Install and verify

Run `install.sh --dedicated-vm --source PROJECT --region ACTUAL_REGION --resolver
APPROVED_PUBLIC_IPV4 --controls ROOT_OWNED_CONTROLS_JSON` as root only on that VM.
Source installation retains pyproject dependency pins and includes analysis extras
and matching Playwright Chromium. Ubuntu AppArmor receives a user-namespace profile
for those exact Chromium executables only. No global sandbox sysctl is changed.

The controls JSON has `owned_controls` with `http_url`, `https_url`,
`dns_template` (for example `{nonce}.YOUR_OWNED_ZONE`), and `redirect_url` returning
a redirect to the owned denied receiver. `expected_deny` requires `owned_ipv4`
(private/link-local owned receiver), `owned_ipv6`, `owned_public_ipv4`, and
`owned_port` (neither 53 nor 80/443). URLs and DNS zones must be yours to test.
Do not substitute documentation addresses as working controls.

Run `validate-fixtures.sh` first. It saves the strict complete suite and the
six-observation selftest with current source hashes. Create one fresh 32-character
lowercase hexadecimal nonce. Run `verify.sh --phase normal --nonce NONCE --output
/var/lib/phishing-study/verification/NONCE/normal`, then the equivalent
`--phase dns-blocked` into a fresh blocked directory. The blocked phase removes
only the dedicated DNS allowance chain; an EXIT trap restores that chain even
after failure. Unrelated firewall tables are never flushed. Normal must pass
before the blocked browser phase can run.

The root-owned receiver receipt supplied to `combine-verification.sh NONCE RECEIPT`
has `schema_version: 1`, the nonce, `normal` and `dns-blocked` objects with
`denied_receiver_requests: 0` and `dns_queries` arrays of `{name,resolver_ipv4}`.
Normal queries must include the fresh nonce hostname at the approved resolver;
blocked queries must be empty. Include `receiver_controls`, exactly the three
owned address/port combinations: private IPv4/non-web port, public IPv4/non-web
port, IPv6/443. Each has `address`, `port`, `nonce`, `positive_control_hits` greater
than zero from a separate authorized controller, and `normal_requests: 0` plus
`dns_blocked_requests: 0`. Retain the underlying receiver and resolver logs. A dead
receiver or absent DNS logs cannot prove isolation. Root helpers derive identity,
denied counter deltas and restored-policy hashes from actual immutable snapshots,
replacing those fields in the operator receipt.

Missing controls, unknown Chromium DNS configuration, failed sandbox verification,
different policy/source/configuration, incomplete receiver logs or unavailable TLS
and public DNS measurements prevent successful aggregation. Preserve failures and
use fresh output directories/nonces. The `study-egress` boot unit retains its own
policy when collection stops; it does not modify other firewall tables.

## Finite pilot and recovery

Copy the reviewed CSV and adjacent export audit into protected root-owned intake
files before activation. At least 50 independent reviewed domain/tenant groups
are required. Supply fresh locally saved OpenPhish and/or PhishTank files with
root-owned receipts `{source,sha256,retrieved_at}`; retrieval time must be explicit
UTC, never in the future, and no older than 12 hours/one hour respectively. This
records download freshness, not the continued availability of an endpoint.

Run `start.sh --legitimate-csv CSV --review-manifest AUDIT --openphish-file FEED
--openphish-receipt RECEIPT` (and/or corresponding PhishTank arguments). The script
validates the human-review export, freezes local intake, verifies current source,
configuration, resolver, service and installed firewall evidence, then enables the
isolation flag for the finite collector only. It has two workers, 50 captures per
class, 400 attempts and a two-hour deadline, plus two CPUs, 4 GB RAM and 512 tasks.
Initial free storage must be 15 GB; artifacts retain a 10 GB budget and 5 GB floor.
No feed download or unattended runner is started.

`stop.sh` requests graceful SIGTERM completion. `recover.sh UNFINISHED_RUN_ID`
resumes only an unfinished run with its original configuration and budgets;
downtime counts. A completed pilot must be reviewed before planning another batch.
After completion export and analyze through the existing CLI, then review coverage,
dispositions, missingness, redaction, domain/template diversity and resources before
an unattended collection. The installed paths are `/opt/phishing-study`,
`/etc/phishing-study` and restricted `/var/lib/phishing-study`.
