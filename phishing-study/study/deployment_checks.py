"""Owned-control preflight for a dedicated VM; never a research crawl.

Missing evidence is incomplete, never a successful deployment attestation.  The
root wrapper freezes phase reports and supplies firewall snapshots; this module
does not install packages, change DNS/firewall rules, or touch shared services.
"""
import asyncio
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit, urlunsplit

from .config import load
from .policy import Policy, public_ip


CONTROL_KEYS = ("http_url", "https_url", "dns_template", "redirect_url")
DENY_KEYS = ("owned_ipv4", "owned_ipv6", "owned_port", "owned_public_ipv4")
IDENTITY_KEYS = ("configuration_hash", "pilot_config_hash", "source_hash", "firewall_hash", "resolver_hash")
PHASES = ("normal", "dns-blocked")
HEX_NONCE = re.compile(r"^[a-f0-9]{32}$")
COMMON_CHECKS = {"inputs", "phase_nonce", "dedicated_ubuntu_non_root", "root_owned_manifest",
                 "manifest_digest", "root_owned_source", "pinned_dependencies", "resource_limits", "systemd_address_families", "frozen_config", "resolver", "root_snapshot", "vm_fixtures",
                 "sandbox_and_guard", "chromium_dns_configuration", "denied_connections"}
NORMAL_CHECKS = COMMON_CHECKS | {"initial_owned_destination_policy", "owned_http_https", "owned_denied_redirect", "fresh_browser_dns", "owned_tls_public_dns"}
BLOCKED_CHECKS = COMMON_CHECKS | {"prior_normal_phase", "fresh_browser_dns_blocked"}
FIXTURE_CHECKS = {"six_expected_observations", "expected_outcomes", "six_exported_rows", "three_usable_fixture_rows",
                  "fixture_data_excluded_from_research", "two_redirect_hops", "expected_security_headers",
                  "forms_and_password_inputs", "external_script_and_fetch", "fixture_only_synthetic_post",
                  "fresh_storage_on_next_visit", "passive_visit_has_no_post", "saved_artifacts_redacted"}


def _hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def manifest_digest_valid(manifest):
    from .deployment import digest_json
    return manifest.get("configuration_hash") == digest_json({
        key: value for key, value in manifest.items() if key not in {"configuration_hash", "generated_at"}})


def _read(path):
    return json.loads(Path(path).read_text())


def root_readonly(path):
    """Reject symlinks or writable evidence, including writable parent paths."""
    path = Path(path).absolute()
    for item in (path, *path.parents):
        metadata = item.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            return False
    return path.is_file()


def _url_ok(url, scheme=None):
    try:
        parsed = urlsplit(url)
        return bool(parsed.scheme in ({scheme} if scheme else {"http", "https"})
                    and parsed.hostname and not parsed.username and not parsed.password
                    and parsed.port in {None, 80, 443} and not parsed.fragment)
    except (TypeError, ValueError):
        return False


def missing_inputs(manifest):
    missing = []
    if manifest.get("schema_version") != 1 or manifest.get("dedicated_vm") is not True:
        missing.append("explicit_dedicated_vm")
    if not manifest.get("region") or manifest["region"] == "unspecified":
        missing.append("accurate_region")
    if manifest.get("route_id") != "direct-ipv4":
        missing.append("direct_ipv4_route")
    try:
        resolver = ipaddress.ip_address(manifest.get("approved_resolver", ""))
        if resolver.version != 4 or not public_ip(str(resolver)):
            raise ValueError()
    except ValueError:
        missing.append("approved_public_ipv4_resolver")
    if not isinstance(manifest.get("study_uid"), int) or manifest.get("study_uid", 0) <= 0:
        missing.append("non_root_study_uid")
    controls = manifest.get("owned_controls", {})
    for name in CONTROL_KEYS:
        if not controls.get(name):
            missing.append("owned_controls." + name)
    for key, scheme in (("http_url", "http"), ("https_url", "https"), ("redirect_url", None)):
        if controls.get(key) and not _url_ok(controls[key], scheme):
            missing.append("valid_owned_controls." + key)
    template = controls.get("dns_template", "")
    if template and (template.count("{nonce}") != 1 or not re.fullmatch(r"[a-zA-Z0-9.{\}-]+", template)
                     or "." not in template or template.endswith((".local", ".internal", ".localhost"))):
        missing.append("valid_owned_dns_template")
    denied = manifest.get("expected_deny", {})
    for name in DENY_KEYS:
        if denied.get(name) is None:
            missing.append("expected_deny." + name)
    for key, version, is_public in (("owned_ipv4", 4, False), ("owned_ipv6", 6, None),
                                    ("owned_public_ipv4", 4, True)):
        if denied.get(key) is not None:
            try:
                address = ipaddress.ip_address(denied[key])
                if address.version != version or (is_public is not None and public_ip(str(address)) != is_public):
                    raise ValueError()
            except ValueError:
                missing.append("valid_expected_deny." + key)
    port = denied.get("owned_port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int)
                             or port in {53, 80, 443} or not 1 <= port <= 65535):
        missing.append("owned_non_web_port")
    return sorted(set(missing))


def resolver_valid(resolv_conf, nsswitch, approved):
    lines = [line.split("#", 1)[0].strip() for line in resolv_conf.splitlines()]
    nameservers = [line.split()[1:] for line in lines if line.startswith("nameserver ")]
    host_lines = [line.split("#", 1)[0].strip() for line in nsswitch.splitlines()
                  if line.split("#", 1)[0].strip().startswith("hosts:")]
    return (nameservers == [[approved]] and host_lines == ["hosts: files dns"]
            and not any(line.startswith(("search ", "domain ")) for line in lines))


def resource_limits(cgroup_root="/sys/fs/cgroup", proc_cgroup="/proc/self/cgroup"):
    try:
        entries = Path(proc_cgroup).read_text().splitlines()
        relative = next(line.split("::", 1)[1] for line in entries if line.startswith("0::"))
        root = Path(cgroup_root).resolve()
        group = (root / relative.lstrip("/")).resolve()
        group.relative_to(root)
        quota, period = (group / "cpu.max").read_text().split()
        memory, pids = (group / "memory.max").read_text().strip(), (group / "pids.max").read_text().strip()
        result = {"cpu_max": quota + " " + period, "memory_max": memory, "pids_max": pids}
        result["ok"] = (quota != "max" and int(quota) / int(period) <= 2
                        and memory != "max" and 0 < int(memory) <= 4 * 1024 ** 3
                        and pids != "max" and 0 < int(pids) <= 512)
        return result
    except (OSError, ValueError, StopIteration):
        return {"ok": False, "reason": "bounded_cgroup_v2_required"}


def systemd_address_families(phase, proc_cgroup="/proc/self/cgroup"):
    """Read the effective unit property, rather than trusting wrapper flags."""
    try:
        group = next(line.split("::", 1)[1] for line in Path(proc_cgroup).read_text().splitlines() if line.startswith("0::"))
        unit = group.rstrip("/").rsplit("/", 1)[-1]
        if unit != f"study-verify-{phase}.service":
            return {"ok": False, "reason": "dedicated_verification_service_required"}
        value = subprocess.check_output(["systemctl", "show", unit, "--property=RestrictAddressFamilies", "--value"],
                                        text=True, timeout=5).strip().split()
        return {"ok": sorted(value) == ["AF_INET", "AF_NETLINK", "AF_UNIX"], "effective": sorted(value)}
    except (OSError, ValueError, StopIteration, subprocess.SubprocessError):
        return {"ok": False, "reason": "effective_systemd_profile_unavailable"}


def netlog_dns(log, approved, hostname):
    """Inspect effective DNS configuration and a fresh browser-side lookup.

    Unknown NetLog formats fail closed. Never infer the effective configuration
    from Chromium command-line options. Source: Chromium DnsConfig::ToValue.
    """
    names = {value: key for key, value in log.get("constants", {}).get("logEventTypes", {}).items()}
    configs, queries = [], []
    def exact_host(value):
        if not isinstance(value, str):
            return False
        try:
            parsed = urlsplit(value if "://" in value else "//" + value)
            return parsed.hostname and parsed.hostname.rstrip(".").lower() == hostname.rstrip(".").lower()
        except ValueError:
            return False
    for event in log.get("events", []):
        params = event.get("params", {})
        kind = names.get(event.get("type"), event.get("type"))
        dns_config = params.get("dns_config", params)
        if kind == "DNS_CONFIG_CHANGED" and "secure_dns_mode" in dns_config:
            configs.append(dns_config)
        if "DNS" in str(kind) or "HOST_RESOLVER" in str(kind):
            # Different pinned browser paths emit host/hostname/qname parameters.
            for key in ("host", "hostname", "qname"):
                value = params.get(key)
                if exact_host(value):
                    queries.append(kind)
    event_config_count = len(configs)
    polled = log.get("polledData", [])
    if isinstance(polled, dict):
        polled = [polled]
    if isinstance(polled, list):
        for item in polled:
            config = item.get("hostResolverInfo", {}).get("dns_config") if isinstance(item, dict) else None
            if isinstance(config, dict) and "secure_dns_mode" in config:
                configs.append(config)
    def no_doh(item):
        # Recent Chromium calls the serialized field doh_config; older builds
        # expose doh_servers. Absence of both does not establish a negative.
        if "doh_config" in item:
            doh = item["doh_config"]
            empty = doh == [] or doh == {"servers": []}
        else:
            empty = item.get("doh_servers") == []
        return (empty and item.get("fallback_doh_nameservers", []) == []
                and item.get("dns_over_tls_active", False) is False)
    config_ok = bool(configs) and all(
        item.get("secure_dns_mode") in {0, "off"}
        and no_doh(item)
        and item.get("nameservers") == [approved + ":53"] for item in configs)
    return {"ok": config_ok and bool(queries), "effective_config_verified": config_ok,
            "fresh_browser_lookup_seen": bool(queries), "config_events": event_config_count,
            "polled_configs": len(configs) - event_config_count}


def dns_failure_code(value):
    """Keep only a native categorical DNS failure, never a URL-bearing error."""
    if not isinstance(value, str):
        return None
    match = re.search(r"\bnet::ERR_(?:NAME_NOT_RESOLVED|DNS_[A-Z_]+)\b", value)
    return match.group(0) if match else None


def fixture_evidence(test_report, fixture_report):
    browser = test_report.get("browser_tests", {})
    return (test_report.get("successful") is True and test_report.get("browser_required") is True
            and test_report.get("browser_verified") is True and test_report.get("tests_run", 0) >= 120
            and test_report.get("passed") == test_report.get("tests_run")
            and not test_report.get("skipped") and not test_report.get("failures") and not test_report.get("errors")
            and browser.get("discovered", 0) >= 18
            and browser.get("discovered") == browser.get("executed") == browser.get("passed")
            and not browser.get("missing") and fixture_report.get("status") == "passed"
            and fixture_report.get("fixture_verified") is True
            and FIXTURE_CHECKS.issubset(fixture_report.get("checks", {}))
            and all(item is True for item in fixture_report.get("checks", {}).values())
            and fixture_report.get("rows") == 6
            and fixture_report.get("outcomes") == {"captured": 3, "challenge": 1, "takedown": 1, "parked": 1})


def _snapshot_identity(manifest):
    from .deployment import source_hash
    root = Path(manifest["source_root"])
    config = load(manifest["config_path"])
    return {"configuration_hash": manifest["configuration_hash"],
            "pilot_config_hash": config.fingerprint, "source_hash": source_hash(root),
            "firewall_hash": _hash("/etc/phishing-study/collector.nft"),
            "resolver_hash": _hash("/etc/phishing-study/resolver/resolv.conf")}


def _counterpart(manifest, phase):
    path = manifest.get("owned_controls", {}).get("runtime_snapshot_path")
    return Path(path.format(phase=phase) if path else f"/etc/phishing-study/runtime-{phase}.json")


def _check(report, name, ok, **details):
    report["checks"][name] = {"ok": bool(ok), **details}


async def _connect_denied(address, port):
    def connect():
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((address, port))
                return False
        except OSError:
            # RestrictAddressFamilies can deny socket creation before nftables;
            # this is a denied workload connection, not a firewall counter hit.
            return True
    return await asyncio.to_thread(connect)


async def _sandbox_evidence(browser):
    """Require renderer namespace separation and the Linux seccomp filter."""
    cdp = None
    try:
        cdp = await browser.new_browser_cdp_session()
        processes = (await cdp.send("SystemInfo.getProcessInfo"))["processInfo"]
        renderers = [item for item in processes if item["type"] == "renderer"]
        own_status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
        own_pid_depth = len(own_status.get("NSpid", "0").split())
        passed = []
        for renderer in renderers:
            path = Path("/proc") / str(renderer["id"])
            status = dict(line.split(":", 1) for line in (path / "status").read_text().splitlines() if ":" in line)
            # /proc namespace inode access can require ptrace permission for a
            # non-dumpable sandboxed child. NSpid remains readable and proves a
            # deeper PID namespace without weakening the Chromium sandbox.
            separated = len(status.get("NSpid", "0").split()) > own_pid_depth
            if not separated:
                try:
                    separated = (path / "ns/user").stat().st_ino != Path("/proc/self/ns/user").stat().st_ino
                except OSError:
                    separated = False
            passed.append(status.get("Seccomp", "").strip() == "2"
                          and status.get("NoNewPrivs", "").strip() == "1"
                          and all(int(uid) != 0 for uid in status.get("Uid", "0").split())
                          and separated)
        return bool(passed) and all(passed)
    except Exception:
        return False
    finally:
        if cdp is not None:
            try:
                await cdp.detach()
            except Exception:
                pass


async def _browser_process_evidence(browser, proc_root="/proc"):
    """Inspect the live owned Linux process without enabling browser automation.

    The pinned headless shell does not expose Browser.getBrowserCommandLine.
    Use its CDP-reported browser PID, then require a stable non-root process,
    a matching root-owned executable, and no sandbox-disabling arguments.
    Never export command-line contents, which can contain private paths.
    """
    cdp = None
    try:
        uid = os.geteuid()
        if uid == 0:
            return {"ok": False, "reason": "non_root_browser_required"}
        cdp = await browser.new_browser_cdp_session()
        processes = (await asyncio.wait_for(cdp.send("SystemInfo.getProcessInfo"), 5))["processInfo"]
        pids = [item["id"] for item in processes if item["type"] == "browser"]
        if len(pids) != 1 or type(pids[0]) is not int or pids[0] <= 0:
            return {"ok": False, "reason": "browser_pid_ambiguous"}
        proc = Path(proc_root) / str(pids[0])
        # Start time (field 22) detects exit/PID reuse during inspection.
        started = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
        executable = (proc / "exe").resolve(strict=True)
        command_bytes = (proc / "cmdline").read_bytes()
        if len(command_bytes) > 1024 * 1024 or not command_bytes.endswith(b"\0"):
            return {"ok": False, "reason": "invalid_browser_command"}
        command = [part.decode("utf-8", errors="strict") for part in command_bytes.split(b"\0") if part]
        status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
        uids = [int(value) for value in status.get("Uid", "").split()]
        owned = len(uids) == 4 and all(value == uid for value in uids)
        binary_ok = (bool(command) and Path(command[0]).is_absolute()
                     and Path(command[0]).resolve(strict=True) == executable and root_readonly(executable))
        sandbox_ok = bool(command) and not any(arg.split("=", 1)[0] in {
            "--no-sandbox", "--disable-setuid-sandbox", "--disable-namespace-sandbox",
            "--disable-seccomp-filter-sandbox", "--disable-gpu-sandbox"} for arg in command[1:])
        stable = (browser.is_connected()
                  and (proc / "stat").read_text().rsplit(")", 1)[1].split()[19] == started
                  and (proc / "exe").resolve(strict=True) == executable
                  and (proc / "cmdline").read_bytes() == command_bytes)
        return {"ok": owned and binary_ok and sandbox_ok and stable,
                "method": "SystemInfo browser PID plus /proc", "owned_process": owned,
                "root_owned_binary": binary_ok, "sandbox_arguments_ok": sandbox_ok,
                "stable_process": stable, "command_sha256": hashlib.sha256(command_bytes).hexdigest()}
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, asyncio.TimeoutError):
        return {"ok": False, "reason": "browser_process_inspection_unavailable"}
    finally:
        if cdp is not None:
            try:
                await asyncio.wait_for(cdp.detach(), 5)
            except Exception:
                pass


async def _browser_probe(manifest, config, output, phase, nonce):
    from playwright.async_api import async_playwright
    from .redirects import RedirectGuard
    controls = manifest["owned_controls"]
    host = controls["dns_template"].replace("{nonce}", phase.replace("-", "") + nonce)
    netlog_path = output / "owned-preflight-netlog.json"
    results = {"dns_hostname": host}
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True, chromium_sandbox=True, proxy=config.proxy(),
                                                   args=["--log-net-log=" + str(netlog_path)])
        guard = None
        results["chromium_version"] = browser.version
        try:
            guard = await RedirectGuard.start(browser)
            results["browser_process"] = await _browser_process_evidence(browser)
            results["sandbox_requested"] = results["browser_process"]["ok"]
            if not results["sandbox_requested"]:
                raise RuntimeError("browser_process_inspection_failed")
            sandbox_context = await browser.new_context(service_workers="block")
            try:
                sandbox_page = await sandbox_context.new_page()
                await sandbox_page.goto("about:blank")
                results["renderer_sandbox_verified"] = await _sandbox_evidence(browser)
            finally:
                await sandbox_context.close()

            async def visit(url, expect_redirect_denial=False):
                context = await browser.new_context(service_workers="block", viewport={"width": config.viewport_width, "height": config.viewport_height},
                                                    locale=config.locale, timezone_id=config.timezone)
                page, owner = None, None
                failures, denied = [], []
                dns_failures = []
                source_origin = urlsplit(url)

                async def route(request):
                    target = urlsplit(request.request.url)
                    if (target.scheme, target.hostname, target.port) != (source_origin.scheme, source_origin.hostname, source_origin.port):
                        await request.abort()
                    else:
                        await request.continue_()

                async def redirect(target, paused):
                    allowed, reason = await Policy(config).check(target)
                    if expect_redirect_denial:
                        expected = manifest["expected_deny"]
                        destination = urlsplit(target)
                        if destination.hostname != expected["owned_ipv4"] or destination.port != expected["owned_port"]:
                            failures.append("owned_redirect_control_mismatch")
                        if not allowed:
                            denied.append(reason)
                        return False
                    destination = urlsplit(target)
                    return allowed and (destination.scheme, destination.hostname, destination.port) == (source_origin.scheme, source_origin.hostname, source_origin.port)

                async def failure(reason):
                    failures.append(reason)
                    await context.close()

                response, error, sandbox = None, None, False
                try:
                    page = await context.new_page()
                    def request_failed(request):
                        code = dns_failure_code(request.failure)
                        if code:
                            dns_failures.append(code)
                    page.on("requestfailed", request_failed)
                    await context.route("**/*", route)
                    owner = await guard.register(page, redirect, failure)
                    try:
                        response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    except Exception as exc:
                        error = type(exc).__name__
                        code = dns_failure_code(str(exc))
                        if code:
                            dns_failures.append(code)
                    sandbox = await _sandbox_evidence(browser)
                finally:
                    try:
                        await context.close()
                    finally:
                        if owner is not None:
                            await guard.unregister(owner)
                return {"ok": bool(response and 200 <= response.status < 300 and not failures),
                        "status": response.status if response else None, "error_type": error,
                        "denied_redirect": bool(denied) and not failures, "guard_failures": failures,
                        "renderer_sandbox_verified": sandbox, "dns_failure": bool(dns_failures),
                        "dns_error_codes": sorted(set(dns_failures))}

            if phase == "normal":
                results["http"] = await visit(controls["http_url"])
                results["https"] = await visit(controls["https_url"])
                parsed = urlsplit(controls["redirect_url"])
                query = parsed.query + ("&" if parsed.query else "") + "study_nonce=" + nonce
                results["redirect"] = await visit(urlunsplit(parsed._replace(query=query)), True)
            results["fresh_dns"] = await visit("http://" + host + "/")
        finally:
            try:
                if guard is not None:
                    await guard.close()
                    results["redirect_guard"] = not guard.failed
            finally:
                await browser.close()
    results["netlog_dns"] = netlog_dns(_read(netlog_path), manifest["approved_resolver"], host)
    return results


async def run_phase(deployment_path, output, phase, nonce):
    """Write a fresh phase report; absent controls never trigger network probes."""
    output = Path(output)
    started = time.monotonic()
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    report = {"schema_version": 1, "status": "incomplete", "network_isolation_verified": False,
              "generated_at": datetime.now(timezone.utc).isoformat(), "phase": phase, "nonce": nonce,
              "checks": {}, "tls_verified": False, "public_dns_verified": False}
    try:
        versions = {"python": sys.version.split()[0]}
        for package in ("playwright", "tldextract", "dnspython", "pyarrow", "pandas", "scipy", "scikit-learn"):
            try:
                versions[package] = importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError:
                versions[package] = None
        report["versions"] = versions
        manifest = _read(deployment_path)
        missing = missing_inputs(manifest)
        _check(report, "inputs", not missing, missing=missing)
        _check(report, "phase_nonce", phase in PHASES and bool(HEX_NONCE.fullmatch(nonce)))
        if missing or not report["checks"]["phase_nonce"]["ok"]:
            return report
        ubuntu = Path("/etc/os-release").read_text() if sys.platform == "linux" else ""
        host_ok = sys.platform == "linux" and 'ID=ubuntu' in ubuntu and 'VERSION_ID="24.04"' in ubuntu
        _check(report, "dedicated_ubuntu_non_root", host_ok and os.geteuid() == manifest["study_uid"] and os.geteuid() != 0)
        _check(report, "root_owned_manifest", root_readonly(deployment_path))
        _check(report, "manifest_digest", manifest_digest_valid(manifest))
        _check(report, "pinned_dependencies", all(versions.get(name) == version for name, version in
               {"playwright": "1.63.0", "tldextract": "5.4.0", "dnspython": "2.9.0", "pyarrow": "26.0.0"}.items()))
        _check(report, "resource_limits", **resource_limits())
        _check(report, "systemd_address_families", **systemd_address_families(phase))
        if not all(value["ok"] for value in report["checks"].values()):
            return report
        identity = _snapshot_identity(manifest)
        report.update(identity)
        from .deployment import source_files
        _check(report, "root_owned_source", all(root_readonly(path) for path in source_files(manifest["source_root"])))
        config = load(manifest["config_path"])
        _check(report, "frozen_config", identity["pilot_config_hash"] == manifest["pilot_config_hash"]
               and identity["source_hash"] == manifest["source_hash"] and config.profile == "live"
               and config.route_id == "direct-ipv4" and config.region == manifest["region"]
               and config.network_isolation_verified is False and not config.proxy_required
               and (config.workers, config.max_attempts, config.max_hours, config.usable_per_class) == (2, 400, 2, 50)
               and config.interaction == "none")
        resolver = Path("/etc/resolv.conf").read_text()
        nsswitch = Path("/etc/nsswitch.conf").read_text()
        _check(report, "resolver", resolver_valid(resolver, nsswitch, manifest["approved_resolver"])
               and _hash("/etc/resolv.conf") == identity["resolver_hash"])
        snapshot_path = _counterpart(manifest, phase)
        snapshot = _read(snapshot_path)
        _check(report, "root_snapshot", root_readonly(snapshot_path) and snapshot.get("nonce") == nonce
               and snapshot.get("phase") == phase and snapshot.get("dns_blocked") is (phase == "dns-blocked")
               and all(snapshot.get(key) == value for key, value in identity.items())
               and sorted(snapshot.get("restrict_address_families", [])) == report["checks"]["systemd_address_families"].get("effective")
               and bool(snapshot.get("local_ipv4"))
               and snapshot.get("local_ipv4") == manifest.get("local_ipv4")
               # An on-link default route legitimately has no gateway field.
               # Missing network snapshots still fail; root records actual routes.
               and isinstance(snapshot.get("gateways_ipv4"), list)
               and snapshot["gateways_ipv4"] == manifest.get("gateways_ipv4"))
        report["normal_firewall_state_hash"] = snapshot.get("normal_firewall_state_hash", snapshot.get("firewall_state_hash"))
        test_path = Path("/etc/phishing-study/fixture-test-report.json")
        fixture_path = Path("/etc/phishing-study/fixture-report.json")
        _check(report, "vm_fixtures", root_readonly(test_path) and root_readonly(fixture_path)
               and fixture_evidence(_read(test_path), _read(fixture_path))
               and snapshot.get("fixture_source_hash") == identity["source_hash"])
        if not all(value["ok"] for value in report["checks"].values()):
            return report
        if phase == "normal":
            policy = Policy(config)
            urls = [manifest["owned_controls"][key] for key in ("http_url", "https_url", "redirect_url")]
            dns_hostname = manifest["owned_controls"]["dns_template"].replace("{nonce}", "normal" + nonce)
            urls.append("http://" + dns_hostname + "/")
            admissions = await asyncio.gather(*(policy.check(url) for url in urls))
            _check(report, "initial_owned_destination_policy", all(allowed for allowed, _ in admissions))
        else:
            prior_path = Path(f"/etc/phishing-study/evidence/{nonce}/normal/phase-report.json")
            prior = _read(prior_path)
            _check(report, "prior_normal_phase", root_readonly(prior_path) and prior.get("status") == "phase-passed"
                   and prior.get("nonce") == nonce and NORMAL_CHECKS.issubset(prior.get("checks", {}))
                   and all(value.get("ok") is True for value in prior.get("checks", {}).values())
                   and all(prior.get(key) == value for key, value in identity.items()))
        if not all(value["ok"] for value in report["checks"].values()):
            return report
        results = await _browser_probe(manifest, config, output, phase, nonce)
        report["owned_probe"] = results
        report["versions"]["chromium"] = results.get("chromium_version")
        _check(report, "sandbox_and_guard", results.get("sandbox_requested") and results.get("redirect_guard")
               and results.get("renderer_sandbox_verified"))
        _check(report, "chromium_dns_configuration", results["netlog_dns"]["ok"])
        if phase == "normal":
            _check(report, "owned_http_https", results["http"]["ok"] and results["https"]["ok"])
            _check(report, "owned_denied_redirect", results["redirect"]["denied_redirect"])
            _check(report, "fresh_browser_dns", results["fresh_dns"]["ok"])
            from .metadata import dns_metadata, tls_metadata
            dns = await dns_metadata(manifest["owned_controls"]["https_url"], config)
            tls = await tls_metadata(manifest["owned_controls"]["https_url"], config)
            report["owned_metadata"] = {"dns": dns, "tls": tls}
            report["tls_verified"] = tls.get("measured") is True
            report["public_dns_verified"] = dns.get("measured") is True
            _check(report, "owned_tls_public_dns", report["tls_verified"] and report["public_dns_verified"])
        else:
            _check(report, "fresh_browser_dns_blocked", not results["fresh_dns"]["ok"]
                   and results["fresh_dns"].get("dns_failure") is True)
        deny = manifest["expected_deny"]
        endpoints = [("127.0.0.1", 80), ("0.0.0.0", 80), ("169.254.169.254", 80),
                     (deny["owned_ipv4"], deny["owned_port"]), (deny["owned_public_ipv4"], deny["owned_port"]),
                     (deny["owned_public_ipv4"], 53),
                     ("::ffff:" + deny["owned_ipv4"], deny["owned_port"]), (deny["owned_ipv6"], 443), ("::1", 80)]
        endpoints += [(address, 80) for address in snapshot.get("local_ipv4", []) + snapshot.get("gateways_ipv4", [])]
        denied = await asyncio.gather(*(_connect_denied(address, port) for address, port in endpoints))
        _check(report, "denied_connections", all(denied), attempted=len(endpoints), denied=sum(denied))
        report["status"] = "phase-passed" if all(value["ok"] for value in report["checks"].values()) else "failed"
    except Exception as exc:
        report["error_type"] = type(exc).__name__
        report["reason"] = "deployment preflight incomplete; inspect prerequisites and owned diagnostic artifacts"
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "phase-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def combine_evidence(manifest, normal, blocked, receipt):
    """Pure matching/acceptance; root CLI additionally checks file ownership."""
    report = {"schema_version": 1, "status": "incomplete", "network_isolation_verified": False,
              "generated_at": datetime.now(timezone.utc).isoformat(), "checks": {},
              "tls_verified": False, "public_dns_verified": False}
    if not all(isinstance(value, dict) for value in (manifest, normal, blocked, receipt)):
        _check(report, "evidence_format", False)
        return report
    identity_match = all(normal.get(key) == blocked.get(key) and normal.get(key) == receipt.get(key)
                         and bool(normal.get(key)) for key in IDENTITY_KEYS)
    identity_match = identity_match and all(normal.get(key) == manifest.get(key)
                                           for key in IDENTITY_KEYS[:3])
    nonce = normal.get("nonce", "")
    _check(report, "matching_identity", identity_match and manifest_digest_valid(manifest)
           and isinstance(nonce, str) and HEX_NONCE.fullmatch(nonce) is not None
           and blocked.get("nonce") == nonce and receipt.get("nonce") == nonce)
    _check(report, "valid_phases", normal.get("phase") == "normal" and blocked.get("phase") == "dns-blocked"
           and all(phase.get("status") == "phase-passed" and isinstance(phase.get("checks"), dict)
                   and bool(phase["checks"])
                   and required.issubset(phase["checks"])
                   and all(isinstance(value, dict) and value.get("ok") is True for value in phase["checks"].values())
                   for phase, required in ((normal, NORMAL_CHECKS), (blocked, BLOCKED_CHECKS))))
    normal_receipt, blocked_receipt = receipt.get("normal", {}), receipt.get("dns-blocked", {})
    dns_hostname = normal.get("owned_probe", {}).get("dns_hostname")
    queries = normal_receipt.get("dns_queries", [])
    dns_ok = (isinstance(queries, list) and all(isinstance(item, dict) and isinstance(item.get("name"), str) for item in queries)
              and bool(dns_hostname) and any(item.get("name", "").rstrip(".") == dns_hostname
                                       and item.get("resolver_ipv4") == manifest["approved_resolver"] for item in queries)
              and all(item.get("resolver_ipv4") == manifest["approved_resolver"] for item in queries)
              and blocked_receipt.get("dns_queries") == [])
    _check(report, "approved_dns_receipts", dns_ok)
    _check(report, "zero_denied_receiver_hits", all(type(value.get("denied_receiver_requests")) is int
           and value["denied_receiver_requests"] == 0
           and type(value.get("denied_counter_delta")) is int and value["denied_counter_delta"] > 0
           for value in (normal_receipt, blocked_receipt)))
    deny = manifest.get("expected_deny", {})
    expected_receivers = {(deny.get("owned_ipv4"), deny.get("owned_port")),
                          (deny.get("owned_public_ipv4"), deny.get("owned_port")),
                          (deny.get("owned_ipv6"), 443)}
    receiver_controls = receipt.get("receiver_controls", [])
    _check(report, "owned_receivers_positive_controls", isinstance(receiver_controls, list) and bool(receiver_controls)
           and all(isinstance(item, dict) for item in receiver_controls)
           and {(item.get("address"), item.get("port")) for item in receiver_controls} == expected_receivers
           and all(item.get("nonce") == nonce and type(item.get("positive_control_hits")) is int
                   and item["positive_control_hits"] > 0 and type(item.get("normal_requests")) is int
                   and item["normal_requests"] == 0 and type(item.get("dns_blocked_requests")) is int
                   and item["dns_blocked_requests"] == 0 for item in receiver_controls))
    _check(report, "normal_firewall_restored", receipt.get("restored_firewall_state_hash") == normal.get("normal_firewall_state_hash")
           and bool(normal.get("normal_firewall_state_hash")))
    if all(value["ok"] for value in report["checks"].values()):
        report.update({key: normal[key] for key in IDENTITY_KEYS})
        report.update({"status": "passed", "network_isolation_verified": True, "nonce": nonce,
                       "normal_firewall_state_hash": normal["normal_firewall_state_hash"],
                       "tls_verified": normal.get("tls_verified") is True,
                       "public_dns_verified": normal.get("public_dns_verified") is True})
        report["versions"] = normal.get("versions", {})
        report["phase_timings_seconds"] = {"normal": normal.get("elapsed_seconds"), "dns-blocked": blocked.get("elapsed_seconds")}
    return report
