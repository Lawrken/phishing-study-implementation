"""Non-root worker for the disconnected generated public-web policy diagnostic.

The root controller owns isolation, fixtures, firewall changes and receipts.
This worker never invokes the research runner or changes a production gate.
"""
import argparse
import asyncio
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import re
import socket
import sys
import time
from urllib.parse import urlsplit

APP = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = Path("/var/lib/phishing-study-public/verification-private")
RESOLVER = "127.0.0.153"
SOCKET_CASES = ("private_ipv4_tcp", "public_shaped_nonweb_tcp", "ipv6_tcp",
                "alternate_dns_tcp", "alternate_dns_udp", "nonweb_udp_443", "resolver_web_tcp")
from .browser_lifecycle import Lifecycle, run_bounded
from .dns_evidence import categorical_page_error, correlated_netlog_dns_failure


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def check(report, name, passed, **details):
    report["checks"][name] = {"ok": bool(passed), **details}


def event(report, kind, **details):
    report["events"].append({"at": timestamp(), "kind": kind, **details})


def network_snapshot():
    interfaces = sorted(path.name for path in Path("/sys/class/net").iterdir())
    rows = Path("/proc/net/route").read_text().splitlines()[1:]
    default_routes = [line.split()[0] for line in rows if len(line.split()) > 1 and line.split()[1] == "00000000"]
    ipv6_rows = Path("/proc/net/ipv6_route").read_text().splitlines()
    ipv6_defaults = [line.split()[-1] for line in ipv6_rows
                     if len(line.split()) >= 10 and line.split()[0] == "0" * 32
                     and line.split()[1] == "00" and line.split()[-1] != "lo"]
    return {"interfaces": interfaces, "default_route_interfaces": default_routes,
            "ipv6_default_route_interfaces": ipv6_defaults,
            "loopback_only_without_default_route": interfaces == ["lo"] and not default_routes and not ipv6_defaults}


def guard_state(guard):
    return {"closed": guard._closed, "failed": guard.failed,
            "failure_reason": guard.failure_reason,
            "owners": len(guard._owners), "contexts": len(guard._contexts),
            "frames": len(guard._frames), "tasks": len(guard._tasks),
            "pending": len(guard._pending), "task_owners": len(guard._task_owners)}






async def browser_phase(report, output, phase, nonce):
    from playwright.async_api import async_playwright
    from study.config import Config
    from study.deployment_checks import _browser_process_evidence, _sandbox_evidence, dns_failure_code, netlog_dns
    from study.policy import Policy
    from study.redirects import RedirectGuard

    hostname = report.get("label", phase) + nonce + ".controls.test"
    url = "http://" + hostname + ("/redirect" if phase == "redirect" else "/")
    report.update({"dns_hostname": hostname, "requested_url": url})
    config = Config(profile="live", workers=1, route_id="disconnected-local-control",
                    region="laboratory-only", network_isolation_verified=False)
    config.validate()
    policy = Policy(config)
    browser = guard = context = owner = None
    lifecycle = Lifecycle(report, event_path=output / "lifecycle-events.jsonl")
    guard_failures, denied_redirects, dns_failures, page_error_codes = [], [], [], []
    netlog = output / "netlog.json"
    response_status, navigation_error = None, None
    try:
        started, playwright = await lifecycle.stage("driver_start", async_playwright().start)
        if not started:
            check(report, "driver_started", False)
            raise RuntimeError("driver_start_failed")
        lifecycle.driver = playwright
        launched, browser = await lifecycle.stage("browser_launch", lambda:
            playwright.chromium.launch(headless=True, chromium_sandbox=True,
            timeout=30000, args=["--log-net-log=" + str(netlog)]))
        if not launched:
            check(report, "chromium_started", False)
            raise RuntimeError("browser_launch_failed")
        lifecycle.browser = browser
        await lifecycle.capture_browser_identity()
        report["chromium_version"] = browser.version
        check(report, "chromium_started", True)
        report["browser_process"] = await _browser_process_evidence(browser)
        check(report, "owned_sandboxed_browser_process", report["browser_process"].get("ok") is True)
        guard = await RedirectGuard.start(browser)
        lifecycle.guard = guard
        check(report, "guard_started_before_context", not guard.failed)
        context = await browser.new_context(service_workers="block", accept_downloads=False,
            viewport={"width": 1365, "height": 768}, locale="en-US", timezone_id="UTC")
        lifecycle.context = context

        async def route(request_route):
            request = request_route.request
            parsed = urlsplit(request.url)
            allowed = (parsed.scheme == "http" and parsed.hostname == hostname
                       and parsed.port in {None, 80} and not parsed.username
                       and not parsed.password and request.method == "GET")
            event(report, "request_route", url=request.url, method=request.method, allowed=allowed)
            if allowed:
                await request_route.continue_()
            else:
                await request_route.abort()

        async def websocket(websocket_route):
            event(report, "websocket_blocked")
            await websocket_route.close()

        async def redirect(target, paused):
            allowed, reason = await policy.check(target)
            parsed = urlsplit(target)
            expected = (phase == "redirect" and target == "http://10.0.0.2:8443/")
            event(report, "redirect_checked", target=target, policy_allowed=allowed,
                  reason=reason, expected_fixture=expected)
            if expected and not allowed:
                denied_redirects.append(reason)
            elif phase == "redirect":
                guard_failures.append("redirect_fixture_or_policy_mismatch")
            return (phase != "redirect" and allowed and parsed.scheme == "http"
                    and parsed.hostname == hostname and parsed.port in {None, 80})

        async def failure(reason):
            guard_failures.append(reason)
            event(report, "guard_failure", reason=reason)
            await context.close()

        await context.route("**/*", route)
        await context.route_web_socket("**/*", websocket)
        page = await context.new_page()

        def request_failed(request):
            code = dns_failure_code(request.failure)
            page_code = categorical_page_error(request.failure)
            if page_code:
                page_error_codes.append(page_code)
            event(report, "request_failed", url=request.url, dns_failure_code=code,
                  native_error_code=page_code)
            if code:
                dns_failures.append(code)

        page.on("requestfailed", request_failed)
        owner = await guard.register(page, redirect, failure)
        lifecycle.owner = owner
        check(report, "owner_registered_before_navigation", owner.active and owner in guard._owners)
        await page.goto("about:blank", wait_until="domcontentloaded", timeout=10000)
        report["sandbox_before_navigation"] = await _sandbox_evidence(browser)
        check(report, "renderer_sandbox_before_navigation", report["sandbox_before_navigation"])
        event(report, "navigation_started", url=url)
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            response_status = response.status if response else None
        except Exception as exc:
            navigation_error = type(exc).__name__
            page_code = categorical_page_error(str(exc))
            if page_code:
                page_error_codes.append(page_code)
            code = dns_failure_code(str(exc))
            if code:
                dns_failures.append(code)
        event(report, "navigation_finished", status=response_status, error_type=navigation_error)
        report["sandbox_after_navigation"] = await _sandbox_evidence(browser)
        report["navigation"] = {"status": response_status, "error_type": navigation_error,
            "dns_error_codes": sorted(set(dns_failures)), "redirect_denials": denied_redirects,
            "guard_failures": guard_failures, "page_native_error_codes": sorted(set(page_error_codes))}
        if phase in {"normal", "restored"}:
            check(report, "http_200", response_status == 200 and navigation_error is None)
            marker = await page.locator("body").inner_text(timeout=3000)
            report["dom_control_marker"] = marker.strip() == "LOCAL CONTROL"
            check(report, "controlled_dom_observed", report["dom_control_marker"])
            check(report, "renderer_sandbox_after_navigation", report["sandbox_after_navigation"])
        elif phase == "blocked":
            decisive_page_codes = [code for code in dns_failures if "TIMED_OUT" not in code and "TIMEOUT" not in code]
            check(report, "page_only_native_dns_failure", bool(decisive_page_codes) and response_status is None
                  and navigation_error != "TimeoutError", codes=sorted(set(decisive_page_codes)))
        else:
            check(report, "redirect_denied_by_production_policy", bool(denied_redirects)
                  and not guard_failures and response_status is None)
        check(report, "no_guard_failures", not guard_failures and not guard.failed)
    except asyncio.CancelledError:
        lifecycle.cancelled = True
        raise
    finally:
        await lifecycle.cleanup()
    if netlog.is_file():
        try:
            raw_netlog = json.loads(netlog.read_text())
            report["netlog_dns"] = netlog_dns(raw_netlog, RESOLVER, hostname)
            if phase == "blocked":
                report["correlated_netlog_dns_failure"] = correlated_netlog_dns_failure(raw_netlog, hostname)
            if phase != "redirect":
                check(report, "effective_browser_dns", report["netlog_dns"].get("ok") is True)
        except (OSError, ValueError, TypeError) as exc:
            check(report, "effective_browser_dns", False, error_type=type(exc).__name__)
    elif phase != "redirect":
        check(report, "effective_browser_dns", False, reason="netlog_missing")
    if phase == "blocked":
        page_only = report["checks"].pop("page_only_native_dns_failure", {"ok": False})
        report["page_only_native_dns_failure"] = page_only
        correlated = report.get("correlated_netlog_dns_failure", {"ok": False})
        check(report, "native_dns_failure", response_status is None and navigation_error != "TimeoutError"
              and (page_only["ok"] or correlated.get("ok") is True),
              method="page_native_dns_error" if page_only["ok"] else correlated.get("method", "missing"),
              page_native_error_codes=sorted(set(page_error_codes)),
              resolver_native_dns_error_codes=correlated.get("dns_error_codes", []))


def socket_attempt(name, address, port, transport, payload):
    started = time.monotonic()
    result = {"name": name, "address": address, "port": port, "transport": transport,
              "socket_created": False, "categorical_denial": False, "response_received": False}
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    try:
        with socket.socket(family, kind) as connection:
            result["socket_created"] = True
            connection.settimeout(2)
            connection.connect((address, port))
            if transport == "tcp":
                result["connected"] = True
                if payload:
                    connection.sendall(payload)
                result["reason"] = "unexpected_connection_allowed"
            else:
                connection.send(payload)
                data = connection.recv(4096)
                result["response_received"] = bool(data)
                result["reason"] = "unexpected_udp_response" if data else "empty_udp_response"
    except TimeoutError:
        result["reason"] = "timeout_is_inconclusive"
    except OSError as exc:
        result["errno"] = exc.errno
        result["errno_name"] = errno.errorcode.get(exc.errno, "UNKNOWN")
        result["reason"] = "categorical_socket_error"
        result["categorical_denial"] = (result["socket_created"] and not result.get("connected") and exc.errno in {
            errno.EACCES, errno.EPERM, errno.ECONNREFUSED, errno.ENETUNREACH,
            errno.EHOSTUNREACH, errno.ECONNRESET})
    result["elapsed_seconds"] = round(time.monotonic() - started, 4)
    return result


async def socket_phase(report, nonce):
    import dns.message
    query = dns.message.make_query("socket" + nonce + ".controls.test", "A").to_wire()
    marker = ("LOCAL-CONTROLS " + nonce + "\n").encode("ascii")
    probes = [
        ("private_ipv4_tcp", "10.0.0.2", 8443, "tcp", marker),
        ("public_shaped_nonweb_tcp", "93.184.216.34", 8443, "tcp", marker),
        ("ipv6_tcp", "2001:4860::1234", 443, "tcp", marker),
        ("alternate_dns_tcp", "93.184.216.36", 53, "tcp", len(query).to_bytes(2, "big") + query),
        ("alternate_dns_udp", "93.184.216.36", 53, "udp", query),
        ("nonweb_udp_443", "93.184.216.34", 443, "udp", marker),
        ("resolver_web_tcp", "93.184.216.34", 80, "tcp", marker),
    ]
    report["socket_probes"] = []
    for arguments in probes:
        if report.get("socket_case") and arguments[0] != report["socket_case"]:
            continue
        result = await asyncio.to_thread(socket_attempt, *arguments)
        report["socket_probes"].append(result)
        event(report, "socket_probe", **result)
        check(report, arguments[0], result["categorical_denial"],
              reason=result.get("reason"), errno_name=result.get("errno_name"))


def dns_positive(phase, nonce, transport, server=RESOLVER):
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype
    hostname = transport + phase + nonce + ".controls.test"
    result = {"hostname": hostname, "transport": transport, "ok": False}
    try:
        query = dns.message.make_query(hostname, "A")
        function = dns.query.udp if transport == "udp" else dns.query.tcp
        response = function(query, server, timeout=3)
        addresses = [item.address for answer in response.answer if answer.rdtype == dns.rdatatype.A for item in answer]
        result.update({"rcode": dns.rcode.to_text(response.rcode()), "addresses": addresses,
                       "ok": response.rcode() == dns.rcode.NOERROR and addresses == ["93.184.216.34"]})
    except Exception as exc:
        result["error_type"] = type(exc).__name__
    return result


async def run(report, output, phase, nonce):
    import pwd
    from study.deployment import source_files, source_hash
    from study.deployment_checks import resource_limits, root_readonly
    from study.public_web import validate_public_bundle
    manifest = validate_public_bundle(report["bundle"], root=APP)
    expected = manifest["resolver"]["uid"] if report["role"] == "resolver" else manifest["study_uid"]
    gid = pwd.getpwuid(expected).pw_gid
    check(report, "non_root_fixture_identity", os.geteuid() == expected and os.getegid() == gid
          and not os.getgroups())
    report["identity"] = {"uid": os.geteuid(), "gid": os.getegid(), "supplementary_groups": os.getgroups()}
    report["network"] = network_snapshot()
    check(report, "disconnected_namespace", report["network"]["loopback_only_without_default_route"])
    report["resources"] = resource_limits()
    check(report, "bounded_resources", report["resources"].get("ok") is True
          and int(report["resources"].get("memory_max", 0)) <= 2 * 1024 ** 3)
    report["source_hash"] = source_hash(APP)
    check(report, "manifest_source_identity", report["source_hash"] == manifest["source_hash"])
    check(report, "root_owned_source", all(root_readonly(path) for path in source_files(APP)))
    report["resolver"] = Path("/etc/resolv.conf").read_text()
    check(report, "local_resolver_binding", [line.split("#", 1)[0].strip() for line in report["resolver"].splitlines()
          if line.split("#", 1)[0].strip().startswith("nameserver")] == ["nameserver " + RESOLVER])
    if not all(item["ok"] for item in report["checks"].values()):
        return
    if phase == "resolver":
        report["resolver_stub_positives"] = []
        for transport in ("udp", "tcp"):
            result = await asyncio.to_thread(dns_positive, "stub", nonce, transport, "127.0.0.53")
            report["resolver_stub_positives"].append(result)
            check(report, "resolver_stub_" + transport, result["ok"])
    elif phase == "sockets":
        await socket_phase(report, nonce)
    else:
        if phase in {"normal", "restored"}:
            report["non_root_dns_positives"] = []
            for transport in ("udp", "tcp"):
                positive = await asyncio.to_thread(dns_positive, report.get("label", phase), nonce, transport)
                report["non_root_dns_positives"].append(positive)
                event(report, "non_root_dns_positive", **positive)
                check(report, "non_root_" + transport + "_dns_positive", positive["ok"])
        await browser_phase(report, output, phase, nonce)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("normal", "blocked", "restored", "redirect", "sockets", "resolver"), required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--socket-case", choices=SOCKET_CASES)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--role", choices=("workload", "resolver"), default="workload")
    parser.add_argument("--label", help="fresh synthetic single DNS label prefix")
    args = parser.parse_args()
    if args.socket_case and args.phase != "sockets":
        parser.error("--socket-case is restricted to --phase sockets")
    if ((args.role == "resolver") != (args.phase == "resolver" or args.socket_case == "resolver_web_tcp")
            or args.label and re.fullmatch("[a-z0-9]{1,24}", args.label) is None):
        parser.error("resolver role is restricted to resolver policy probes; label must be synthetic")
    output = args.output.absolute()
    if (not re.fullmatch("[0-9a-f]{32}", args.nonce)
            or not output.resolve().is_relative_to(OUTPUT_ROOT)
            or output.exists() or output.is_symlink()):
        raise SystemExit("A fresh private fixture-only output directory and 32-hex nonce are required")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.umask(0o077)
    started = time.monotonic()
    report = {"schema_version": 1, "started_at": timestamp(), "phase": args.phase, "nonce": args.nonce,
        "status": "failed", "diagnostic_only": True, "synthetic_disconnected_fixtures": True,
        "research_eligible": False, "network_isolation_verified": False,
        "public_dns_verified": False, "public_tls_verified": False,
        "research_collection_count": 0, "checks": {}, "events": [],
        "bundle": str(args.bundle.absolute()), "role": args.role, "label": args.label or args.phase}
    if args.socket_case:
        report["socket_case"] = args.socket_case
    try:
        run_bounded(run(report, output, args.phase, args.nonce), timeout=90, cleanup_seconds=60, report=report)
        report["status"] = "passed" if report["checks"] and all(item["ok"] for item in report["checks"].values()) else "failed"
    except (Exception, asyncio.CancelledError) as exc:
        report["error_type"] = type(exc).__name__
    finally:
        report["finished_at"] = timestamp()
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        events = report.pop("events")
        with (output / "events.jsonl").open("x", encoding="utf-8") as stream:
            for item in events:
                stream.write(json.dumps(item, sort_keys=True) + "\n")
        with (output / "report.json").open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    print(json.dumps({"phase": args.phase, "status": report["status"], "output": str(output)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
