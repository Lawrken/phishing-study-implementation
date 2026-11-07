import asyncio
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from study.deployment_checks import (BLOCKED_CHECKS, FIXTURE_CHECKS, IDENTITY_KEYS, NORMAL_CHECKS,
                                     combine_evidence, fixture_evidence, missing_inputs, netlog_dns,
                                     resolver_valid, resource_limits, run_phase, systemd_address_families,
                                     _browser_probe, _browser_process_evidence, _connect_denied, dns_failure_code)


def manifest():
    value = {"schema_version": 1, "dedicated_vm": True, "route_id": "direct-ipv4", "region": "test-region",
            "approved_resolver": "8.8.8.8", "study_uid": 1001,
            "owned_controls": {"http_url": "http://owned.example/", "https_url": "https://owned.example/",
                               "dns_template": "{nonce}.owned.example", "redirect_url": "https://owned.example/redirect"},
            "expected_deny": {"owned_ipv4": "10.20.30.40", "owned_ipv6": "2001:4860::1234",
                              "owned_port": 8443, "owned_public_ipv4": "8.8.4.4"},
            **{key: key + "-digest" for key in IDENTITY_KEYS[:3]}}
    from study.deployment import digest_json
    value["configuration_hash"] = digest_json({key: item for key, item in value.items() if key != "configuration_hash"})
    return value


def evidence():
    configured = manifest()
    identities = {key: configured.get(key, key + "-digest") for key in IDENTITY_KEYS}
    base = {**identities, "nonce": "a" * 32, "normal_firewall_state_hash": "normal-nft-digest"}
    normal = {**base, "status": "phase-passed", "phase": "normal", "checks": {key: {"ok": True} for key in NORMAL_CHECKS},
              "owned_probe": {"dns_hostname": "normal" + "a" * 32 + ".owned.example"},
              "tls_verified": True, "public_dns_verified": True}
    blocked = {**base, "status": "phase-passed", "phase": "dns-blocked", "checks": {key: {"ok": True} for key in BLOCKED_CHECKS}}
    receipt = {**base, "normal": {"denied_counter_delta": 2, "denied_receiver_requests": 0,
                                  "dns_queries": [{"name": normal["owned_probe"]["dns_hostname"], "resolver_ipv4": "8.8.8.8"}]},
               "dns-blocked": {"denied_counter_delta": 1, "denied_receiver_requests": 0, "dns_queries": []},
               "restored_firewall_state_hash": "normal-nft-digest",
               "receiver_controls": [{"address": address, "port": port, "nonce": "a" * 32,
                                      "positive_control_hits": 1, "normal_requests": 0, "dns_blocked_requests": 0}
                                     for address, port in (("10.20.30.40", 8443), ("8.8.4.4", 8443), ("2001:4860::1234", 443))]}
    return configured, normal, blocked, receipt


class DeploymentChecksTests(unittest.TestCase):
    def browser_process_probe(self, *, command_extra=(), uids="1001 1001 1001 1001", pids=None,
                              root_owned=True, connected=True, missing_command=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proc = root / "1234"
            proc.mkdir()
            binary = proc / "exe"
            binary.write_bytes(b"owned browser fixture")
            command = [str(binary.resolve()), *command_extra]
            if not missing_command:
                (proc / "cmdline").write_bytes(b"\0".join(x.encode() for x in command) + b"\0")
            (proc / "status").write_text("Uid:\t" + uids + "\n")
            (proc / "stat").write_text("1234 (headless shell) " + " ".join(["0"] * 19 + ["42"]) + "\n")
            cdp = SimpleNamespace(send=AsyncMock(return_value={"processInfo": [
                {"type": "browser", "id": pid} for pid in ([1234] if pids is None else pids)]}), detach=AsyncMock())
            browser = SimpleNamespace(new_browser_cdp_session=AsyncMock(return_value=cdp), is_connected=lambda: connected)
            with patch("study.deployment_checks.os.geteuid", return_value=1001, create=True), \
                 patch("study.deployment_checks.root_readonly", return_value=root_owned):
                result = asyncio.run(_browser_process_evidence(browser, root))
            cdp.detach.assert_awaited_once()
            cdp.send.assert_awaited_once_with("SystemInfo.getProcessInfo")
            self.assertNotIn(str(binary), json.dumps(result))
            return result

    def test_browser_process_inspection_works_without_enable_automation(self):
        result = self.browser_process_probe(command_extra=("--headless",))
        self.assertTrue(result["ok"])
        self.assertEqual(result["method"], "SystemInfo browser PID plus /proc")

    def test_browser_process_inspection_rejects_sandbox_disabling_flags(self):
        for arg in ("--no-sandbox", "--no-sandbox=true", "--disable-setuid-sandbox",
                    "--disable-namespace-sandbox", "--disable-seccomp-filter-sandbox", "--disable-gpu-sandbox"):
            with self.subTest(arg=arg):
                self.assertFalse(self.browser_process_probe(command_extra=(arg,))["ok"])

    def test_browser_process_inspection_rejects_wrong_uid_and_writable_binary(self):
        for values in ({"uids": "0 0 0 0"}, {"uids": "1001 1001 1001 0"}, {"root_owned": False}):
            with self.subTest(values=values):
                self.assertFalse(self.browser_process_probe(**values)["ok"])

    def test_browser_process_inspection_rejects_missing_or_ambiguous_pid(self):
        for pids in ([], [1234, 1235], [True], [-1], ["1234"]):
            with self.subTest(pids=pids):
                self.assertFalse(self.browser_process_probe(pids=pids)["ok"])

    def test_browser_process_inspection_rejects_missing_proc_or_disconnected_browser(self):
        for values in ({"missing_command": True}, {"connected": False}):
            with self.subTest(values=values):
                self.assertFalse(self.browser_process_probe(**values)["ok"])

    def test_browser_process_inspection_rejects_root_before_cdp(self):
        browser = SimpleNamespace(new_browser_cdp_session=AsyncMock())
        with patch("study.deployment_checks.os.geteuid", return_value=0, create=True):
            result = asyncio.run(_browser_process_evidence(browser))
        self.assertFalse(result["ok"])
        browser.new_browser_cdp_session.assert_not_awaited()

    def test_browser_probe_stops_before_navigation_if_process_inspection_fails(self):
        browser = SimpleNamespace(version="test", close=AsyncMock(), new_context=AsyncMock())
        guard = SimpleNamespace(close=AsyncMock(), failed=False)
        class Driver:
            async def __aenter__(self):
                return SimpleNamespace(chromium=SimpleNamespace(launch=AsyncMock(return_value=browser)))
            async def __aexit__(self, *args):
                return False
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict("sys.modules", {"playwright.async_api": SimpleNamespace(async_playwright=Driver)}), \
             patch("study.redirects.RedirectGuard.start", new=AsyncMock(return_value=guard)), \
             patch("study.deployment_checks._browser_process_evidence", new=AsyncMock(return_value={"ok": False})):
            with self.assertRaisesRegex(RuntimeError, "browser_process_inspection_failed"):
                asyncio.run(_browser_probe(manifest(), SimpleNamespace(proxy=lambda: None), Path(directory), "normal", "a" * 32))
        browser.new_context.assert_not_awaited()
        guard.close.assert_awaited_once()
        browser.close.assert_awaited_once()

    def test_complete_inputs_are_accepted(self):
        self.assertEqual(missing_inputs(manifest()), [])

    def test_missing_owned_controls_prevent_any_probe_and_save_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deployment = root / "deployment.json"
            deployment.write_text(json.dumps({"schema_version": 1}))
            with patch("study.deployment_checks._browser_probe", side_effect=AssertionError("must not visit")):
                result = asyncio.run(run_phase(deployment, root / "out", "normal", "a" * 32))
            saved = json.loads((root / "out" / "phase-report.json").read_text())
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(saved, result)
            self.assertFalse(result["network_isolation_verified"])

    def test_invalid_control_and_resolver_forms_are_rejected(self):
        for change in (lambda m: m.update(approved_resolver="127.0.0.53"),
                       lambda m: m.update(approved_resolver="2001:4860::8888"),
                       lambda m: m["owned_controls"].update(http_url="http://user:pass@owned.example/"),
                       lambda m: m["owned_controls"].update(dns_template="owned.example"),
                       lambda m: m["owned_controls"].update(dns_template="{nonce}.host.local"),
                       lambda m: m["expected_deny"].update(owned_port=443),
                       lambda m: m["expected_deny"].update(owned_ipv4="8.8.8.8")):
            value = manifest()
            change(value)
            with self.subTest(value=value):
                self.assertTrue(missing_inputs(value))

    def test_direct_resolver_without_nss_fallback(self):
        self.assertTrue(resolver_valid("nameserver 8.8.8.8\noptions timeout:2 attempts:1\n", "hosts: files dns\n", "8.8.8.8"))
        for resolv, nss in (("nameserver 8.8.8.8\nnameserver 1.1.1.1", "hosts: files dns"),
                            ("nameserver 127.0.0.53", "hosts: files dns"),
                            ("nameserver 8.8.8.8\nsearch internal", "hosts: files dns"),
                            ("nameserver 8.8.8.8", "hosts: files mdns4_minimal dns"),
                            ("nameserver 8.8.8.8", "hosts: files resolve dns")):
            self.assertFalse(resolver_valid(resolv, nss, "8.8.8.8"))

    def test_resource_ceiling_requires_bounded_cgroup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "proc-cgroup").write_text("0::/service\n")
            group = root / "service"
            group.mkdir()
            (group / "cpu.max").write_text("200000 100000")
            (group / "memory.max").write_text(str(4 * 1024 ** 3))
            (group / "pids.max").write_text("512")
            self.assertTrue(resource_limits(root, root / "proc-cgroup")["ok"])
            for key, invalid in (("cpu.max", "max 100000"), ("memory.max", "max"), ("pids.max", "513")):
                previous = (group / key).read_text()
                (group / key).write_text(invalid)
                self.assertFalse(resource_limits(root, root / "proc-cgroup")["ok"])
                (group / key).write_text(previous)

    def test_effective_systemd_address_family_property_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cgroup"
            path.write_text("0::/system.slice/study-verify-normal.service\n")
            with patch("study.deployment_checks.subprocess.check_output", return_value="AF_UNIX AF_INET AF_NETLINK\n"):
                self.assertTrue(systemd_address_families("normal", path)["ok"])
            with patch("study.deployment_checks.subprocess.check_output", return_value="AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"):
                self.assertFalse(systemd_address_families("normal", path)["ok"])
            self.assertFalse(systemd_address_families("dns-blocked", path)["ok"])

    def test_os_address_family_rejection_is_a_denied_connection(self):
        async def probe():
            fake_socket = SimpleNamespace(AF_INET6=10, AF_INET=2, SOCK_STREAM=1,
                                          socket=Mock(side_effect=OSError("Address family restricted")))
            with patch("study.deployment_checks.socket", fake_socket):
                return await _connect_denied("::1", 80)
        self.assertTrue(asyncio.run(probe()))

    def test_browser_closed_if_guard_startup_fails(self):
        browser = SimpleNamespace(version="test", close=AsyncMock())
        chromium = SimpleNamespace(launch=AsyncMock(return_value=browser))
        class Driver:
            async def __aenter__(self):
                return SimpleNamespace(chromium=chromium)
            async def __aexit__(self, *args):
                return False
        module = SimpleNamespace(async_playwright=Driver)
        with tempfile.TemporaryDirectory() as directory, patch.dict("sys.modules", {"playwright.async_api": module}), \
             patch("study.redirects.RedirectGuard.start", new=AsyncMock(side_effect=RuntimeError("guard unavailable"))):
            with self.assertRaises(RuntimeError):
                asyncio.run(_browser_probe(manifest(), SimpleNamespace(proxy=lambda: None), Path(directory), "normal", "a" * 32))
        browser.close.assert_awaited_once()

    def test_context_closed_if_owner_registration_fails(self):
        page = SimpleNamespace(goto=AsyncMock(), on=Mock())
        baseline = SimpleNamespace(new_page=AsyncMock(return_value=page), close=AsyncMock())
        attempted = SimpleNamespace(new_page=AsyncMock(return_value=page), route=AsyncMock(), close=AsyncMock())
        cdp = SimpleNamespace(send=AsyncMock(return_value={"arguments": ["/root-owned/browser"]}), detach=AsyncMock())
        browser = SimpleNamespace(version="test", close=AsyncMock(), new_browser_cdp_session=AsyncMock(return_value=cdp),
                                  new_context=AsyncMock(side_effect=[baseline, attempted]))
        chromium = SimpleNamespace(launch=AsyncMock(return_value=browser))
        guard = SimpleNamespace(register=AsyncMock(side_effect=RuntimeError("owner registration failed")), close=AsyncMock(), failed=False)
        class Driver:
            async def __aenter__(self):
                return SimpleNamespace(chromium=chromium)
            async def __aexit__(self, *args):
                return False
        config = SimpleNamespace(proxy=lambda: None, viewport_width=1365, viewport_height=768, locale="en-US", timezone="UTC")
        with tempfile.TemporaryDirectory() as directory, patch.dict("sys.modules", {"playwright.async_api": SimpleNamespace(async_playwright=Driver)}), \
             patch("study.redirects.RedirectGuard.start", new=AsyncMock(return_value=guard)), \
             patch("study.deployment_checks._browser_process_evidence", new=AsyncMock(return_value={"ok": True})), \
             patch("study.deployment_checks._sandbox_evidence", new=AsyncMock(return_value=True)):
            with self.assertRaises(RuntimeError):
                asyncio.run(_browser_probe(manifest(), config, Path(directory), "normal", "a" * 32))
        attempted.close.assert_awaited_once()
        guard.close.assert_awaited_once()
        browser.close.assert_awaited_once()

    def test_netlog_effective_off_and_fresh_lookup(self):
        log = {"constants": {"logEventTypes": {"DNS_CONFIG_CHANGED": 1, "HOST_RESOLVER_MANAGER_REQUEST": 2}},
               "events": [{"type": 1, "params": {"secure_dns_mode": 0, "doh_servers": [], "nameservers": ["8.8.8.8:53"]}},
                          {"type": 2, "params": {"host": "http://normalnonce.owned.example:80"}}]}
        self.assertTrue(netlog_dns(log, "8.8.8.8", "normalnonce.owned.example")["ok"])
        for key, invalid in (("secure_dns_mode", 1), ("doh_servers", ["https://resolver/dns-query"]),
                             ("nameservers", ["8.8.8.8:53", "1.1.1.1:53"]), ("fallback_doh_nameservers", ["1.1.1.1:443"]),
                             ("dns_over_tls_active", True)):
            changed = deepcopy(log)
            changed["events"][0]["params"][key] = invalid
            self.assertFalse(netlog_dns(changed, "8.8.8.8", "normalnonce.owned.example")["ok"])
        self.assertFalse(netlog_dns(log, "8.8.8.8", "missingnonce.owned.example")["ok"])

    def test_unknown_netlog_or_missing_doh_evidence_is_not_pass(self):
        for log in ({}, {"events": [{"type": "DNS_CONFIG_CHANGED", "params": {"secure_dns_mode": 0, "nameservers": ["8.8.8.8:53"]}}]}):
            self.assertFalse(netlog_dns(log, "8.8.8.8", "nonce.owned.example")["ok"])

    def test_newer_doh_config_serialization(self):
        log = {"events": [{"type": "DNS_CONFIG_CHANGED", "params": {"dns_config": {"secure_dns_mode": 0, "doh_config": {"servers": []}, "nameservers": ["8.8.8.8:53"]}}},
                          {"type": "HOST_RESOLVER_MANAGER_REQUEST", "params": {"host": "nonce.owned.example"}}]}
        self.assertTrue(netlog_dns(log, "8.8.8.8", "nonce.owned.example")["ok"])

    def test_pinned_polled_dns_configuration_and_exact_nonce_hostname(self):
        config = {"secure_dns_mode": 0, "doh_config": {"servers": []}, "fallback_doh_nameservers": [],
                  "dns_over_tls_active": False, "nameservers": ["8.8.8.8:53"]}
        log = {"polledData": [{"hostResolverInfo": {"dns_config": config}}],
               "events": [{"type": "HOST_RESOLVER_MANAGER_REQUEST", "params": {"host": "http://nonce.owned.example:80"}}]}
        result = netlog_dns(log, "8.8.8.8", "nonce.owned.example")
        self.assertTrue(result["ok"])
        self.assertEqual(result["config_events"], 0)
        self.assertEqual(result["polled_configs"], 1)
        for host in ("http://nonce.owned.example.attacker.test/", "http://prefixnonce.owned.example/", "http://other.test/nonce.owned.example"):
            changed = deepcopy(log)
            changed["events"][0]["params"]["host"] = host
            self.assertFalse(netlog_dns(changed, "8.8.8.8", "nonce.owned.example")["ok"])
        changed = deepcopy(log)
        changed["polledData"][0]["hostResolverInfo"]["dns_config"]["secure_dns_mode"] = 1
        self.assertFalse(netlog_dns(changed, "8.8.8.8", "nonce.owned.example")["ok"])

    def test_dns_block_requires_native_dns_failure_not_any_timeout(self):
        for value in ("net::ERR_NAME_NOT_RESOLVED", "Page.goto: net::ERR_DNS_TIMED_OUT at http://owned.example/"):
            self.assertIsNotNone(dns_failure_code(value))
        for value in ("TimeoutError: http://owned.example/", "net::ERR_CONNECTION_REFUSED", "net::ERR_ABORTED", None):
            self.assertIsNone(dns_failure_code(value))

    def test_fixtures_require_original_browser_suite_and_all_assertions(self):
        tests = {"successful": True, "browser_required": True, "browser_verified": True, "tests_run": 120, "passed": 120,
                 "browser_tests": {"discovered": 18, "executed": 18, "passed": 18, "missing": []}, "skipped": [], "failures": 0, "errors": 0}
        fixture = {"status": "passed", "fixture_verified": True, "checks": dict.fromkeys(FIXTURE_CHECKS, True), "rows": 6,
                   "outcomes": {"captured": 3, "challenge": 1, "takedown": 1, "parked": 1}}
        self.assertTrue(fixture_evidence(tests, fixture))
        for change in (lambda t, f: t.update(passed=119), lambda t, f: t["browser_tests"].update(executed=17),
                       lambda t, f: t.update(skipped=["browser"]), lambda t, f: f["checks"].update(saved_artifacts_redacted=False),
                       lambda t, f: f.update(checks={})):
            t, f = deepcopy(tests), deepcopy(fixture)
            change(t, f)
            self.assertFalse(fixture_evidence(t, f))

    def test_matching_independent_receipts_produce_evidence(self):
        result = combine_evidence(*evidence())
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["network_isolation_verified"])
        self.assertTrue(result["tls_verified"])

    def test_mismatched_nonce_config_or_source_rejected(self):
        for key in ("nonce", *IDENTITY_KEYS):
            values = evidence()
            values[2][key] = "different"
            self.assertFalse(combine_evidence(*values)["network_isolation_verified"])

    def test_manifest_control_change_invalidates_recorded_hash(self):
        values = evidence()
        values[0]["owned_controls"]["http_url"] = "http://different-owned.example/"
        self.assertFalse(combine_evidence(*values)["network_isolation_verified"])

    def test_missing_or_false_required_phase_checks_rejected(self):
        for mutation in (lambda phase: phase.update(checks={"pretend": {"ok": True}}),
                         lambda phase: phase["checks"].update(fresh_browser_dns_blocked={"ok": False}),
                         lambda phase: phase.update(status="incomplete")):
            values = evidence()
            mutation(values[2])
            self.assertEqual(combine_evidence(*values)["status"], "incomplete")

    def test_dns_fallback_or_absent_query_receipt_rejected(self):
        for mutation in (lambda receipt: receipt["normal"].update(dns_queries=[]),
                         lambda receipt: receipt["normal"]["dns_queries"][0].update(resolver_ipv4="1.1.1.1"),
                         lambda receipt: receipt["dns-blocked"].update(dns_queries=[{"name": "leak"}])):
            values = evidence()
            mutation(values[3])
            self.assertFalse(combine_evidence(*values)["network_isolation_verified"])

    def test_owned_receiver_and_firewall_counter_both_required(self):
        for mutation in (lambda receipt: receipt["normal"].update(denied_receiver_requests=1),
                         lambda receipt: receipt["normal"].update(denied_counter_delta=0),
                         lambda receipt: receipt["dns-blocked"].pop("denied_receiver_requests"),
                         lambda receipt: receipt.update(restored_firewall_state_hash="different")):
            values = evidence()
            mutation(values[3])
            self.assertFalse(combine_evidence(*values)["network_isolation_verified"])

    def test_inactive_or_wrong_owned_receiver_cannot_prove_zero_hits(self):
        for mutation in (lambda receipt: receipt.update(receiver_controls=[]),
                         lambda receipt: receipt["receiver_controls"][0].update(positive_control_hits=0),
                         lambda receipt: receipt["receiver_controls"][0].update(address="10.0.0.99"),
                         lambda receipt: receipt["receiver_controls"][0].update(nonce="b" * 32),
                         lambda receipt: receipt["receiver_controls"][0].update(normal_requests=1)):
            values = evidence()
            mutation(values[3])
            self.assertFalse(combine_evidence(*values)["network_isolation_verified"])

    def test_ambiguous_evidence_types_are_rejected(self):
        for mutation in (lambda values: values[2].update(nonce=1234),
                         lambda values: values[2]["checks"].update(fresh_browser_dns_blocked=True),
                         lambda values: values[3]["normal"].update(denied_counter_delta=True),
                         lambda values: values[3]["receiver_controls"][0].update(normal_requests=False)):
            values = evidence()
            mutation(values)
            self.assertFalse(combine_evidence(*values)["network_isolation_verified"])


if __name__ == "__main__":
    unittest.main()
