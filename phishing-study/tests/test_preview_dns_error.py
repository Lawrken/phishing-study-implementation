"""Strict owned-control DNS parser regressions; no browser or network activity."""
import copy
import unittest

from study import dns_evidence as WORKER
HOST = "blocked" + "a" * 32 + ".controls.test"


def fixture():
    return {"constants": {"logEventTypes": {"HOST_RESOLVER_MANAGER_REQUEST": 77},
        "netError": {"ERR_NAME_NOT_RESOLVED": -105, "ERR_INTERNET_DISCONNECTED": -106,
                     "ERR_TIMED_OUT": -7, "ERR_DNS_TIMED_OUT": -803}}, "events": [
        {"type": 77, "phase": 1, "source": {"id": 2, "type": 30},
         "params": {"host": "http://" + HOST, "is_speculative": False}},
        {"type": 77, "phase": 2, "source": {"id": 2, "type": 30},
         "params": {"net_error": -105}}]}


class CorrelatedDnsTests(unittest.TestCase):
    def assert_rejected(self, log):
        self.assertFalse(WORKER.correlated_netlog_dns_failure(log, HOST)["ok"])

    def test_exact_correlated_native_name_error(self):
        result = WORKER.correlated_netlog_dns_failure(fixture(), HOST)
        self.assertTrue(result["ok"])
        self.assertEqual(result["dns_error_codes"], ["net::ERR_NAME_NOT_RESOLVED"])
        self.assertEqual(result["matches"][0]["begin_index"], 0)
        self.assertEqual(result["matches"][0]["end_index"], 1)

    def test_bare_host_and_case_normalization(self):
        log = fixture()
        log["events"][0]["params"]["host"] = HOST.upper() + "."
        self.assertTrue(WORKER.correlated_netlog_dns_failure(log, HOST)["ok"])

    def test_wrong_host_prefix_suffix_and_embedded_path(self):
        for host in ("wrong.controls.test", "x" + HOST, HOST + ".wrong.test",
                     "http://wrong.test/" + HOST, "http://wrong.test/?q=" + HOST,
                     "http://" + HOST + "/path", "http://" + HOST + "?q=1",
                     "http://" + HOST + "#fragment", "http://user@" + HOST):
            with self.subTest(host=host):
                log = fixture()
                log["events"][0]["params"]["host"] = host
                self.assert_rejected(log)

    def test_speculative_or_missing_speculative_marker(self):
        for speculative in (True, None, 0, "false"):
            with self.subTest(speculative=speculative):
                log = fixture()
                log["events"][0]["params"]["is_speculative"] = speculative
                self.assert_rejected(log)

    def test_wrong_source_id_or_type(self):
        for key, value in (("id", 3), ("type", 31)):
            log = fixture()
            log["events"][1]["source"][key] = value
            self.assert_rejected(log)

    def test_wrong_event_kind_or_phase(self):
        for key, value in (("type", 78), ("phase", 0), ("phase", "2")):
            log = fixture()
            log["events"][1][key] = value
            self.assert_rejected(log)

    def test_no_end_or_no_begin(self):
        for selection in ([fixture()["events"][0]], [fixture()["events"][1]], []):
            log = fixture()
            log["events"] = selection
            self.assert_rejected(log)

    def test_end_before_begin_rejected(self):
        log = fixture()
        log["events"].reverse()
        self.assert_rejected(log)

    def test_duplicate_begin_or_end_rejected(self):
        for event_index in (0, 1):
            log = fixture()
            log["events"].append(copy.deepcopy(log["events"][event_index]))
            self.assert_rejected(log)

    def test_reused_source_for_different_host_rejected(self):
        log = fixture()
        second = copy.deepcopy(log["events"])
        second[0]["params"]["host"] = "wrong.controls.test"
        log["events"].extend(second)
        self.assert_rejected(log)

    def test_offline_timeout_unknown_error_and_success_rejected(self):
        for error in (-106, -7, -803, -999, 0, "-105", None):
            with self.subTest(error=error):
                log = fixture()
                log["events"][1]["params"]["net_error"] = error
                self.assert_rejected(log)

    def test_error_on_source_or_begin_does_not_count(self):
        log = fixture()
        log["events"][1]["params"].clear()
        log["events"][1]["source"]["net_error"] = -105
        log["events"][0]["params"]["net_error"] = -105
        self.assert_rejected(log)

    def test_unknown_or_changed_constants_fail_closed(self):
        for section, name, value in (("netError", "ERR_NAME_NOT_RESOLVED", -999),
                                     ("netError", "ERR_INTERNET_DISCONNECTED", -999),
                                     ("logEventTypes", "HOST_RESOLVER_MANAGER_REQUEST", 78)):
            log = fixture()
            log["constants"][section][name] = value
            self.assert_rejected(log)
        log = fixture()
        log["constants"]["netError"].pop("ERR_NAME_NOT_RESOLVED")
        self.assert_rejected(log)

    def test_ambiguous_error_mapping_rejected(self):
        log = fixture()
        log["constants"]["netError"]["ERR_DNS_SERVER_FAILED"] = -105
        self.assert_rejected(log)

    def test_malformed_events_do_not_raise_or_pass(self):
        for events in (None, {}, [None], [{"type": 77, "source": None}],
                       [{"type": 77, "phase": 1, "source": {"id": "2", "type": 30}}]):
            log = fixture()
            log["events"] = events
            self.assert_rejected(log)
        for params in (None, [], "invalid"):
            log = fixture()
            log["events"][0]["params"] = params
            self.assert_rejected(log)

    def test_unrelated_error_cannot_override_successful_exact_lookup(self):
        log = fixture()
        log["events"][1]["params"]["net_error"] = 0
        unrelated = copy.deepcopy(fixture()["events"])
        for item in unrelated:
            item["source"]["id"] = 99
        unrelated[0]["params"]["host"] = "wrong.controls.test"
        log["events"].extend(unrelated)
        self.assert_rejected(log)

    def test_two_exact_host_sources_with_success_and_failure_are_ambiguous(self):
        log = fixture()
        second = copy.deepcopy(log["events"])
        for item in second:
            item["source"]["id"] = 99
        second[1]["params"]["net_error"] = 0
        log["events"].extend(second)
        self.assert_rejected(log)

    def test_categorical_page_error_drops_message(self):
        self.assertEqual(WORKER.categorical_page_error("Page.goto: net::ERR_INTERNET_DISCONNECTED at http://secret/"),
                         "net::ERR_INTERNET_DISCONNECTED")
        self.assertIsNone(WORKER.categorical_page_error("Timeout 15000ms exceeded"))
        self.assertIsNone(WORKER.categorical_page_error(None))


if __name__ == "__main__":
    unittest.main()
