"""Local preview bundles cannot impersonate production deployment evidence."""
from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from study.config import load
from study.deployment import ROOT, check_evidence, file_hash, main, manifest_hash, prepare, toml_config
from study.local_preview import (EXTERNAL_PROFILE, IDENTITY_KEYS, LISTEN, PREVIEW_PHASES, PROFILE, REQUIRED_CHECKS, RESOURCES, UPSTREAM,
                                 owned_homepage, prepare_preview, preview_identity,
                                 validate_preview_bundle, validate_preview_evidence,
                                 validate_preview_manifest)


def configured(output, **changes):
    values = {"region": None, "uid": 999, "resolver_uid": 998,
              "owned_https_url": "https://d-tx-t.vercel.app/", "root": ROOT}
    values.update(changes)
    return prepare_preview(output, **values)


def rehash(manifest):
    manifest["configuration_hash"] = manifest_hash(manifest)
    return manifest


def successful_evidence(manifest):
    report = {**preview_identity(manifest), "status": "preview-passed",
              "checks": {name: True for name in REQUIRED_CHECKS},
              "activation_allowed": False, "network_isolation_verified": False,
              "research_eligible": False, "research_collection_count": 0,
              "public_dns_verified": False, "public_tls_verified": False,
              "full_production_verification": False, "nonce": "a" * 32,
              "firewall_file_hash": "b" * 64, "normal_firewall_state_hash": "c" * 64,
              "resolver_runtime_service_hash": "d" * 64, "cleanup_errors": [],
              "resolver_service_exit": 0, "started_at": "2026-10-25T00:00:00+00:00",
              "finished_at": "2026-10-25T00:01:00+00:00",
              "phase_receipt_hashes": {phase: "e" * 64 for phase in PREVIEW_PHASES}, "phases": []}
    for index, name in enumerate(PREVIEW_PHASES):
        report["phases"].append({"phase": name, "worker_exit": 0, "service_hash": "f" * 64,
                                  "reject_counter_delta": 0 if name in {"normal", "restored", "denied-ipv6"} else 1,
                                  "started_at": f"2026-10-25T00:00:{index * 2 + 1:02}+00:00",
                                  "finished_at": f"2026-10-25T00:00:{index * 2 + 2:02}+00:00"})
    return report


class LocalPreviewTests(unittest.TestCase):
    def test_preview_bundle_has_separate_identity_limits_and_inert_services(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "bundle"
            manifest = configured(output)
            actual = validate_preview_bundle(output, root=ROOT)
            self.assertEqual(actual, manifest)
            self.assertEqual((manifest["schema_version"], manifest["verification_profile"], manifest["status"]), (2, PROFILE, "preview-prepared"))
            self.assertEqual(manifest["resources"], RESOURCES)
            self.assertEqual(manifest["resolver"], {"listen": LISTEN, "upstream": UPSTREAM,
                             "port": 53, "transports": ["udp", "tcp"], "allow_hosts": ["d-tx-t.vercel.app"], "uid": 998})
            config = load(output / "preview.template.toml")
            self.assertEqual((config.workers, config.max_attempts, config.max_hours, config.usable_per_class), (1, 400, 2, 50))
            self.assertFalse(config.network_isolation_verified)
            self.assertEqual((output / "resolver/resolv.conf").read_text().splitlines()[0], "nameserver 127.0.0.153")
            self.assertIn("@@PHASE@@", (output / "preview-worker.service").read_text())
            self.assertIn("CAP_NET_BIND_SERVICE", (output / "preview-resolver.service").read_text())
            rules = (output / "preview.nft.in").read_text()
            self.assertIn("meta skuid 999 jump workload", rules)
            self.assertIn("@@SITE_IPV4@@", rules)
            self.assertNotIn("flush ruleset", rules)
            self.assertLess(rules.index("jump dns_allow"), rules.index("meta nfproto ipv6"))
            self.assertFalse((output / "pilot.toml").exists())

    def test_unknown_region_is_explicit_and_never_inferred(self):
        for region in (None, "unspecified", "unknown", "todo"):
            with self.subTest(region=region), tempfile.TemporaryDirectory() as temp:
                manifest = configured(Path(temp) / "bundle", region=region)
                self.assertEqual(manifest["region"], "unspecified")
                self.assertIs(manifest["region_confirmed"], False)
                self.assertIn("accurate_region", manifest["activation_blockers"])
                self.assertTrue(validate_preview_manifest(manifest))
        with tempfile.TemporaryDirectory() as temp:
            manifest = configured(Path(temp) / "bundle", region="operator-confirmed country")
            self.assertTrue(manifest["region_confirmed"])
            self.assertEqual(manifest["region"], "operator-confirmed country")

    def test_missing_inputs_stay_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = prepare(Path(temp) / "bundle", verification_profile=PROFILE)
            self.assertEqual(manifest["status"], "incomplete")
            self.assertEqual(set(manifest["required_inputs"]), {"study_uid", "resolver_uid", "owned_https_url"})
            self.assertTrue(validate_preview_manifest(manifest, require_ready=False))
            with self.assertRaisesRegex(ValueError, "incomplete"):
                validate_preview_manifest(manifest)

    def test_account_identity_cannot_be_root_boolean_shared_or_out_of_range(self):
        for values in ({"uid": 0}, {"uid": True}, {"uid": "999"}, {"uid": -1},
                       {"resolver_uid": 0}, {"resolver_uid": True}, {"resolver_uid": 999}, {"resolver_uid": 2 ** 31}):
            with self.subTest(values=values), tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
                configured(Path(temp) / "bundle", **values)

    def test_owned_control_must_be_exact_passive_https_dns_homepage(self):
        for url in (None, "http://d-tx-t.vercel.app/", "https://user@d-tx-t.vercel.app/",
                    "https://d-tx-t.vercel.app:8443/", "https://d-tx-t.vercel.app/login",
                    "https://d-tx-t.vercel.app/?secret=x", "https://d-tx-t.vercel.app/#x",
                    "https://127.0.0.1/", "https://93.184.216.34/", "https://[::1]/",
                    "https://localhost/", "https://a.test/", "https://a..example/", "https://bad host.example/",
                    "https://-bad.example/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                owned_homepage(url)
        self.assertEqual(owned_homepage("https://D-TX-T.vercel.app:443"), ("https://d-tx-t.vercel.app/", "d-tx-t.vercel.app"))

    def test_changed_manifest_and_rehashed_unsafe_settings_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            original = configured(Path(temp) / "bundle")
            changed = deepcopy(original)
            changed["study_uid"] = 1002
            with self.assertRaisesRegex(ValueError, "identity changed"):
                validate_preview_manifest(changed)
            mutations = [lambda m: m.update(schema_version=1),
                         lambda m: m.update(verification_profile=EXTERNAL_PROFILE),
                         lambda m: m.update(activation_allowed=True),
                         lambda m: m.update(research_eligible=True),
                         lambda m: m.update(research_collection_count=True),
                         lambda m: m["resources"].update(workers=2),
                         lambda m: m["resolver"].update(upstream=LISTEN),
                         lambda m: m["resolver"].update(listen="0.0.0.0"),
                         lambda m: m["resolver"].update(allow_hosts=["another.example"]),
                         lambda m: m["artifact_hashes"].update({"../outside": "x"})]
            for mutate in mutations:
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    changed = deepcopy(original)
                    mutate(changed)
                    validate_preview_manifest(rehash(changed))

    def test_modified_file_and_changed_source_invalidate_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "bundle"
            configured(output)
            path = output / "resolver/resolv.conf"
            path.write_text("nameserver 8.8.8.8\n")
            with self.assertRaisesRegex(ValueError, "artifact changed"):
                validate_preview_bundle(output)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "bundle"
            configured(output)
            fake_root = Path(temp) / "changed-source"
            fake_root.mkdir()
            with self.assertRaisesRegex(ValueError, "source changed"):
                validate_preview_bundle(output, root=fake_root)

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "bundle"
            configured(output)
            before = (output / "deployment.json").read_bytes()
            with self.assertRaisesRegex(ValueError, "fresh"):
                configured(output)
            self.assertEqual((output / "deployment.json").read_bytes(), before)

    def test_topology_records_literal_ipv4_addresses_only(self):
        for changes in ({"local_ipv4": [True]}, {"gateways_ipv4": [16843009]},
                        {"local_ipv4": ["::1"]}, {"gateways_ipv4": ["invalid"]}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
                configured(Path(temp) / "bundle", **changes)
        with tempfile.TemporaryDirectory() as temp:
            manifest = configured(Path(temp) / "bundle", local_ipv4=["10.0.2.15", "127.0.0.1"], gateways_ipv4=["10.0.2.2"])
            self.assertEqual(manifest["local_ipv4"], ["10.0.2.15", "127.0.0.1"])

    def test_rehashed_configuration_cannot_raise_worker_count(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "bundle"
            manifest = configured(output)
            path = output / "preview.template.toml"
            config = load(path)
            config.workers = 2
            path.write_text(toml_config(config), encoding="utf-8", newline="\n")
            manifest["pilot_config_hash"] = config.fingerprint
            manifest["artifact_hashes"]["preview.template.toml"] = file_hash(path)
            (output / "deployment.json").write_text(json.dumps(rehash(manifest)), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "finite passive configuration"):
                validate_preview_bundle(output)

    def test_preview_evidence_requires_exact_identity_and_zero_collection(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = configured(Path(temp) / "bundle")
        evidence = successful_evidence(manifest)
        self.assertTrue(validate_preview_evidence(manifest, evidence))
        for key in IDENTITY_KEYS:
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_preview_evidence(manifest, {**evidence, key: "stale"})
        for changes in ({"status": "passed"}, {"checks": {}}, {"checks": {"failure": False}},
                        {"research_collection_count": True}, {"research_collection_count": 1},
                        {"network_isolation_verified": True}, {"research_eligible": True}, {"activation_allowed": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_preview_evidence(manifest, {**evidence, **changes})

    def test_preview_evidence_cannot_replace_or_omit_required_measured_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = configured(Path(temp) / "bundle")
        evidence = successful_evidence(manifest)
        for name in REQUIRED_CHECKS:
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, "checks"):
                changed = deepcopy(evidence)
                changed["checks"].pop(name)
                validate_preview_evidence(manifest, changed)
        with self.assertRaisesRegex(ValueError, "checks"):
            validate_preview_evidence(manifest, {**evidence, "checks": {"invented_pass": True}})

    def test_preview_evidence_requires_complete_successful_ordered_phases_and_receipts(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = configured(Path(temp) / "bundle")
        evidence = successful_evidence(manifest)
        mutations = [lambda r: r.pop("phases"), lambda r: r["phases"].pop(),
                     lambda r: r["phases"].reverse(), lambda r: r["phases"][1].update(phase="normal"),
                     lambda r: r["phases"][0].update(worker_exit=False),
                     lambda r: r["phases"][0].update(worker_exit=1),
                     lambda r: r["phases"][0].update(service_hash="invalid"),
                     lambda r: r["phases"][1].update(reject_counter_delta=0),
                     lambda r: r["phases"][0].update(reject_counter_delta=-1),
                     lambda r: r["phases"][0].update(reject_counter_delta=True),
                     lambda r: r.pop("phase_receipt_hashes"),
                     lambda r: r["phase_receipt_hashes"].pop("normal"),
                     lambda r: r["phase_receipt_hashes"].update(normal="not-a-hash")]
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                changed = deepcopy(evidence)
                mutate(changed)
                validate_preview_evidence(manifest, changed)

    def test_preview_evidence_requires_run_nonce_runtime_hashes_and_clean_shutdown(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = configured(Path(temp) / "bundle")
        evidence = successful_evidence(manifest)
        for changes in ({"nonce": None}, {"nonce": "a" * 31}, {"nonce": "G" * 32},
                        {"firewall_file_hash": "bad"}, {"normal_firewall_state_hash": "g" * 64},
                        {"resolver_runtime_service_hash": None}, {"cleanup_errors": [{"error": "timeout"}]},
                        {"resolver_service_exit": True}, {"resolver_service_exit": 1},
                        {"public_dns_verified": True}, {"public_tls_verified": True},
                        {"full_production_verification": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_preview_evidence(manifest, {**evidence, **changes})

    def test_preview_phase_windows_must_be_aware_ordered_and_inside_run(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = configured(Path(temp) / "bundle")
        evidence = successful_evidence(manifest)
        mutations = [lambda r: r.pop("started_at"), lambda r: r.update(started_at="2026-10-25T00:00:00"),
                     lambda r: r.update(finished_at="2026-10-24T00:00:00+00:00"),
                     lambda r: r["phases"][0].pop("started_at"),
                     lambda r: r["phases"][0].update(started_at="2026-10-25T00:00:01"),
                     lambda r: r["phases"][0].update(finished_at="2026-10-25T00:01:01+00:00"),
                     lambda r: r["phases"][1].update(started_at="2026-10-25T00:00:01+00:00")]
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaisesRegex(ValueError, "window"):
                changed = deepcopy(evidence)
                mutate(changed)
                validate_preview_evidence(manifest, changed)

    def test_preview_cannot_authorize_collection_even_with_forged_success(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "bundle"
            manifest = configured(output)
            config = load(output / "preview.template.toml")
        forged = {**preview_identity(manifest), "status": "passed", "network_isolation_verified": True}
        with self.assertRaisesRegex(ValueError, "cannot authorize"):
            check_evidence(manifest, forged, manifest["source_hash"], "firewall", "state", "resolver", config)
        external = {"schema_version": 1, "verification_profile": EXTERNAL_PROFILE}
        with self.assertRaisesRegex(ValueError, "cannot authorize"):
            check_evidence(external, forged, "source", "firewall", "state", "resolver", config)

    def test_activation_script_rejects_preview_before_reading_other_files_or_writing(self):
        spec = importlib.util.spec_from_file_location("preview_gate_test", ROOT / "deployment/linux/gate.py")
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        with (patch.object(gate, "read", return_value={"schema_version": 2, "verification_profile": PROFILE}) as read,
             patch.object(gate, "load") as load_config,
             patch.object(Path, "write_text") as write,
             patch("sys.argv", ["gate.py", "--activate"])):
            with self.assertRaisesRegex(ValueError, "cannot activate"):
                gate.main()
        read.assert_called_once()
        load_config.assert_not_called()
        write.assert_not_called()

    def test_cli_dispatch_requires_explicit_preview_and_external_default_stays_legacy(self):
        with tempfile.TemporaryDirectory() as temp, redirect_stdout(io.StringIO()):
            output = Path(temp) / "bundle"
            result = main(["--output", str(output), "--verification-profile", PROFILE,
                           "--uid", "999", "--resolver-uid", "998", "--owned-https-url", "https://d-tx-t.vercel.app/"])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads((output / "deployment.json").read_text())["verification_profile"], PROFILE)
        with tempfile.TemporaryDirectory() as temp:
            manifest = prepare(Path(temp) / "external")
            self.assertEqual(manifest["schema_version"], 1)
            self.assertNotIn("verification_profile", manifest)
            self.assertEqual(manifest["resources"]["workers"], 2)
        for options in ({"verification_profile": "unknown"}, {"owned_https_url": "https://d-tx-t.vercel.app/"},
                        {"verification_profile": PROFILE, "resolver": "1.1.1.1"}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
                prepare(Path(temp) / "bundle", **options)
