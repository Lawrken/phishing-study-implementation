"""Prepare and identify an owned-control preview that cannot authorize collection."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from .config import Config, load

PROFILE = "local-logged-preview-v1"
EXTERNAL_PROFILE = "external-controls-v1"
SCHEMA_VERSION = 2
LISTEN = "127.0.0.153"
UPSTREAM = "127.0.0.53"
RESOURCES = {"memory_max_bytes": 2147483648, "cpu_quota_percent": 200,
             "tasks_max": 512, "workers": 1}
ARTIFACTS = frozenset(("preview.template.toml", "resolver/resolv.conf",
                       "resolver/nsswitch.conf", "resolver/config.json",
                       "preview-worker.service", "preview-resolver.service", "preview.nft.in"))
IDENTITY_KEYS = ("schema_version", "verification_profile", "configuration_hash",
                 "source_hash", "pilot_config_hash", "service_hash",
                 "resolver_config_hash", "resolver_code_hash", "nsswitch_hash")
PREVIEW_PHASES = ("normal", "denied-alternate_tcp", "denied-alternate_udp", "denied-private",
                  "denied-ipv6", "blocked", "restored")
REQUIRED_CHECKS = frozenset({
    "recorded_vm_topology_matches", "non_root_logging_resolver_ready", "resolver_identity",
    "resolver_only_bind_capability", "resolver_udp_tcp_positive", "receivers_stopped",
    "resolver_stop_command", "resolver_service_exit_zero", "resolver_logged_clean_shutdown",
    "preview_accounts_idle", "outer_firewall_unchanged", "outer_dns_nss_hosts_unchanged",
    "outer_ipv4_topology_unchanged", "source_unchanged", "blackout_zero_resolver_queries",
    "dns_policy_restored", "normal_logged_owned_query", "restored_logged_owned_query",
    "denied-ipv6_os_address_family_denial",
    *(phase + suffix for phase in PREVIEW_PHASES
      for suffix in ("_worker_passed", "_zero_receiver_hits", "_resolver_healthy")),
    *("denied-" + case + "_working_receiver" for case in ("alternate_tcp", "alternate_udp", "private", "ipv6")),
    *(phase + "_kernel_reject" for phase in ("denied-alternate_tcp", "denied-alternate_udp", "denied-private", "blocked")),
})
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def owned_homepage(url):
    """Only a configured HTTPS DNS hostname's passive homepage is supported."""
    if not isinstance(url, str):
        raise ValueError("owned HTTPS homepage is required")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if (parsed.scheme != "https" or not host or parsed.port not in (None, 443)
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                or any(character.isspace() for character in url)):
            raise ValueError()
        host = host.lower()
        if (len(host) > 253 or "." not in host or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid"))
                or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in host.split("."))):
            raise ValueError()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError()
    except (TypeError, ValueError):
        raise ValueError("owned control must be an HTTPS DNS homepage without credentials, path, query or fragment") from None
    return "https://" + host + "/", host


def _uid(value, label):
    if value is not None and (type(value) is not int or not 100 <= value < 2 ** 31):
        raise ValueError(label + " must identify a dedicated non-root account")
    return value


def preview_config(region=None):
    config = Config(workers=1, max_hours=2, max_attempts=400, usable_per_class=50,
                    route_id="direct-ipv4", region=region or "unspecified")
    config.validate()
    return config


def service_templates(source_root, bundle, uid, resolver_uid):
    """Controller substitutes only marked runtime tokens and freezes that unit."""
    environment = "Environment=" + json.dumps("PYTHONPATH=" + str(source_root)) + "\n"
    common = ("Type=exec\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=true\n"
              "ProtectHome=true\nProtectSystem=strict\nRestart=no\nKillMode=control-group\n"
              "TimeoutStopSec=10\nRuntimeMaxSec=600\n" + environment)
    worker = ("# Non-activating owned-control preview; never the pilot service.\n[Service]\n"
              + common + "User=" + str(uid if uid is not None else "@@STUDY_UID@@") + "\n"
              "CPUQuota=200%\nMemoryMax=2G\nMemorySwapMax=0\nTasksMax=512\n"
              "RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\n"
              "BindReadOnlyPaths=" + str(bundle / "resolver/resolv.conf") + ":/etc/resolv.conf "
              + str(bundle / "resolver/nsswitch.conf") + ":/etc/nsswitch.conf\n"
              "ExecStart=@@PYTHON@@ -m study.preview_worker --bundle @@BUNDLE@@ --phase @@PHASE@@ --output @@OUTPUT@@\n")
    resolver = ("# Exact owned-host DNS preview only; no public listener.\n[Service]\n"
                + common + "User=" + str(resolver_uid if resolver_uid is not None else "@@RESOLVER_UID@@") + "\n"
                "CPUQuota=20%\nMemoryMax=128M\nMemorySwapMax=0\nTasksMax=32\n"
                "RestrictAddressFamilies=AF_UNIX AF_INET\n"
                "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"
                "ExecStart=@@PYTHON@@ -m study.logging_resolver --listen " + LISTEN
                + " --upstream " + UPSTREAM + " --allowed-host @@OWNED_HOST@@ --log @@DNS_LOG@@ --ready @@DNS_READY@@ --phase-file @@PHASE_FILE@@\n")
    return worker, resolver


def firewall_template(uid):
    """Inert until the root controller validates and supplies table/public IPv4s."""
    worker_uid = str(uid) if uid is not None else "@@STUDY_UID@@"
    return """# Owned-control preview only; this template is not executable policy.
# The DNS exception is deliberately before the final loopback/private denial.
table inet @@TABLE@@ {
    chain dns_allow {
        ip daddr 127.0.0.153 udp dport 53 counter accept
        ip daddr 127.0.0.153 tcp dport 53 counter accept
    }
    chain workload {
        jump dns_allow
        meta nfproto ipv6 counter reject
        ip daddr { @@SITE_IPV4@@ } tcp dport 443 counter accept
        counter reject
    }
    chain output {
        type filter hook output priority -10; policy accept;
        meta skuid """ + worker_uid + """ jump workload
    }
}
"""


def prepare_preview(output, region, uid, resolver_uid, owned_https_url, root,
                    local_ipv4=(), gateways_ipv4=()):
    from .deployment import NSSWITCH, digest_json, file_hash, manifest_hash, source_files, source_hash, toml_config
    output, root = Path(output), Path(root).resolve()
    if output.exists():
        raise ValueError("use a fresh output directory; existing evidence must be preserved")
    uid, resolver_uid = _uid(uid, "study_uid"), _uid(resolver_uid, "resolver_uid")
    if uid is not None and uid == resolver_uid:
        raise ValueError("resolver and browser must use different dedicated accounts")
    if region is not None and (not isinstance(region, str) or not region.strip()):
        raise ValueError("region must be an operator-supplied location or omitted")
    confirmed_region = bool(region and region.strip().lower() not in {"unspecified", "unknown", "todo"})
    region = region.strip() if confirmed_region else None
    url, host = owned_homepage(owned_https_url) if owned_https_url else (None, None)
    def ipv4_values(values):
        if not isinstance(values, (list, tuple)) or any(not isinstance(value, str) for value in values):
            raise ValueError("preview topology must contain literal IPv4 strings")
        return sorted({str(ipaddress.IPv4Address(value)) for value in values})
    locals_, gateways = ipv4_values(local_ipv4), ipv4_values(gateways_ipv4)
    missing = [name for name, value in (("study_uid", uid), ("resolver_uid", resolver_uid),
                                        ("owned_https_url", url)) if value is None]
    config = preview_config(region)
    resolver = {"listen": LISTEN, "upstream": UPSTREAM, "port": 53,
                "transports": ["udp", "tcp"], "allow_hosts": [host] if host else [], "uid": resolver_uid}
    worker_service, resolver_service = service_templates(root, output.resolve(), uid, resolver_uid)
    content = {"preview.template.toml": toml_config(config),
               "resolver/resolv.conf": f"nameserver {LISTEN}\noptions timeout:1 attempts:1\n",
               "resolver/nsswitch.conf": NSSWITCH,
               "resolver/config.json": json.dumps(resolver, indent=2) + "\n",
               "preview-worker.service": worker_service,
               "preview-resolver.service": resolver_service,
               "preview.nft.in": firewall_template(uid)}
    artifact_hashes = {name: hashlib.sha256(value.encode()).hexdigest() for name, value in content.items()}
    resolver_source = root / "study/logging_resolver.py"
    manifest = {"schema_version": SCHEMA_VERSION, "verification_profile": PROFILE,
                "status": "incomplete" if missing else "preview-prepared", "required_inputs": missing,
                "activation_allowed": False, "network_isolation_verified": False,
                "research_eligible": False, "research_collection_count": 0, "dedicated_vm": True,
                "route_id": config.route_id, "region": config.region, "region_confirmed": confirmed_region,
                "source_root": str(root), "study_uid": uid, "resolver": resolver,
                "owned_controls": {"https_url": url} if url else {}, "resources": dict(RESOURCES),
                "local_ipv4": locals_, "gateways_ipv4": gateways, "pilot_config_hash": config.fingerprint,
                "source_hash": source_hash(root), "artifact_hashes": artifact_hashes,
                "service_hash": digest_json({name: artifact_hashes[name] for name in ("preview-worker.service", "preview-resolver.service")}),
                "resolver_config_hash": artifact_hashes["resolver/config.json"],
                "resolver_code_hash": file_hash(resolver_source) if resolver_source.is_file() else None,
                "nsswitch_hash": artifact_hashes["resolver/nsswitch.conf"],
                "activation_blockers": ["preview_profile_cannot_authorize_collection", "full_deployment_control_coverage", "independent_labels"],
                "generated_at": datetime.now(timezone.utc).isoformat()}
    if not confirmed_region:
        manifest["activation_blockers"].append("accurate_region")
    manifest["configuration_hash"] = manifest_hash(manifest)
    output.mkdir(parents=True)
    (output / "resolver").mkdir()
    for name, value in content.items():
        (output / name).write_text(value, encoding="utf-8", newline="\n")
    (output / "deployment.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    (output / "source-hashes.json").write_text(json.dumps({p.relative_to(root).as_posix(): file_hash(p) for p in source_files(root)}, indent=2) + "\n", encoding="utf-8", newline="\n")
    return manifest


def validate_preview_manifest(manifest, require_ready=True):
    from .deployment import digest_json, manifest_hash
    if not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int or manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("verification_profile") != PROFILE:
        raise ValueError("preview schema and verification profile required")
    if manifest.get("configuration_hash") != manifest_hash(manifest):
        raise ValueError("preview manifest identity changed")
    if (any(manifest.get(key) is not False for key in ("activation_allowed", "network_isolation_verified", "research_eligible"))
            or type(manifest.get("research_collection_count")) is not int or manifest["research_collection_count"] != 0):
        raise ValueError("preview cannot authorize or contain research collection")
    resources = manifest.get("resources")
    if (not isinstance(resources, dict) or resources != RESOURCES or any(type(value) is not int for value in resources.values())
            or manifest.get("route_id") != "direct-ipv4" or manifest.get("dedicated_vm") is not True):
        raise ValueError("preview route or resource limits changed")
    region = manifest.get("region")
    if not isinstance(region, str) or not region.strip() or region != region.strip():
        raise ValueError("preview region is invalid")
    confirmed = region.lower() not in {"unspecified", "unknown", "todo"}
    if manifest.get("region_confirmed") is not confirmed:
        raise ValueError("preview region confirmation changed")
    if manifest.get("pilot_config_hash") != preview_config(region).fingerprint:
        raise ValueError("preview finite passive configuration changed")
    resolver = manifest.get("resolver", {})
    if not isinstance(resolver, dict) or type(resolver.get("port")) is not int or any(resolver.get(k) != v for k, v in
            (("listen", LISTEN), ("upstream", UPSTREAM), ("port", 53), ("transports", ["udp", "tcp"]))):
        raise ValueError("preview resolver endpoints changed")
    for key, value in (("study_uid", manifest.get("study_uid")), ("resolver_uid", resolver.get("uid"))):
        _uid(value, key)
    if set(manifest.get("artifact_hashes", {})) != ARTIFACTS:
        raise ValueError("preview artifact inventory is incomplete")
    artifact_hashes = manifest["artifact_hashes"]
    if (manifest.get("resolver_config_hash") != artifact_hashes["resolver/config.json"]
            or manifest.get("nsswitch_hash") != artifact_hashes["resolver/nsswitch.conf"]
            or manifest.get("service_hash") != digest_json({name: artifact_hashes[name] for name in ("preview-worker.service", "preview-resolver.service")})):
        raise ValueError("preview artifact identities disagree")
    if require_ready:
        if manifest.get("status") != "preview-prepared" or manifest.get("required_inputs") != []:
            raise ValueError("preview inputs remain incomplete")
        if manifest.get("study_uid") is None or resolver.get("uid") is None or manifest["study_uid"] == resolver["uid"]:
            raise ValueError("separate non-root preview accounts required")
        url, host = owned_homepage(manifest.get("owned_controls", {}).get("https_url"))
        if manifest["owned_controls"]["https_url"] != url or resolver.get("allow_hosts") != [host]:
            raise ValueError("preview host allowlist changed")
    return True


def preview_identity(manifest):
    validate_preview_manifest(manifest)
    result = {key: manifest.get(key) for key in IDENTITY_KEYS}
    if any(value is None or value == "" for value in result.values()):
        raise ValueError("preview identity is incomplete")
    if any(not isinstance(result[key], str) or HASH_PATTERN.fullmatch(result[key]) is None
           for key in IDENTITY_KEYS if key not in {"schema_version", "verification_profile"}):
        raise ValueError("preview identity must contain actual SHA-256 digests")
    return result


def validate_preview_bundle(bundle, *, root=None):
    from .deployment import file_hash, source_hash
    bundle = Path(bundle)
    manifest_path = bundle / "deployment.json"
    if manifest_path.is_symlink():
        raise ValueError("preview manifest cannot be a symlink")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_preview_manifest(manifest)
    for name, expected in manifest["artifact_hashes"].items():
        path = bundle / name
        if path.is_symlink() or not path.is_file() or file_hash(path) != expected:
            raise ValueError("preview bundle artifact changed: " + name)
    config = load(bundle / "preview.template.toml")
    if config.fingerprint != manifest["pilot_config_hash"] or config.network_isolation_verified:
        raise ValueError("preview configuration changed")
    if json.loads((bundle / "resolver/config.json").read_text(encoding="utf-8")) != manifest["resolver"]:
        raise ValueError("preview resolver configuration changed")
    actual_root = Path(root) if root is not None else Path(manifest["source_root"])
    if source_hash(actual_root) != manifest["source_hash"]:
        raise ValueError("preview source changed")
    if file_hash(actual_root / "study/logging_resolver.py") != manifest["resolver_code_hash"]:
        raise ValueError("preview resolver code identity changed")
    preview_identity(manifest)
    return manifest


def validate_preview_evidence(manifest, evidence):
    expected = preview_identity(manifest)
    if not isinstance(evidence, dict) or evidence.get("status") != "preview-passed":
        raise ValueError("successful preview evidence required")
    if any(evidence.get(key) != value for key, value in expected.items()):
        raise ValueError("preview evidence belongs to a different source, configuration or profile")
    if any(evidence.get(key) is not False for key in ("activation_allowed", "network_isolation_verified", "research_eligible",
                                                     "public_dns_verified", "public_tls_verified", "full_production_verification")):
        raise ValueError("preview evidence cannot authorize collection")
    if type(evidence.get("research_collection_count")) is not int or evidence["research_collection_count"] != 0:
        raise ValueError("preview evidence must contain zero research captures")
    checks = evidence.get("checks")
    if (not isinstance(checks, dict) or not REQUIRED_CHECKS.issubset(checks)
            or not all(value is True or isinstance(value, dict) and value.get("ok") is True for value in checks.values())):
        raise ValueError("preview checks did not all pass")
    if not isinstance(evidence.get("nonce"), str) or re.fullmatch(r"[a-f0-9]{32}", evidence["nonce"]) is None:
        raise ValueError("preview run nonce is missing or invalid")
    for key in ("firewall_file_hash", "normal_firewall_state_hash", "resolver_runtime_service_hash"):
        value = evidence.get(key)
        if not isinstance(value, str) or HASH_PATTERN.fullmatch(value) is None:
            raise ValueError("preview runtime identity is missing or invalid: " + key)
    if evidence.get("cleanup_errors") != [] or type(evidence.get("resolver_service_exit")) is not int or evidence["resolver_service_exit"] != 0:
        raise ValueError("preview cleanup did not complete successfully")
    try:
        started = datetime.fromisoformat(evidence["started_at"])
        finished = datetime.fromisoformat(evidence["finished_at"])
        if started.tzinfo is None or finished.tzinfo is None or finished < started:
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ValueError("preview measurement window is missing or invalid") from None
    phases = evidence.get("phases")
    if (not isinstance(phases, list) or len(phases) != len(PREVIEW_PHASES)
            or not all(isinstance(phase, dict) for phase in phases)
            or tuple(phase.get("phase") for phase in phases) != PREVIEW_PHASES):
        raise ValueError("preview phase sequence is missing or incomplete")
    receipts = evidence.get("phase_receipt_hashes")
    if (not isinstance(receipts, dict) or set(receipts) != set(PREVIEW_PHASES)
            or any(not isinstance(value, str) or HASH_PATTERN.fullmatch(value) is None for value in receipts.values())):
        raise ValueError("preview phase receipt identities are missing or invalid")
    previous_finished = started
    for phase in phases:
        if type(phase.get("worker_exit")) is not int or phase["worker_exit"] != 0:
            raise ValueError("preview worker did not exit successfully")
        delta, service_hash = phase.get("reject_counter_delta"), phase.get("service_hash")
        if type(delta) is not int or delta < 0 or not isinstance(service_hash, str) or HASH_PATTERN.fullmatch(service_hash) is None:
            raise ValueError("preview phase counters or service identity are invalid")
        if phase["phase"] in {"denied-alternate_tcp", "denied-alternate_udp", "denied-private", "blocked"} and delta <= 0:
            raise ValueError("preview phase is missing its measured kernel rejection")
        try:
            phase_started = datetime.fromisoformat(phase["started_at"])
            phase_finished = datetime.fromisoformat(phase["finished_at"])
            if (phase_started.tzinfo is None or phase_finished.tzinfo is None
                    or not previous_finished <= phase_started <= phase_finished <= finished):
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise ValueError("preview phase measurement window is missing or invalid") from None
        previous_finished = phase_finished
    return True
