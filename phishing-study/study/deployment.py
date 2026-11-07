"""Generate a dedicated Linux deployment; preparation never applies host settings."""
from dataclasses import asdict
from datetime import datetime, timezone
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlsplit

from .config import Config, load

ROOT = Path(__file__).resolve().parents[1]
ETC = "/etc/phishing-study"
APP = "/opt/phishing-study/app"
DATA = "/var/lib/phishing-study"
NFT_TABLE = "study_egress"
NSSWITCH = "passwd: files\ngroup: files\nshadow: files\ngshadow: files\nhosts: files dns\nnetworks: files\nprotocols: files\nservices: files\nethers: files\nrpc: files\n"
# Conservative special-purpose IPv4 exclusions; additional VM addresses/gateways
# are collected at installation and rejected before resolver/web allowances.
DENIED_IPV4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)
CONTROL_KEYS = ("http_url", "https_url", "dns_template", "redirect_url")
DENY_KEYS = ("owned_ipv4", "owned_ipv6", "owned_port", "owned_public_ipv4")


def digest_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def manifest_hash(manifest):
    return digest_json({k: v for k, v in manifest.items() if k not in {"generated_at", "configuration_hash"}})


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_files(root):
    root = Path(root)
    patterns = ("pyproject.toml", "study/*.py", "scripts/*.py", "scripts/*.sh",
                "scripts/*.ps1", "deployment/linux/*", "tests/*.py")
    return sorted({p for pattern in patterns for p in root.glob(pattern) if p.is_file()})


def source_hash(root):
    root = Path(root)
    return digest_json({p.relative_to(root).as_posix(): file_hash(p) for p in source_files(root)})


def parse_network_snapshot(addresses, routes):
    """Normalize actual iproute2 JSON; absent or malformed evidence fails closed."""
    if not isinstance(addresses, list) or not addresses or not isinstance(routes, list):
        raise ValueError("VM interface and route snapshots must be JSON arrays")
    local, gateways = set(), set()

    def ipv4(value):
        if not isinstance(value, str):
            raise ValueError("VM IPv4 snapshot address must be a string")
        return str(ipaddress.IPv4Address(value))

    for interface in addresses:
        if not isinstance(interface, dict) or not isinstance(interface.get("addr_info"), list):
            raise ValueError("VM interface snapshot is missing address information")
        for address in interface["addr_info"]:
            if not isinstance(address, dict) or address.get("family") not in ("inet", "inet6"):
                raise ValueError("VM interface snapshot has invalid address information")
            if address["family"] == "inet":
                local.add(ipv4(address.get("local")))
            else:
                if not isinstance(address.get("local"), str):
                    raise ValueError("VM IPv6 snapshot address must be a string")
                ipaddress.IPv6Address(address["local"])
    if not local:
        raise ValueError("VM interface snapshot must contain an IPv4 address")
    for route in routes:
        if not isinstance(route, dict) or not isinstance(route.get("dst"), str) or not route["dst"]:
            raise ValueError("VM route snapshot has an invalid route")
        if route["dst"] != "default":
            ipaddress.IPv4Network(route["dst"], strict=False)
        if "gateway" in route:
            gateways.add(ipv4(route["gateway"]))
        if "nexthops" in route:
            if not isinstance(route["nexthops"], list) or not route["nexthops"]:
                raise ValueError("VM route snapshot has invalid next hops")
            for hop in route["nexthops"]:
                if not isinstance(hop, dict) or not hop or ("gateway" not in hop and not isinstance(hop.get("dev"), str)):
                    raise ValueError("VM route snapshot has an invalid next hop")
                if "gateway" in hop:
                    gateways.add(ipv4(hop["gateway"]))
                if "via" in hop:
                    raise ValueError("VM route snapshot uses an unsupported gateway family")
        if "via" in route or "nhid" in route:
            # An IPv4 route through another address family needs an explicit
            # deployment policy; silently omitting that gateway is unsafe.
            raise ValueError("VM route snapshot uses an unsupported gateway family")
    return {"local_ipv4": sorted(local), "gateways_ipv4": sorted(gateways)}


def network_snapshot():
    """Read current interfaces/routes without modifying the host or sending probes."""
    try:
        addresses = json.loads(subprocess.check_output(["ip", "-j", "address", "show"], text=True, timeout=5))
        routes = json.loads(subprocess.check_output(["ip", "-j", "route", "show"], text=True, timeout=5))
        return parse_network_snapshot(addresses, routes)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise ValueError("Current VM interface/route snapshots are unavailable") from exc


def check_network_snapshot(manifest):
    """Reject stale topology before verification, activation and service startup."""
    current = network_snapshot()
    expected = {key: manifest.get(key) for key in ("local_ipv4", "gateways_ipv4")}
    if current != expected:
        raise ValueError("VM interfaces/gateways changed; regenerate policy and reverify")
    return current


def firewall_state_hash(ruleset):
    """nft handles/counters are runtime identities, not policy differences."""
    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in {"handle", "packets", "bytes", "metainfo"}}
        if isinstance(value, list):
            return [clean(v) for v in value if not (isinstance(v, dict) and "metainfo" in v)]
        return value
    return digest_json(clean(ruleset))


def public_ipv4(value):
    if not isinstance(value, str):
        return False
    try:
        address = ipaddress.ip_address(value)
        return address.version == 4 and address.is_global and not any(address in ipaddress.ip_network(n) for n in DENIED_IPV4)
    except (TypeError, ValueError):
        return False


def allowed_egress(address, protocol, port, resolver, local_ipv4=(), gateways_ipv4=(), dns_blocked=False):
    """Pure specification mirrored by generated nftables rules, for unit checks."""
    if not public_ipv4(address) or address in {*local_ipv4, *gateways_ipv4}:
        return False
    return (protocol == "tcp" and port in {80, 443}) or (
        not dns_blocked and address == resolver and protocol in {"tcp", "udp"} and port == 53)


def render_firewall(uid, resolver, local_ipv4=(), gateways_ipv4=()):
    if not isinstance(uid, int) or uid <= 0 or not public_ipv4(resolver):
        raise ValueError("non-root collector UID and approved public IPv4 resolver required")
    extras = sorted({str(ipaddress.IPv4Address(v)) for v in (*local_ipv4, *gateways_ipv4)})
    if resolver in extras:
        raise ValueError("resolver cannot be a VM address or gateway")
    blocked = ", ".join([*DENIED_IPV4, *extras])
    return f"""# Apply only on the explicitly designated dedicated VM.
# The install script refuses an existing table; unrelated tables are preserved.
table inet {NFT_TABLE} {{
    set denied_v4 {{ type ipv4_addr; flags interval; auto-merge; elements = {{ {blocked} }}; }}
    chain dns_allow {{
        ip daddr {resolver} udp dport 53 accept
        ip daddr {resolver} tcp dport 53 accept
    }}
    chain workload {{
        meta nfproto ipv6 counter reject
        ip daddr @denied_v4 counter reject
        jump dns_allow
        meta l4proto tcp tcp dport {{ 80, 443 }} accept
        counter reject
    }}
    chain output {{
        type filter hook output priority -10; policy accept;
        meta skuid {uid} jump workload
    }}
}}
"""


def pilot_config(region):
    config = Config(max_hours=2, max_attempts=400, usable_per_class=50,
                    route_id="direct-ipv4", region=region or "unspecified")
    config.validate()
    return config


def toml_config(config):
    def encode(value):
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, str):
            return json.dumps(value)
        if isinstance(value, list):
            return json.dumps(value)
        return str(value)
    return "# Activation is gated by current, root-owned deployment evidence.\n" + "\n".join(
        f"{key} = {encode(value)}" for key, value in asdict(config).items()) + "\n"


def validate_controls(controls, expected_deny):
    if not isinstance(controls, dict) or not isinstance(expected_deny, dict):
        raise ValueError("controls and expected_deny must be JSON objects")
    missing = [f"owned_controls.{key}" for key in CONTROL_KEYS if not controls.get(key)]
    missing += [f"expected_deny.{key}" for key in DENY_KEYS if expected_deny.get(key) is None or expected_deny.get(key) == ""]
    for key in ("http_url", "https_url", "redirect_url"):
        if controls.get(key):
            if not isinstance(controls[key], str):
                raise ValueError(f"invalid {key}")
            parsed = urlsplit(controls[key])
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
                raise ValueError(f"invalid {key}")
            if key == "http_url" and parsed.scheme != "http" or key == "https_url" and parsed.scheme != "https":
                raise ValueError(f"invalid {key} scheme")
    if controls.get("dns_template"):
        template = controls["dns_template"]
        if not isinstance(template, str) or not re.fullmatch(r"\{nonce\}\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", template) or template.endswith((".local", ".internal", ".localhost")):
            raise ValueError("dns_template must begin {nonce}. and identify an owned public DNS zone")
    for key, version in (("owned_ipv4", 4), ("owned_ipv6", 6), ("owned_public_ipv4", 4)):
        if expected_deny.get(key):
            address = ipaddress.ip_address(expected_deny[key])
            if address.version != version:
                raise ValueError(f"invalid {key}")
            if key == "owned_public_ipv4" and not public_ipv4(str(address)):
                raise ValueError("owned_public_ipv4 must be public")
            if key == "owned_ipv4" and address.is_global:
                raise ValueError("owned_ipv4 must identify an owned non-public receiver")
    if expected_deny.get("owned_port") is not None:
        port = expected_deny["owned_port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or port in {53, 80, 443}:
            raise ValueError("owned_port must be a non-web, non-DNS port")
    return missing


def prepare(output, region=None, resolver=None, uid=None, controls=None, local_ipv4=(), gateways_ipv4=(), root=ROOT,
            verification_profile="external-controls-v1", owned_https_url=None, resolver_uid=None,
            intake_manifest_hash=None, upstream_config_hash=None):
    if verification_profile == "local-public-web-v1":
        from .public_web import OWNED_URL, prepare_public_web
        if resolver is not None:
            raise ValueError("public-web uses its fixed logged local resolver; omit --resolver")
        if owned_https_url not in (None, OWNED_URL):
            raise ValueError("public-web verification uses the configured owned Vercel control")
        return prepare_public_web(output, region, uid, resolver_uid, root, local_ipv4, gateways_ipv4,
                                  intake_manifest_hash, upstream_config_hash)
    if intake_manifest_hash is not None or upstream_config_hash is not None:
        raise ValueError("public-web evidence options require the public-web profile")
    if verification_profile == "local-logged-preview-v1":
        from .local_preview import prepare_preview
        if resolver is not None:
            raise ValueError("preview uses its fixed local resolver; omit --resolver")
        if owned_https_url is None and isinstance(controls, dict):
            owned_https_url = controls.get("owned_controls", {}).get("https_url")
        return prepare_preview(output, region, uid, resolver_uid, owned_https_url, root, local_ipv4, gateways_ipv4)
    if verification_profile != "external-controls-v1":
        raise ValueError("unknown verification profile")
    if owned_https_url is not None or resolver_uid is not None:
        raise ValueError("preview-only options require the preview verification profile")
    output = Path(output)
    if output.exists():
        raise ValueError("use a fresh output directory; existing evidence must be preserved")
    controls_document = controls or {}
    if not isinstance(controls_document, dict) or not isinstance(controls_document.get("owned_controls", {}), dict) or not isinstance(controls_document.get("expected_deny", {}), dict):
        raise ValueError("controls document must contain JSON objects")
    owned = dict(controls_document.get("owned_controls", {}))
    denied = dict(controls_document.get("expected_deny", {}))
    owned.setdefault("receiver_receipt_path", f"{ETC}/receiver-receipt.json")
    owned.setdefault("runtime_snapshot_path", f"{ETC}/runtime-{{phase}}.json")
    if owned["receiver_receipt_path"] != f"{ETC}/receiver-receipt.json" or owned["runtime_snapshot_path"] != f"{ETC}/runtime-{{phase}}.json":
        raise ValueError("deployment evidence paths are fixed protected paths")
    missing = validate_controls(owned, denied)
    if resolver and denied.get("owned_public_ipv4") == resolver:
        raise ValueError("owned alternate-DNS receiver must differ from the approved resolver")
    if not region or region.strip().lower() in {"unspecified", "unknown", "todo"}:
        missing.append("region")
    if resolver is None:
        missing.append("approved_resolver")
    elif not public_ipv4(resolver):
        raise ValueError("approved_resolver must be a public IPv4 address")
    if uid is None:
        missing.append("study_uid")
    elif not isinstance(uid, int) or uid < 100:
        raise ValueError("study_uid must identify a dedicated non-root account")
    config = pilot_config(region)
    manifest = {"schema_version": 1, "dedicated_vm": True, "route_id": "direct-ipv4",
                "region": config.region, "approved_resolver": resolver, "study_uid": uid,
                "nft_table": NFT_TABLE, "config_path": f"{ETC}/pilot.template.toml",
                "source_root": APP, "dataset_path": DATA, "owned_controls": owned,
                "expected_deny": denied, "local_ipv4": sorted(local_ipv4),
                "gateways_ipv4": sorted(gateways_ipv4), "required_inputs": sorted(missing),
                "status": "incomplete" if missing else "configured",
                "network_isolation_verified": False, "pilot_config_hash": config.fingerprint,
                "nsswitch_hash": hashlib.sha256(NSSWITCH.encode()).hexdigest(),
                "source_hash": source_hash(root), "resources": {"cpu_quota_percent": 200,
                "memory_max_bytes": 4294967296, "tasks_max": 512, "workers": 2,
                "initial_free_disk_bytes": 15000000000},
                "generated_at": datetime.now(timezone.utc).isoformat()}
    manifest["configuration_hash"] = manifest_hash(manifest)
    output.mkdir(parents=True)
    (output / "deployment.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (output / "pilot.template.toml").write_text(toml_config(config), encoding="utf-8")
    (output / "resolver").mkdir()
    (output / "resolver" / "resolv.conf").write_text(
        f"nameserver {resolver}\noptions timeout:2 attempts:1\n" if resolver else "# INCOMPLETE: approved public IPv4 resolver required\n", encoding="utf-8")
    (output / "resolver" / "nsswitch.conf").write_text(NSSWITCH, encoding="utf-8")
    if uid and resolver:
        (output / "collector.nft").write_text(render_firewall(uid, resolver, local_ipv4, gateways_ipv4), encoding="utf-8")
    else:
        (output / "collector.nft.incomplete").write_text("# No executable policy emitted until dedicated UID and resolver are known.\n", encoding="utf-8")
    (output / "source-hashes.json").write_text(json.dumps({p.relative_to(root).as_posix(): file_hash(p) for p in source_files(root)}, indent=2) + "\n", encoding="utf-8")
    shutil.copytree(Path(root) / "deployment" / "linux", output / "linux")
    return manifest


def check_evidence(manifest, evidence, current_source_hash, current_firewall_hash, current_state_hash, current_resolver_hash, config,
                   current_upstream_hash=None, current_intake_hash=None):
    if manifest.get('verification_profile') == 'local-public-web-v1':
        from .public_web import check_public_activation
        return check_public_activation(manifest, evidence, current_source_hash, current_firewall_hash,
            current_state_hash, current_resolver_hash, config, current_upstream_hash, current_intake_hash)
    if (manifest.get("schema_version") != 1 or evidence.get("schema_version", 1) != 1
            or manifest.get("verification_profile", "external-controls-v1") != "external-controls-v1"
            or evidence.get("verification_profile", "external-controls-v1") != "external-controls-v1"):
        raise ValueError("preview or unknown verification profile cannot authorize research collection")
    if manifest.get("configuration_hash") != manifest_hash(manifest):
        raise ValueError("deployment manifest changed since preparation")
    if manifest.get("status") != "configured" or manifest.get("required_inputs") or manifest.get("network_isolation_verified") is not False:
        raise ValueError("deployment template is incomplete or was manually activated")
    if evidence.get("status") != "passed" or evidence.get("network_isolation_verified") is not True:
        raise ValueError("successful deployment evidence is required")
    expected = {"configuration_hash": manifest["configuration_hash"], "pilot_config_hash": config.fingerprint,
                "source_hash": current_source_hash, "firewall_hash": current_firewall_hash,
                "normal_firewall_state_hash": current_state_hash, "resolver_hash": current_resolver_hash}
    for key, value in expected.items():
        if evidence.get(key) != value:
            raise ValueError(f"deployment evidence no longer matches {key}")
    if current_source_hash != manifest["source_hash"] or config.fingerprint != manifest["pilot_config_hash"]:
        raise ValueError("source or pilot configuration changed since preparation")
    if config.network_isolation_verified or config.region != manifest["region"] or config.route_id != "direct-ipv4" or config.proxy_required or config.interaction != "none":
        raise ValueError("template does not preserve the verified passive direct route")
    if (config.workers, config.max_attempts, config.max_hours, config.usable_per_class) != (2, 400, 2, 50):
        raise ValueError("finite pilot limits changed")
    return True


def secure_root_file(path):
    path = Path(path)
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("deployment input must be a root-owned regular file without group/world write")
    for parent in path.parents:
        info = parent.lstat()
        if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("deployment parent directory is not root-owned and protected")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--region")
    parser.add_argument("--resolver")
    parser.add_argument("--verification-profile", choices=("external-controls-v1", "local-logged-preview-v1", "local-public-web-v1"), default="external-controls-v1")
    parser.add_argument("--owned-https-url", help="owned homepage for the non-activating local preview")
    parser.add_argument("--resolver-uid", type=int, help="separate non-root preview resolver account")
    parser.add_argument('--intake-manifest-hash', help='SHA-256 of the frozen PhiUSIIL intake manifest')
    parser.add_argument('--upstream-config-hash', help='SHA-256 of the actual existing system resolver upstream snapshot')
    parser.add_argument("--uid", type=int)
    parser.add_argument("--controls", help="JSON with owned_controls and expected_deny")
    parser.add_argument("--local-ipv4", action="append", default=[])
    parser.add_argument("--gateway-ipv4", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        controls = json.loads(Path(args.controls).read_text()) if args.controls else None
        result = prepare(args.output, args.region, args.resolver, args.uid, controls, args.local_ipv4, args.gateway_ipv4,
                         verification_profile=args.verification_profile, owned_https_url=args.owned_https_url,
                         resolver_uid=args.resolver_uid, intake_manifest_hash=args.intake_manifest_hash,
                         upstream_config_hash=args.upstream_config_hash)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
