"""Strict Chromium DNS failure evidence for owned controls only."""
import re
from urllib.parse import urlsplit


def categorical_page_error(value):
    """Keep a native category without persisting an exception message."""
    match = re.search(r"\bnet::ERR_[A-Z_]+\b", value) if isinstance(value, str) else None
    return match.group(0) if match else None


def correlated_netlog_dns_failure(log, hostname):
    """Require one exact non-speculative resolver request and its native END.

    This is owned-control evidence, never a substitute for a deployment gate.
    Chromium can wrap the actual resolver error in a page-level offline error
    when a namespace has only loopback. A timeout or offline error is not proof.
    """
    from study.deployment_checks import dns_failure_code
    result = {"ok": False, "method": "exact_host_correlated_native_netlog_resolver_error",
              "dns_error_codes": [], "matches": [], "constants_verified": False}
    if not isinstance(log, dict) or not isinstance(hostname, str) or not hostname:
        return result
    constants = log.get("constants", {})
    if not isinstance(constants, dict):
        return result
    kinds, errors = constants.get("logEventTypes", {}), constants.get("netError", {})
    if not isinstance(kinds, dict) or not isinstance(errors, dict):
        return result
    kind = kinds.get("HOST_RESOLVER_MANAGER_REQUEST")
    if (type(kind) is not int or errors.get("ERR_NAME_NOT_RESOLVED") != -105
            or errors.get("ERR_INTERNET_DISCONNECTED") != -106):
        return result
    result["constants_verified"] = True
    native_dns_codes = {}
    for name, value in errors.items():
        if (isinstance(name, str) and type(value) is int and value < 0
                and "TIMED_OUT" not in name and "TIMEOUT" not in name):
            code = dns_failure_code("net::" + name)
            if code == "net::" + name:
                native_dns_codes.setdefault(value, []).append(code)

    def exact_host(value):
        if not isinstance(value, str):
            return False
        try:
            parsed = urlsplit(value if "://" in value else "//" + value)
            parsed.port  # Reject malformed authority forms.
            return (parsed.hostname is not None and not parsed.username and not parsed.password
                    and parsed.scheme in {"", "http", "https"} and parsed.path in {"", "/"}
                    and not parsed.query and not parsed.fragment
                    and parsed.hostname.rstrip(".").lower() == hostname.rstrip(".").lower())
        except ValueError:
            return False

    events = log.get("events", [])
    if not isinstance(events, list):
        return result
    groups = {}
    for index, item in enumerate(events):
        if not isinstance(item, dict) or item.get("type") != kind:
            continue
        source = item.get("source", {})
        if (not isinstance(source, dict) or type(source.get("id")) is not int
                or source["id"] <= 0 or type(source.get("type")) is not int):
            continue
        key = source["id"], source["type"]
        if type(item.get("phase")) is int and item["phase"] in {1, 2}:
            groups.setdefault(key, {1: [], 2: []})[item["phase"]].append((index, item))
    candidate_begins = [item for phases in groups.values() for _, item in phases[1]
                        if isinstance(item.get("params"), dict)
                        and item["params"].get("is_speculative") is False
                        and exact_host(item["params"].get("host"))]
    if len(candidate_begins) != 1:
        return result
    for (source_id, source_type), phases in groups.items():
        if len(phases[1]) != 1 or len(phases[2]) != 1:
            continue
        (begin_index, begin), (end_index, end) = phases[1][0], phases[2][0]
        before, after = begin.get("params", {}), end.get("params", {})
        if (not isinstance(before, dict) or not isinstance(after, dict)
                or begin_index >= end_index or before.get("is_speculative") is not False
                or not exact_host(before.get("host"))):
            continue
        error = after.get("net_error")
        if type(error) is not int or len(native_dns_codes.get(error, [])) != 1:
            continue
        code = native_dns_codes[error][0]
        result["matches"].append({"source_id": source_id, "source_type": source_type,
                                  "begin_index": begin_index, "end_index": end_index,
                                  "net_error": error, "dns_error_code": code})
    result["dns_error_codes"] = sorted({item["dns_error_code"] for item in result["matches"]})
    result["ok"] = bool(result["matches"])
    return result


def native_dns_evidence(log, hostname):
    """Return exact-host, non-speculative native resolver failure evidence."""
    return correlated_netlog_dns_failure(log, hostname)
