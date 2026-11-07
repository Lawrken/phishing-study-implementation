import asyncio
from datetime import datetime, timezone
import socket
import ssl
from urllib.parse import urlsplit


def missing(reason):
    return {"measured": False, "missing_reason": reason}


async def dns_metadata(url, config):
    if config.profile == "fixture":
        return missing("fixture_not_public_dns")
    host = urlsplit(url).hostname
    try:
        import dns.asyncresolver
        resolver = dns.asyncresolver.Resolver()
        results, missing_fields = {}, {}
        for kind in ("A", "AAAA", "CNAME", "NS"):
            try:
                response = await resolver.resolve(host, kind, lifetime=2)
                results[kind] = {"count": len(response), "ttl": response.rrset.ttl}
            except Exception as exc:
                missing_fields[kind] = type(exc).__name__
        return {"measured": bool(results), "records": results, "missing_fields": missing_fields,
                "vantage": "collector_resolver", "domain_age": None, "domain_age_missing_reason": "registration_lookup_not_in_protocol"}
    except ImportError:
        return missing("dnspython_not_installed")


def _tls(url):
    p = urlsplit(url)
    context = ssl.create_default_context()
    with socket.create_connection((p.hostname, p.port or 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=p.hostname) as secured:
            cert = secured.getpeercert()
            def name(field):
                return ",".join(f"{key}={value}" for component in cert.get(field, []) for key, value in component)
            expires = ssl.cert_time_to_seconds(cert["notAfter"])
            return {"measured": True, "protocol": secured.version(), "issuer": name("issuer"),
                    "subject": name("subject"), "san_count": len(cert.get("subjectAltName", [])),
                    "valid_from": cert.get("notBefore"), "valid_to": cert.get("notAfter"),
                    "days_to_expiry": (expires - datetime.now(timezone.utc).timestamp()) / 86400,
                    "validation": "system_trust_verified", "vantage": "direct_metadata_connection"}


async def tls_metadata(url, config):
    if urlsplit(url).scheme != "https":
        return missing("not_https")
    if config.profile == "fixture":
        return missing("fixture_tls_not_configured")
    if config.proxy_required:
        return missing("full_certificate_not_collected_through_proxy_use_browser_tls")
    try:
        return await asyncio.wait_for(asyncio.to_thread(_tls, url), timeout=6)
    except Exception as exc:
        return missing(type(exc).__name__)
