"""Stable identity keeps path/query semantics; exports contain no raw URL secrets."""
import hashlib
import ipaddress
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit


def canonical_url(value):
    p = urlsplit(value.strip())
    if p.scheme.lower() not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise ValueError("only HTTP(S) URLs without userinfo are accepted")
    if any(ord(c) < 32 for c in value) or len(value) > 8192:
        raise ValueError("invalid URL length or control characters")
    host = p.hostname.encode("idna").decode().lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    port = p.port
    scheme = p.scheme.lower()
    authority = host + (f":{port}" if port and (scheme, port) not in {("http", 80), ("https", 443)} else "")
    return urlunsplit((scheme, authority, p.path or "/", p.query, ""))


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


@lru_cache(maxsize=1)
def _extractor():
    import tldextract
    return tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def domain_group(url):
    host = urlsplit(url).hostname
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    # Use bundled PSL; no hidden network fetch. Private suffixes group tenants separately.
    ext = _extractor()(host)
    return ext.top_domain_under_public_suffix or host


def safe_url(value):
    """Retain origin + path fingerprint only. Query/fragment/path contents never exported."""
    try:
        p = urlsplit(value)
        if p.scheme not in {"http", "https"}:
            return {"scheme": p.scheme, "url_hash": digest(value)}
        host = p.hostname or ""
        origin = f"{p.scheme}://{host}" + (f":{p.port}" if p.port else "")
        return {"origin": origin, "url_hash": digest(value), "path_hash": digest(p.path or "/"),
                "path_length": len(p.path), "query_present": bool(p.query)}
    except ValueError:
        return {"url_hash": digest(value), "invalid": True}


def origin(value):
    p = urlsplit(value)
    default = 443 if p.scheme == "https" else 80
    return (p.scheme, p.hostname, p.port or default)
