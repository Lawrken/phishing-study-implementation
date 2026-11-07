"""Frozen numeric features. Labels/provenance never enter the feature matrix."""
FEATURES = {
    "http_status": ("http.status", "HTTP headers", "status code"),
    "header_count": ("http.header_count", "HTTP headers", "count"),
    "security_header_count": ("http.security_header_count", "HTTP headers", "count"),
    "set_cookie_present": ("http.set_cookie_present", "HTTP headers", "boolean"),
    "http_redirect_count": ("redirects.http_redirect_count", "Redirect behavior", "count"),
    "main_document_count": ("redirects.main_document_count", "Redirect behavior", "count"),
    "cross_origin_hop_count": ("redirects.cross_origin_hop_count", "Redirect behavior", "count"),
    "tls_days_to_expiry": ("tls.days_to_expiry", "TLS certificates", "days"),
    "tls_san_count": ("tls.san_count", "TLS certificates", "count"),
    "dns_a_count": ("dns.records.A.count", "DNS/domain metadata", "count"),
    "dns_a_ttl": ("dns.records.A.ttl", "DNS/domain metadata", "seconds"),
    "dns_aaaa_count": ("dns.records.AAAA.count", "DNS/domain metadata", "count"),
    "dns_cname_count": ("dns.records.CNAME.count", "DNS/domain metadata", "count"),
    "dom_node_count": ("dom.node_count", "DOM/forms", "count"),
    "form_count": ("dom.form_count", "DOM/forms", "count"),
    "password_input_count": ("dom.password_input_count", "DOM/forms", "count"),
    "input_count": ("dom.input_count", "DOM/forms", "count"),
    "iframe_count": ("dom.iframe_count", "DOM/forms", "count"),
    "cross_origin_form_count": ("dom.cross_origin_form_count", "DOM/forms", "count"),
    "post_form_count": ("dom.post_form_count", "DOM/forms", "count"),
    "request_count": ("network.request_count", "Network requests", "count"),
    "response_count": ("network.response_count", "Network requests", "count"),
    "failed_request_count": ("network.failed_request_count", "Network requests", "count"),
    "destination_origin_count": ("network.destination_origin_count", "Network requests", "count"),
    "third_party_request_count": ("network.third_party_request_count", "Network requests", "count"),
    "response_transfer_bytes": ("network.response_transfer_bytes", "Network requests", "bytes; completed requests only"),
    "script_count": ("javascript.script_count", "JavaScript/client resources", "count"),
    "inline_script_count": ("javascript.inline_script_count", "JavaScript/client resources", "count"),
    "external_script_count": ("javascript.external_script_count", "JavaScript/client resources", "count"),
    "cross_origin_script_count": ("javascript.cross_origin_script_count", "JavaScript/client resources", "count"),
    "javascript_error_count": ("javascript.page_error_count", "JavaScript/client resources", "count"),
    "interaction_new_requests": ("interaction.new_request_count", "Controlled interaction", "count"),
    "interaction_node_delta": ("interaction.node_count_delta", "Controlled interaction", "count"),
    "interaction_storage_delta": ("interaction.storage_key_count_delta", "Controlled interaction", "count"),
}


def extract(record):
    result = {}
    for name, (path, _, _) in FEATURES.items():
        parts = path.split(".")
        value = record["groups"].get(parts[0], {})
        measured = value.get("measured", False)
        reason = value.get("missing_reason", "field_unavailable")
        for part in parts[1:]:
            value = value.get(part) if isinstance(value, dict) else None
        result[name] = value if measured and isinstance(value, (int, float, bool)) else None
        result[name + "__missing_reason"] = None if result[name] is not None else reason
    return result
