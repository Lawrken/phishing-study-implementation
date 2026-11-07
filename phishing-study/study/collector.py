"""Bounded Chromium visit. No credentials, form bodies, or page text are persisted."""
import asyncio
from collections import Counter
from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import platform
import time
from urllib.parse import urlsplit
from . import PROTOCOL_VERSION, __version__
from .metadata import dns_metadata, tls_metadata, missing
from .policy import Policy
from .redirects import RedirectGuard
from .urls import safe_url, domain_group, digest, origin, canonical_url

DOM_SCRIPT = r"""(limit) => {
 const all = document.querySelectorAll('*');
 const forms = Array.from(document.forms).slice(0,1000);
 const scripts = Array.from(document.scripts).slice(0,10000);
 const text = (document.body?.innerText || '').slice(0,20000).toLowerCase();
 const cross = u => { try { return new URL(u, location.href).origin !== location.origin; } catch { return false; }};
 return {
  measured: true, node_count: Math.min(all.length,limit), truncated: all.length>limit || document.forms.length>1000 || document.scripts.length>10000,
  form_count: document.forms.length, password_input_count: document.querySelectorAll('input[type=password]').length,
  input_count: document.querySelectorAll('input').length, iframe_count: document.querySelectorAll('iframe').length,
  cross_origin_form_count: forms.filter(f=>cross(f.action)).length,
  post_form_count: forms.filter(f=>f.method.toLowerCase()==='post').length,
  script_count: document.scripts.length, inline_script_count: scripts.filter(s=>!s.src).length,
  external_script_count: scripts.filter(s=>s.src).length, cross_origin_script_count: scripts.filter(s=>s.src && cross(s.src)).length,
  storage_key_count: (()=>{try{return localStorage.length+sessionStorage.length;}catch{return null;}})(),
  disposition_flags: {
   challenge: /checking your browser|verify you are human|just a moment|captcha|access denied/.test(text+' '+document.title.toLowerCase()),
   takedown: /website has been suspended|account suspended|site has been removed|this site has been taken down/.test(text),
   parked: /domain is for sale|buy this domain|this domain is parked/.test(text)
  }
 };
}"""


def header_features(headers):
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    security = ("content-security-policy", "strict-transport-security", "x-frame-options",
                "x-content-type-options", "referrer-policy", "permissions-policy")
    # Do not persist arbitrary header values (tokens can appear anywhere).
    cookies = h.get("set-cookie", "").lower()
    return {"measured": True, "header_count": len(h), "security_header_count": sum(k in h for k in security),
            "presence": {k: k in h for k in security}, "set_cookie_present": "set-cookie" in h,
            "cookie_secure_present": "secure" in cookies if cookies else None,
            "cookie_httponly_present": "httponly" in cookies if cookies else None,
            "cookie_samesite_present": "samesite=" in cookies if cookies else None,
            "server_present": "server" in h, "content_type_html": "text/html" in h.get("content-type", "").lower(),
            "location": safe_url(h["location"]) if "location" in h else None}


class Collector:
    def __init__(self, browser, config, redirect_guard=None, control_origin=None):
        self.browser, self.config = browser, config
        self.redirect_guard = redirect_guard
        self.control_origin = origin(control_origin) if control_origin is not None else None
        from .live_view import LiveView
        self.live_view = LiveView.from_environment()

    async def observe(self, item):
        resources = {"contexts": [], "tasks": [], "guard": None, "owner": None}
        result = None
        try:
            result = await self._observe(item, resources)
        finally:
            # Covers cancellation and failures during context creation/event setup.
            try:
                await self._close_contexts(resources)
                if resources["guard"] is not None and self.redirect_guard is None:
                    await resources["guard"].close()
            finally:
                for task in resources["tasks"]:
                    if not task.done():
                        task.cancel()
                if resources["tasks"]:
                    await asyncio.gather(*resources["tasks"], return_exceptions=True)
                if self.live_view is not None:
                    snapshot = resources.get('live_signals')
                    self.live_view.state(item, 'visit finished', outcome=result[0]['outcome'] if result else 'interrupted',
                                         reason=(result[0].get('policy_reason') or result[0].get('error_type')) if result else None,
                                         signals=snapshot() if snapshot else {})
        if result is not None and getattr(resources["guard"], "failed", False):
            record, _ = result
            record.update(outcome="policy_blocked", eligible=False, transient=False,
                          policy_reason=resources["guard"].failure_reason or "redirect_guard_failure")
        return result

    async def _close_contexts(self, resources):
        """Stop network activity before freezing measurements or releasing ownership."""
        for context in list(resources["contexts"]):
            try:
                await asyncio.wait_for(context.close(), timeout=5)
            except Exception:
                guard = resources["guard"]
                if guard is not None:
                    guard.failed, guard.failure_reason = True, "context_teardown_failed"
                invalidate = resources.get("invalidate")
                if invalidate is not None:
                    invalidate("context_teardown_failed")
                # Keep interception and ownership installed unless browser closure
                # actually succeeds. A context that may still browse is not released.
                await asyncio.wait_for(self.browser.close(), timeout=5)
            resources["contexts"].remove(context)
        if resources["owner"] is not None:
            await resources["guard"].unregister(resources["owner"])
            resources["owner"] = None

    async def _observe(self, item, resources):
        c = self.config
        started = time.monotonic()
        policy = Policy(c)
        if self.live_view is not None:
            self.live_view.state(item, 'destination safety checks')
        if self.control_origin is not None:
            base_check = policy.check
            async def control_check(url):
                allowed, reason = await base_check(url)
                if allowed and origin(url) != self.control_origin:
                    return False, 'outside_owned_control'
                return allowed, reason
            policy.check = control_check
        approved, reason = await policy.check(item["url"])
        record = {"schema_version": 1, "protocol_version": PROTOCOL_VERSION, "extractor_version": __version__,
                  "browser_version": self.browser.version, "python_version": platform.python_version(),
                  "candidate_id": item["id"], "attempt_id": item["attempt_id"],
                  "captured_at": datetime.now(timezone.utc).isoformat(), "config_hash": c.fingerprint,
                  "profile": c.profile, "route_id": c.route_id, "region": c.region,
                  "input": safe_url(item["url"]), "outcome": "not_started", "eligible": False,
                  "transient": False, "retry_after": 0, "truncation": [],
                  "groups": {k: missing("not_observed") for k in ("http", "redirects", "tls", "dns", "dom", "network", "javascript", "interaction")}}
        events, response_tasks = [], set()
        if not approved:
            record["outcome"] = "policy_blocked"
            record["policy_reason"] = reason
            return record, events
        guard = self.redirect_guard or await RedirectGuard.start(self.browser)
        resources["guard"] = guard
        metadata_tasks = [asyncio.create_task(dns_metadata(item["url"], c)), asyncio.create_task(tls_metadata(item["url"], c))]
        resources["tasks"].extend(metadata_tasks)
        context = await self.browser.new_context(viewport={"width": c.viewport_width, "height": c.viewport_height},
                    locale=c.locale, timezone_id=c.timezone, accept_downloads=False, service_workers="block",
                    ignore_https_errors=False, proxy=c.proxy())
        resources["contexts"].append(context)
        page = await context.new_page()
        counts = Counter()
        request_rows = {}
        responses = {}
        transfer_bytes = 0
        main_headers, main_tls, main_status = None, None, None
        blocked = Counter()
        policy_rejected = False
        guard_failed = False

        def elapsed():
            return round((time.monotonic() - started) * 1000, 3)

        def event(kind, **data):
            if len(events) < c.max_requests * 4:
                events.append({"kind": kind, "elapsed_ms": elapsed(), **data})
            elif "event_limit" not in record["truncation"]:
                record["truncation"].append("event_limit")

        def spawn(coroutine):
            task = asyncio.create_task(coroutine)
            response_tasks.add(task)
            task.add_done_callback(response_tasks.discard)
            def completed(t):
                if not t.cancelled() and t.exception():
                    record["truncation"].append("response_processing_error")
            task.add_done_callback(completed)
            resources["tasks"].append(task)

        def reserve():
            if counts["route_slots"] >= c.max_requests or transfer_bytes > c.max_transfer_bytes:
                record["truncation"].append("request_limit" if counts["route_slots"] >= c.max_requests else "transfer_limit")
                blocked["budget"] += 1
                record.update(outcome="budget_truncated", eligible=False, transient=False)
                return False
            # Reserve before DNS awaits, so concurrent requests cannot exceed the cap.
            counts["route_slots"] += 1
            return True

        def reject(why, url):
            nonlocal policy_rejected
            policy_rejected = True
            record["policy_reason"] = why
            record.update(outcome="policy_blocked", eligible=False, transient=False)
            blocked[why] += 1
            event("blocked", reason=why, url=safe_url(url))

        def admit(request):
            if request in request_rows:
                return
            counts["requests"] += 1
            rid = str(counts["requests"])
            request_rows[request] = {"id": rid, "url": safe_url(request.url), "method": request.method,
                                     "resource_type": request.resource_type, "start_ms": elapsed(),
                                     "third_party": domain_group(request.url) != domain_group(item["url"])}
            event("request", **request_rows[request])

        def on_request(request):
            # Redirected requests bypass Playwright routes. Only their already-admitted
            # predecessors can create a candidate for the response guard to approve.
            admit_redirect(request)

        async def redirect_allowed(target, paused):
            if not reserve():
                return False
            ok, why = await policy.check(target)
            if not ok:
                reject(why, target)
                return False
            # This one-use approval is created before Chromium can send the successor.
            # The successor must also link to an admitted predecessor in this attempt.
            approved_redirects.append((canonical_url(paused["request"]["url"]), origin(canonical_url(target))))
            return True

        approved_redirects = []

        def admit_redirect(request):
            if request in request_rows:
                return True
            previous = request.redirected_from
            if previous in request_rows:
                # Chromium escapes Location paths/queries. Match the native parent
                # link and origin, while recording the browser's actual successor URL.
                pair = (canonical_url(previous.url), origin(canonical_url(request.url)))
                if pair in approved_redirects:
                    approved_redirects.remove(pair)
                    admit(request)
                    return True
                # A successor without a matching pre-network approval cannot count
                # as a complete measurement, even if rendering later succeeds.
                record["truncation"].append("redirect_admission_unavailable")
            return request in request_rows

        def invalidate(why):
            nonlocal guard_failed
            guard_failed = True
            reject(why, item["url"])

        resources["invalidate"] = invalidate

        async def guard_failure(why):
            invalidate(why)
            await asyncio.wait_for(context.close(), timeout=5)

        async def route_handler(route, request):
            if not reserve():
                await route.abort()
                return
            ok, why = await policy.check(request.url)
            if not ok:
                reject(why, request.url)
                await route.abort()
                return
            admit(request)
            await route.continue_()

        async def on_response(response):
            nonlocal main_headers, main_tls, main_status
            request = response.request
            admit_redirect(request)
            if request not in request_rows:
                return
            headers = await response.all_headers()
            features = header_features(headers)
            data = {"request_id": request_rows[request]["id"], "status": response.status,
                    "url": safe_url(response.url), "headers": features}
            responses[request] = data
            if request.is_navigation_request() and request.frame == page.main_frame:
                main_headers, main_status = features, response.status
                try:
                    main_tls = await response.security_details()
                except Exception:
                    main_tls = None
                data["browser_tls"] = main_tls
                if response.status in {429, 503}:
                    try:
                        record["retry_after"] = min(3600, max(0, int(headers.get("retry-after", "0"))))
                    except ValueError:
                        # HTTP-date values are handled explicitly too.
                        from email.utils import parsedate_to_datetime
                        try:
                            record["retry_after"] = min(3600, max(0, parsedate_to_datetime(headers["retry-after"]).timestamp() - time.time()))
                        except Exception:
                            pass
            event("response", **data)

        async def on_finished(request):
            nonlocal transfer_bytes
            admit_redirect(request)
            if request not in request_rows:
                return
            try:
                sizes = await request.sizes()
                transfer_bytes += sizes["responseBodySize"] + sizes["responseHeadersSize"]
                request_rows[request]["finish_ms"] = elapsed()
                request_rows[request]["response_bytes"] = sizes["responseBodySize"]
                event("finished", request_id=request_rows[request]["id"], sizes=sizes)
                if transfer_bytes > c.max_transfer_bytes and "transfer_limit" not in record["truncation"]:
                    record["truncation"].append("transfer_limit")
                    await page.close()
            except Exception:
                request_rows[request]["sizes_missing_reason"] = "request_sizes_unavailable"

        def on_failed(request):
            admit_redirect(request)
            if request in request_rows:
                # Chromium rejects duplicate Location headers before Fetch can
                # expose their status/headers. Preserve its native rejection as
                # a permanent policy outcome, not a retryable network failure.
                if request.failure == "net::ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION":
                    reject("invalid_redirect_location", request.url)
                counts["failed"] += 1
                # Error strings can contain full URLs. Store category only.
                event("failed", request_id=request_rows[request]["id"], reason="browser_request_failed")

        await context.route("**/*", route_handler)
        await context.route_web_socket("**/*", lambda ws: ws.close())
        context.on("request", on_request)
        context.on("response", lambda r: spawn(on_response(r)))
        context.on("requestfinished", lambda r: spawn(on_finished(r)))
        context.on("requestfailed", on_failed)
        resources["owner"] = await guard.register(page, redirect_allowed, guard_failure)
        page.on("download", lambda download: spawn(download.cancel()))
        page.on("popup", lambda popup: spawn(popup.close()))
        page.on("dialog", lambda dialog: spawn(dialog.dismiss()))
        page.on("pageerror", lambda error: counts.update(["javascript_errors"]))
        if self.live_view is not None:
            def live_signals():
                measured = {}
                for name, task in zip(('dns', 'tls'), metadata_tasks):
                    if task.done() and not task.cancelled():
                        try:
                            measured[name] = task.result()
                        except Exception:
                            measured[name] = {'measured': False, 'missing_reason': 'metadata_task_failed'}
                traffic = [{key: row[key] for key in ('kind','elapsed_ms','method','resource_type','status','reason','url') if key in row}
                           for row in events if row['kind'] in ('request','response','blocked','failed')][-12:]
                return {'requests': len(request_rows), 'responses': len(responses), 'failed': counts['failed'],
                        'transfer_bytes': transfer_bytes, 'http_status': main_status,
                        'dom': record['groups']['dom'], 'javascript': record['groups']['javascript'],
                        **measured, 'traffic': traffic}
            resources['live_signals'] = live_signals
            resources['tasks'].append(asyncio.create_task(self.live_view.frames(page, item, live_signals)))
        try:
            async with asyncio.timeout(c.attempt_seconds):
                await page.goto(item["url"], wait_until="domcontentloaded", timeout=c.navigation_seconds * 1000)
                record["dom_ready_ms"] = elapsed()
                await page.wait_for_timeout(c.observation_seconds * 1000)
                before = await page.evaluate(DOM_SCRIPT, c.max_dom_nodes)
                record["groups"]["dom"] = {k: v for k, v in before.items() if k not in {"script_count", "inline_script_count", "external_script_count", "cross_origin_script_count", "disposition_flags"}}
                record["disposition_flags"] = before["disposition_flags"]
                record["groups"]["javascript"] = {"measured": True, **{k: before[k] for k in ("script_count", "inline_script_count", "external_script_count", "cross_origin_script_count")},
                                                     "page_error_count": counts["javascript_errors"]}
                if before["truncated"]:
                    record["truncation"].append("dom_limit")
                record["dom_structure_hash"] = digest(json.dumps({k: before[k] for k in ("form_count", "input_count", "iframe_count", "script_count", "node_count")}, sort_keys=True))
                if c.interaction == "fixture_submit":
                    if origin(page.url) not in policy.allowed_origins:
                        raise RuntimeError("fixture left owned origin")
                    form = page.locator("[data-study-fixture] form")
                    if await form.count() == 1:
                        await form.locator("input[type=email]").fill("research-invalid@example.invalid")
                        await form.locator("input[type=password]").fill("SYNTHETIC-INVALID-NO-CREDENTIAL")
                        req_before = counts["requests"]
                        await form.locator("button[type=submit]").click(timeout=3000)
                        await page.wait_for_timeout(300)
                        after = await page.evaluate(DOM_SCRIPT, c.max_dom_nodes)
                        record["groups"]["interaction"] = {"measured": True, "policy": "owned_fixture_submit",
                            "actions": 1, "new_request_count": counts["requests"] - req_before,
                            "node_count_delta": after["node_count"] - before["node_count"],
                            "storage_key_count_delta": None if before["storage_key_count"] is None or after["storage_key_count"] is None else after["storage_key_count"] - before["storage_key_count"]}
                    else:
                        record["groups"]["interaction"] = missing("fixture_form_absent")
                else:
                    record["groups"]["interaction"] = missing("passive_policy_no_actions")
                record["final"] = safe_url(page.url)
                record["outcome"] = "captured"
        except Exception as exc:
            name = type(exc).__name__
            record["outcome"] = "timeout" if "Timeout" in name else "navigation_error"
            record["error_type"] = name
            record["transient"] = name in {"TimeoutError", "Error"}
        finally:
            # Fetch metadata already requested while the page is alive. Playwright
            # races header/size/security retrieval against context closure.
            if response_tasks:
                try:
                    await asyncio.wait_for(asyncio.gather(*list(response_tasks), return_exceptions=True), timeout=3)
                except asyncio.TimeoutError:
                    record["truncation"].append("response_tasks_timeout")
            # Close the context and drain its guard callbacks before classification.
            # Otherwise a late rejected redirect can mutate an already-eligible record.
            await self._close_contexts(resources)
            # Bound completion of response tasks after the request stream is frozen.
            if response_tasks:
                try:
                    await asyncio.wait_for(asyncio.gather(*list(response_tasks), return_exceptions=True), timeout=3)
                except asyncio.TimeoutError:
                    record["truncation"].append("response_tasks_timeout")
            for task in list(response_tasks):
                task.cancel()
            dns_result, tls_result = await asyncio.gather(*metadata_tasks, return_exceptions=True)
            record["groups"]["dns"] = dns_result if isinstance(dns_result, dict) else missing("dns_error")
            record["groups"]["tls"] = tls_result if isinstance(tls_result, dict) else missing("tls_error")
        main_responses = [data for request, data in sorted(responses.items(), key=lambda pair: request_rows[pair[0]]["start_ms"]) if request.is_navigation_request() and request.frame == page.main_frame]
        if main_responses:
            last_document = main_responses[-1]
            main_headers, main_status, main_tls = last_document["headers"], last_document["status"], last_document.get("browser_tls")
        if main_tls:
            record["groups"]["tls"]["browser"] = {"measured": True, **main_tls, "vantage": "browser_connection", "target": main_responses[-1]["url"]}
        record["groups"]["dns"]["target"] = safe_url(item["url"])
        record["groups"]["tls"]["target"] = safe_url(item["url"])
        if main_headers is not None:
            record["groups"]["http"] = main_headers | {"status": main_status}
        record["groups"]["redirects"] = {"measured": main_status is not None, "http_redirect_count": sum(300 <= r["status"] < 400 for r in main_responses),
            "main_document_count": len(main_responses), "cross_origin_hop_count": sum(main_responses[i]["url"].get("origin") != main_responses[i-1]["url"].get("origin") for i in range(1, len(main_responses))),
            "chain": [{"status": r["status"], "url": r["url"]} for r in main_responses]}
        methods = Counter(r["method"] for r in request_rows.values())
        resources = Counter(r["resource_type"] for r in request_rows.values())
        statuses = Counter(str(r["status"] // 100) + "xx" for r in responses.values())
        unique_origins = {r["url"].get("origin") for r in request_rows.values()}
        record["groups"]["network"] = {"measured": bool(request_rows), "request_count": len(request_rows),
            "response_count": len(responses), "failed_request_count": counts["failed"], "methods": dict(methods),
            "resource_types": dict(resources), "status_classes": dict(statuses), "destination_origin_count": len(unique_origins),
            "third_party_request_count": sum(r["third_party"] for r in request_rows.values()), "response_transfer_bytes": transfer_bytes,
            "blocked_requests": dict(blocked), "websocket_policy": "blocked", "body_policy": "never_persisted",
            "duration_ms": elapsed()}
        record["truncation"] = sorted(set(record["truncation"]))
        if main_status in {429, 502, 503, 504}:
            record["outcome"], record["transient"] = "http_transient", True
        elif main_status is not None and main_status >= 400:
            record["outcome"], record["transient"] = "http_error", False
        elif record.get("disposition_flags"):
            for kind in ("challenge", "takedown", "parked"):
                if record["disposition_flags"][kind]:
                    record["outcome"], record["transient"] = kind, False
                    break
        if record["truncation"]:
            record["outcome"], record["transient"] = "budget_truncated", False
        if policy_rejected or guard_failed:
            record["outcome"], record["transient"] = "policy_blocked", False
        if record["outcome"] == "captured" and main_headers and not main_headers["content_type_html"]:
            record["outcome"] = "non_html"
        record["eligible"] = record["outcome"] == "captured" and bool(main_headers and main_headers["content_type_html"])
        return record, events


def save(root, record, events):
    folder = Path(root) / "observations"
    folder.mkdir(exist_ok=True, mode=0o700)
    base = folder / record["attempt_id"]
    json_path = base.with_suffix(".json")
    temp = json_path.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(record, f, sort_keys=True, allow_nan=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, json_path)
    event_path = base.with_suffix(".events.jsonl.gz")
    temporary = event_path.with_suffix(".tmp")
    with gzip.open(temporary, "wt", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, sort_keys=True, allow_nan=False) + "\n")
    os.replace(temporary, event_path)
    return str(json_path.relative_to(root))
