"""Browser-native redirect destination checks, without reading or replaying bodies.

Playwright's Chromium routes omit HTTP redirect hops. A separate browser CDP
session pauses responses before Chromium follows Location, while the ordinary
context routes continue to check initial requests. All callbacks receive only
ephemeral protocol data; this module never persists it.
"""
import asyncio
from collections import OrderedDict
from contextvars import ContextVar
from dataclasses import dataclass, field
import re
from urllib.parse import urljoin, urlsplit, urlunsplit


REDIRECT_STATUSES = {301, 302, 303, 307, 308}
COMMAND_SECONDS = 5
CALLBACK_SECONDS = 10
_active_pause_task = ContextVar("redirect_guard_active_pause_task", default=None)


async def shutdown_browser(browser, guard):
    """End a fixture/browser lifetime with interception retained until exit."""
    async def bounded(operation, seconds):
        task = asyncio.create_task(operation())
        try:
            done, _ = await asyncio.wait({task}, timeout=seconds)
            if task not in done:
                raise TimeoutError('browser_shutdown_deadline')
            return task.result()
        finally:
            if not task.done():
                task.cancel()
                def consume(value):
                    try:
                        value.exception()
                    except BaseException:
                        pass
                task.add_done_callback(consume)
    modern = guard is not None and callable(getattr(guard, 'close_after_browser', None))
    if modern:
        guard.prepare_browser_shutdown()
        await bounded(browser.close, 12)
        await bounded(guard.close_after_browser, 20)
    else:
        try:
            if guard is not None:
                await bounded(guard.close, 20)
        finally:
            await bounded(browser.close, 12)


def _pause_disappeared(exc):
    # Chromium removes Fetch pauses when a context closes or a request is
    # cancelled. This protocol reply is an acknowledgement of that race, not
    # evidence that interception has stopped working for other observations.
    message = str(exc).lower()
    return "invalid interceptionid" in message or "invalid requestid" in message


def redirect_target(paused):
    """Return an unambiguous HTTP(S) Location, or None for a normal response.

    Chromium uses WHATWG URL resolution. Reject the authority forms on which
    Python's RFC-oriented urljoin differs, rather than approving one destination
    while the browser follows another. The actual browser response stays intact.
    """
    if paused.get("responseStatusCode") not in REDIRECT_STATUSES:
        return None
    locations = [h.get("value") for h in paused.get("responseHeaders", [])
                 if str(h.get("name", "")).lower() == "location"]
    if not locations:
        return None
    if len(locations) != 1 or not isinstance(locations[0], str):
        raise ValueError("invalid_redirect_location")
    location = locations[0].strip(" \t\r\n\f")
    authority = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*:", "", location)
    if (not location or len(location) > 8192 or "\\" in location
            or any(ord(c) < 32 or ord(c) == 127 for c in location)
            or authority.startswith("///")):
        raise ValueError("invalid_redirect_location")
    target = urlsplit(urljoin(paused["request"]["url"], location))
    if (target.scheme not in {"http", "https"} or not target.hostname
            or target.username is not None or target.password is not None):
        raise ValueError("invalid_redirect_location")
    target.port  # Validate malformed/out-of-range ports before any callback.
    return urlunsplit(target._replace(fragment=""))


@dataclass(eq=False)
class RedirectOwner:
    """Registration token for one isolated observation context."""
    page: object
    session: object
    on_redirect: object
    on_failure: object
    context_id: str | None = None
    frame_ids: set = field(default_factory=set)
    listeners: list = field(default_factory=list)
    active: bool = True
    failure_reported: bool = False


class RedirectGuard:
    def __init__(self, browser, session):
        self.browser, self.session = browser, session
        self._owners = set()
        self._frames = {}
        self._contexts = {}
        self._tasks = set()
        self._task_owners = {}
        self._pending = set()
        self._resolved = OrderedDict()
        self._closing = False
        self._closed = False
        self.failed = False
        self.failure_reason = None

    @classmethod
    async def start(cls, browser):
        """Install the singleton before any collection context is created."""
        session = await browser.new_browser_cdp_session()
        guard = cls(browser, session)
        session.on("Fetch.requestPaused", guard._on_paused)
        try:
            await guard._send(session, "Fetch.enable", {
                "patterns": [{"urlPattern": "*", "requestStage": "Response"}],
            })
        except BaseException:
            session.remove_listener("Fetch.requestPaused", guard._on_paused)
            await session.detach()
            raise
        return guard

    async def _send(self, session, method, params=None):
        return await asyncio.wait_for(session.send(method, params or {}), COMMAND_SECONDS)

    async def register(self, page, on_redirect, on_failure):
        """Register before navigation; callbacks are async, categorical on failure.

        on_redirect(target_url, paused_event) returns bool. It must reserve the
        next attempt-local request slot and check policy before returning True.
        on_failure(reason) marks the observation incomplete and closes its context.
        """
        if self._closing or self.failed:
            raise RuntimeError("redirect_guard_unavailable")
        session = await page.context.new_cdp_session(page)
        owner = RedirectOwner(page, session, on_redirect, on_failure)
        self._owners.add(owner)

        def attached(event):
            if owner.active:
                self._remember_frame(owner, event["frameId"])

        def navigated(event):
            if owner.active:
                self._remember_frame(owner, event["frame"]["id"])

        def detached(event):
            # A process swap keeps the frame and its ownership alive.
            if event.get("reason") != "swap":
                frame_id = event["frameId"]
                if self._frames.get(frame_id) is owner:
                    self._frames.pop(frame_id, None)
                owner.frame_ids.discard(frame_id)

        for name, listener in (("Page.frameAttached", attached),
                               ("Page.frameNavigated", navigated),
                               ("Page.frameDetached", detached)):
            session.on(name, listener)
            owner.listeners.append((name, listener))
        try:
            await self._send(session, "Page.enable")
            info = (await self._send(session, "Target.getTargetInfo"))["targetInfo"]
            owner.context_id = info.get("browserContextId")
            if not owner.context_id:
                raise RuntimeError("redirect_guard_context_unavailable")
            if owner.context_id in self._contexts:
                raise RuntimeError("redirect_guard_context_already_registered")
            self._contexts[owner.context_id] = owner
            await self._refresh_frames(owner)
            return owner
        except BaseException:
            await self.unregister(owner)
            raise

    def _remember_frame(self, owner, frame_id):
        previous = self._frames.get(frame_id)
        if previous is not None and previous is not owner:
            raise RuntimeError("redirect_guard_owner_conflict")
        owner.frame_ids.add(frame_id)
        self._frames[frame_id] = owner

    async def _refresh_frames(self, owner):
        tree = (await self._send(owner.session, "Page.getFrameTree"))["frameTree"]

        def visit(node):
            if owner.active:
                self._remember_frame(owner, node["frame"]["id"])
                for child in node.get("childFrames", []):
                    visit(child)

        visit(tree)

    async def _owner_for(self, frame_id):
        owner = self._frames.get(frame_id)
        if owner is not None:
            return owner
        # A frame may have attached before its Page event reaches this client.
        active = [owner for owner in self._owners if owner.active]
        await asyncio.gather(*(self._refresh_frames(owner) for owner in active),
                             return_exceptions=True)
        owner = self._frames.get(frame_id)
        if owner is not None:
            return owner
        # Worker/OOPIF target identifiers may be the Fetch frameId. Use their
        # browser context, never URL matching across concurrent observations.
        try:
            info = (await self._send(self.session, "Target.getTargetInfo", {
                "targetId": frame_id,
            }))["targetInfo"]
            owner = self._contexts.get(info.get("browserContextId"))
            if owner is not None:
                if owner.active:
                    self._remember_frame(owner, frame_id)
                return owner
        except Exception:
            pass
        # Failed refreshes must not turn into a permissive ownership guess.
        return None

    def _on_paused(self, paused):
        request_id = paused.get("requestId")
        if not request_id or request_id in self._pending or request_id in self._resolved:
            return
        self._pending.add(request_id)
        task = asyncio.create_task(self._handle_paused(paused))
        self._tasks.add(task)
        # The cheap frame lookup covers ordinary document/subresource responses
        # without adding a Page protocol round trip to each network response.
        self._task_owners[task] = self._frames.get(paused.get("frameId"))

        def done(completed):
            self._tasks.discard(completed)
            self._task_owners.pop(completed, None)
            self._pending.discard(request_id)
            self._resolved[request_id] = None
            if len(self._resolved) > 8192:
                self._resolved.popitem(last=False)
            # Every ordinary error is handled inside _handle_paused. Consume
            # cancellation/late transport exceptions so teardown is quiet.
            if not completed.cancelled():
                completed.exception()

        task.add_done_callback(done)

    async def _notify_failure(self, owner, reason):
        owners = [owner] if owner is not None else list(self._owners)
        if owner is None:
            self.failed, self.failure_reason = True, reason
        for registered in owners:
            if registered.active and not registered.failure_reported:
                registered.failure_reported = True
                try:
                    await asyncio.wait_for(registered.on_failure(reason), CALLBACK_SECONDS)
                except Exception:
                    # If even closing the owning context fails, close the browser.
                    self.failed, self.failure_reason = True, "redirect_guard_cleanup_failed"
                    await asyncio.wait_for(self.browser.close(), COMMAND_SECONDS)

    async def _abort(self, request_id):
        """Abort a pause; False means cancellation/closure already removed it."""
        try:
            await self._send(self.session, "Fetch.failRequest", {
                "requestId": request_id, "errorReason": "BlockedByClient",
            })
            return True
        except Exception as exc:
            # Context closure and native cancellation can remove the pause before
            # its task resumes. That specific response means there is no request
            # left to release; other transport failures still close the browser.
            if _pause_disappeared(exc):
                return False
            if self._closing and not self.browser.is_connected():
                return False  # Deliberate browser exit already destroyed this pause.
            # An unresolvable paused response must not be released by detaching.
            self.failed, self.failure_reason = True, "redirect_guard_transport_failed"
            await asyncio.wait_for(self.browser.close(), COMMAND_SECONDS)
            return False

    async def _handle_paused(self, paused):
        token = _active_pause_task.set(asyncio.current_task())
        try:
            await self._process_paused(paused)
        finally:
            _active_pause_task.reset(token)

    async def _process_paused(self, paused):
        owner = self._task_owners.get(asyncio.current_task())
        request_id = paused["requestId"]
        try:
            if self._closing or self.failed or (owner is not None and not owner.active):
                await self._abort(request_id)
                return
            try:
                target = redirect_target(paused)
            except (KeyError, TypeError, ValueError):
                owner = await self._owner_for(paused.get("frameId"))
                self._task_owners[asyncio.current_task()] = owner
                existed = await self._abort(request_id)
                if existed and (owner is None or owner.active):
                    await self._notify_failure(owner, "invalid_redirect_location")
                return
            if target is not None:
                owner = await self._owner_for(paused.get("frameId"))
                self._task_owners[asyncio.current_task()] = owner
                if owner is None:
                    if await self._abort(request_id):
                        await self._notify_failure(None, "redirect_owner_unknown")
                    return
                if not owner.active:
                    await self._abort(request_id)
                    return
                allowed = await asyncio.wait_for(owner.on_redirect(target, paused), CALLBACK_SECONDS)
                if not allowed or not owner.active or self._closing or self.failed:
                    await self._abort(request_id)
                    return
            # No status/header overrides: Chromium keeps its normal redirect,
            # cookie, method, certificate, and streaming behavior.
            try:
                await self._send(self.session, "Fetch.continueResponse", {"requestId": request_id})
            except Exception as exc:
                if _pause_disappeared(exc):
                    return
                await self._abort(request_id)
                # The browser session is shared across all observations; an
                # actual command failure must invalidate that shared guard.
                await self._notify_failure(None, "redirect_guard_transport_failed")
                return
        except asyncio.CancelledError:
            await self._abort(request_id)
            if owner is not None and owner.active and not self._closing:
                await self._notify_failure(owner, "redirect_guard_cancelled")
            raise
        except Exception:
            await self._abort(request_id)
            await self._notify_failure(owner, "redirect_guard_error")

    async def unregister(self, owner):
        """Remove registration after its context has been closed."""
        owner.active = False
        # Keep attribution until every already-dispatched pause for this closed
        # context has resolved. Newly dispatched pauses see the inactive owner
        # and abort instead of becoming spurious global ownership failures.
        await self._drain_tasks(lambda: {
            task for task, registered in self._task_owners.items()
            if registered is owner
        })
        self._owners.discard(owner)
        if self._contexts.get(owner.context_id) is owner:
            self._contexts.pop(owner.context_id, None)
        for frame_id in owner.frame_ids:
            if self._frames.get(frame_id) is owner:
                self._frames.pop(frame_id, None)
        owner.frame_ids.clear()
        for name, listener in owner.listeners:
            owner.session.remove_listener(name, listener)
        owner.listeners.clear()
        try:
            await asyncio.wait_for(owner.session.detach(), COMMAND_SECONDS)
        except Exception:
            pass  # Context closure may already have detached the session.

    async def _drain_tasks(self, select):
        # wait_for creates callback child tasks. The ContextVar preserves their
        # parent Fetch identity so callback-triggered unregister cannot deadlock.
        excluded = {asyncio.current_task(), _active_pause_task.get()}
        loop = asyncio.get_running_loop()
        deadline = loop.time() + COMMAND_SECONDS
        pending = set()
        while True:
            pending = {task for task in select() if task not in excluded and not task.done()}
            if not pending:
                return
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            _, pending = await asyncio.wait(pending, timeout=remaining)
            if pending:
                break
        for task in pending:
            task.cancel()
        deadline = loop.time() + 2 * COMMAND_SECONDS
        while pending:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            await asyncio.wait(pending, timeout=remaining)
            pending = {task for task in select() if task not in excluded and not task.done()}
            for task in pending:
                task.cancel()
        if pending:
            self.failed, self.failure_reason = True, "redirect_guard_cleanup_failed"
            self._closing = True
            # Successful browser closure guarantees no paused response can be
            # released by removing the registration. Failure leaves Fetch on.
            await asyncio.wait_for(self.browser.close(), COMMAND_SECONDS)

    def prepare_browser_shutdown(self):
        """Keep interception installed while the bounded browser close runs."""
        self._closing = True

    async def close_after_browser(self):
        """Release local bookkeeping only after Chromium has disconnected.

        Fetch.disable on a live, otherwise empty browser can stall in the pinned
        headless build. Retaining Fetch through Browser.close avoids releasing
        any paused request and gives the browser its own unchanged deadline.
        """
        if self.browser.is_connected():
            raise RuntimeError('browser_must_disconnect_before_guard_release')
        if self._closed:
            return
        self._closing = True
        for owner in list(self._owners):
            await self.unregister(owner)
        await self._drain_tasks(lambda: set(self._tasks))
        self.session.remove_listener('Fetch.requestPaused', self._on_paused)
        try:
            await asyncio.wait_for(self.session.detach(), COMMAND_SECONDS)
        except Exception:
            pass  # Browser exit is already established; no response can resume.
        self._closed = True

    async def close(self):
        """Stop only after collection contexts close, so pauses cannot escape."""
        if self._closed:
            return
        self._closing = True
        if self._owners:
            # Enforce the lifecycle even when a caller forgets context teardown.
            results = await asyncio.gather(*(
                asyncio.wait_for(owner.page.context.close(), COMMAND_SECONDS)
                for owner in self._owners), return_exceptions=True)
            if any(isinstance(result, BaseException) for result in results):
                self.failed, self.failure_reason = True, "redirect_guard_cleanup_failed"
                await asyncio.wait_for(self.browser.close(), COMMAND_SECONDS)
        for owner in list(self._owners):
            await self.unregister(owner)
        await self._drain_tasks(lambda: set(self._tasks))
        self.session.remove_listener("Fetch.requestPaused", self._on_paused)
        try:
            await self._send(self.session, "Fetch.disable")
            await asyncio.wait_for(self.session.detach(), COMMAND_SECONDS)
        except Exception:
            self.failed, self.failure_reason = True, "redirect_guard_cleanup_failed"
            await asyncio.wait_for(self.browser.close(), COMMAND_SECONDS)
        self._closed = True
