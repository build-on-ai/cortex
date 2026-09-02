"""Client identity, sessions and the auth dependency.

ClientIdentity derives the rate-limit key, SessionManager is the only way to
mint or revoke a session cookie, and require_auth is the dependency every
authenticated endpoint uses. Both auth paths bucket the caller into a rate
limit on success, so no branch can skip it.
"""
from __future__ import annotations

import hashlib as _hashlib
import ipaddress as _ipa
import logging as _logging
import secrets as _secrets
import threading as _threading
import time as _time
from typing import Callable

_log = _logging.getLogger("security.auth")


class AuthError(Exception):
    """Internal exception — web adapter converts to 401/429 HTTPException."""
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)



class ClientIdentity:
    """Who is calling, for rate-limit bucketing.

    Proxy-header trust is an explicit flag; X-Forwarded-For is never trusted
    because proxies append to it and the leftmost value is caller-set. IPv6 zone
    ids are stripped and addresses bucket at /64, which is what an ISP assigns.
    """

    _TRUSTED_SINGLE_VALUE_HEADERS = ("true-client-ip", "cf-connecting-ip", "x-real-ip")

    def __init__(self, ip: str):
        self.ip = ip

    @classmethod
    def from_request(cls, request_or_ws, *, trust_proxy: bool) -> "ClientIdentity":
        ip = ""
        try:
            if trust_proxy and hasattr(request_or_ws, "headers"):
                for h in cls._TRUSTED_SINGLE_VALUE_HEADERS:
                    v = request_or_ws.headers.get(h, "").strip()
                    if v:
                        ip = v
                        break
            if not ip:
                client = getattr(request_or_ws, "client", None)
                if client and client.host:
                    ip = client.host
        except Exception:
            pass
        return cls(ip)

    def bucket_key(self) -> str:
        return rate_limit_key(self.ip)


def rate_limit_key(ip: str) -> str:
    """Normalise *ip* into a rate-limit bucket key. Public so tests
    can exercise the collapse rules directly."""
    if not ip:
        return ""
    if "%" in ip:
        ip = ip.split("%", 1)[0]
    if ":" in ip:
        try:
            addr = _ipa.ip_address(ip)
            if isinstance(addr, _ipa.IPv6Address):
                if addr.ipv4_mapped:
                    return f"v4:{addr.ipv4_mapped}"
                net = _ipa.ip_network(f"{ip}/64", strict=False)
                return f"v6/64:{net.network_address}"
        except ValueError:
            pass
    return f"v4:{ip}"



_AUTH_FAIL_WINDOW_SEC = 60
_AUTH_FAIL_LIMIT = 10
_AUTH_FAIL_GC_THRESHOLD = 256
_auth_fail_log: dict[str, list[float]] = {}
_auth_fail_lock = _threading.Lock()


def note_auth_fail(ip: str) -> bool:
    """Record an auth failure for *ip*, return True if the caller is
    now over the limit. Used by both cookie-less request paths and
    the WS handshake."""
    key = rate_limit_key(ip)
    if not key:
        return False
    now = _time.monotonic()
    cutoff = now - _AUTH_FAIL_WINDOW_SEC
    with _auth_fail_lock:
        bucket = _auth_fail_log.setdefault(key, [])
        bucket[:] = [t for t in bucket if t > cutoff][-_AUTH_FAIL_LIMIT:]
        bucket.append(now)
        if len(_auth_fail_log) > _AUTH_FAIL_GC_THRESHOLD:
            for k in [k for k, v in _auth_fail_log.items() if not v or v[-1] < cutoff]:
                _auth_fail_log.pop(k, None)
        return len(bucket) >= _AUTH_FAIL_LIMIT



class SessionManager:
    """In-memory session table with per-session rate limiting.

    The cookie carries a session id, never the master token, so a leaked cookie
    costs one revocable session. The hit counter is sharded across locks, so one
    session does not serialise the others.
    """
    SESSION_TTL_SEC = 60 * 60 * 8        # 8h
    SESSION_LIMIT = 64                   # hard cap
    SESSION_RATE_LIMIT = 600
    SESSION_RATE_WINDOW = 60.0
    SHARDS = 8
    COOKIE_NAME = "cortex_session"

    def __init__(self):
        self._sessions: dict[str, dict] = {}
        self._lock = _threading.Lock()
        self._shard_locks = [_threading.Lock() for _ in range(self.SHARDS)]
        # Master-token rate limit buckets. Authenticated
        # master-token path needs the same throttle as cookie path.
        self._mt_hits: dict[str, list[float]] = {}
        self._mt_lock = _threading.Lock()

    def _shard(self, sid: str) -> _threading.Lock:
        return self._shard_locks[hash(sid) % self.SHARDS]

    def mint(self) -> str:
        sid = _secrets.token_urlsafe(32)
        expiry = _time.monotonic() + self.SESSION_TTL_SEC
        with self._lock:
            now = _time.monotonic()
            if len(self._sessions) >= self.SESSION_LIMIT:
                expired = [k for k, v in self._sessions.items()
                           if v.get("expiry", 0) < now]
                for k in expired:
                    self._sessions.pop(k, None)
                if len(self._sessions) >= self.SESSION_LIMIT:
                    oldest = min(self._sessions.items(),
                                 key=lambda kv: kv[1].get("expiry", 0))[0]
                    self._sessions.pop(oldest, None)
            self._sessions[sid] = {"expiry": expiry, "hits": []}
        return sid

    def check(self, sid: str) -> bool:
        if not sid:
            return False
        with self._lock:
            rec = self._sessions.get(sid)
            if rec is None:
                return False
            if rec.get("expiry", 0) < _time.monotonic():
                self._sessions.pop(sid, None)
                return False
        return True

    def revoke(self, sid: str) -> None:
        if not sid:
            return
        with self._lock:
            self._sessions.pop(sid, None)

    def note_hit(self, sid: str) -> bool:
        """Per-session rate-limit hit. Returns True iff over budget."""
        if not sid:
            return False
        now = _time.monotonic()
        with self._shard(sid):
            rec = self._sessions.get(sid)
            if rec is None:
                return False
            hits = rec.setdefault("hits", [])
            cutoff = now - self.SESSION_RATE_WINDOW
            hits[:] = [t for t in hits if t > cutoff][-self.SESSION_RATE_LIMIT:]
            hits.append(now)
            return len(hits) > self.SESSION_RATE_LIMIT

    def note_master_token_hit(self, token: str, ip: str) -> bool:
        """rate-limit the master-token path too. Bucketed on
        hash(token)+ip so two honest clients with the same token
        keep independent budgets."""
        bucket_key = f"mt:{_hashlib.sha256((token + '|' + ip).encode()).hexdigest()[:32]}"
        now = _time.monotonic()
        cutoff = now - self.SESSION_RATE_WINDOW
        with self._mt_lock:
            bucket = self._mt_hits.setdefault(bucket_key, [])
            bucket[:] = [t for t in bucket if t > cutoff][-self.SESSION_RATE_LIMIT:]
            bucket.append(now)
            if len(self._mt_hits) > _AUTH_FAIL_GC_THRESHOLD:
                for k in [k for k, v in self._mt_hits.items() if not v or v[-1] < cutoff]:
                    self._mt_hits.pop(k, None)
            return len(bucket) > self.SESSION_RATE_LIMIT



def build_require_auth(
    *,
    master_token: str,
    sessions: SessionManager,
    trust_proxy: bool,
    bootstrap_rate_limit: Callable[[ClientIdentity], bool] | None = None,
) -> Callable:
    """Return a FastAPI ``Depends``-compatible callable configured
    with this instance's auth token + session manager.

    The returned callable is ``require_auth``. Every authenticated
    endpoint in web.py declares ``auth: ... = Depends(require_auth)``.
    A new route that forgets this dependency is caught by
    ``tests/test_invariants.py``.
    """
    # `global`, not a local import: FastAPI resolves the deferred annotation through
    # this module's namespace, and a local import leaves an unresolved ForwardRef
    # that 500s every route using this dependency.
    global Request
    from fastapi import Request

    def require_auth(request: Request) -> ClientIdentity:
        # The annotation is required: without it FastAPI treats the parameter as a query
        # param and every route using this dependency 422s before auth runs.
        from fastapi import HTTPException
        # Pull the inputs directly off the request so the dependency
        # signature stays uniform — endpoints can't forget a header.
        authorization = request.headers.get("authorization", "")
        x_token = request.headers.get("x-token", "")
        query_token = request.query_params.get("token", "")
        cookie_token = request.cookies.get(SessionManager.COOKIE_NAME, "")
        identity = ClientIdentity.from_request(request, trust_proxy=trust_proxy)
        # Cookie path
        if cookie_token and sessions.check(cookie_token):
            if sessions.note_hit(cookie_token):
                raise HTTPException(status_code=429, detail="Session rate limit exceeded")
            return identity
        # Master-token path — constant-time compare.
        token = ""
        if authorization.startswith("Bearer "):
            token = authorization[7:]
        elif x_token:
            token = x_token
        elif query_token:
            token = query_token
        if master_token and token and _secrets.compare_digest(token, master_token):
            # throttle successful master-token calls too.
            if sessions.note_master_token_hit(token, identity.ip):
                raise HTTPException(status_code=429, detail="Token rate limit exceeded")
            return identity
        # An empty token disables auth; web.py refuses to start that way without
        # WEB_INSECURE=1.
        if not master_token:
            return identity
        # Failure — slide into the auth-failure bucket.
        if note_auth_fail(identity.ip):
            raise HTTPException(status_code=429, detail="Too many auth failures")
        raise HTTPException(status_code=401, detail="Invalid or missing token")

    return require_auth


def public_endpoint() -> None:
    """Explicit no-auth marker for endpoints the operator has decided
    are safe to expose unauthenticated (``/health``, ``/api/logout``).
    Used as ``Depends(public_endpoint)``. The invariant test accepts
    this instead of ``require_auth``; forgetting either dependency
    is what fails CI."""
    return None


def require_auth(*args, **kwargs):
    """Placeholder so tests can import and inspect the name. Real
    binding happens via ``build_require_auth`` at startup. Direct
    invocation without binding is a programming error."""
    raise RuntimeError(
        "require_auth must be built via build_require_auth(master_token=..., "
        "sessions=...) at startup. A bare call means the app wiring skipped "
        "the security initialiser."
    )


_session_manager = SessionManager()


def get_session_manager() -> SessionManager:
    """The SessionManager production code uses.

    A cookie is only valid in the manager that minted it. A second
    instance in production would mint cookies no route recognises, so
    login succeeds and every cookie-protected route still answers 401.
    Tests construct their own managers deliberately.
    """
    return _session_manager
