"""Mailbox routes: proxy the local gmail_server so the panel can read mail.

Mail lives outside this process: `gmail_server.py` owns the three delivery
paths (phone Gmail API token, an account's own browser profile, the shared
.gprof browser). This router forwards to it over loopback so the panel needs
no second origin, and keeps the last good answer per account so a transient
upstream failure still shows something instead of an empty modal.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

from fastapi import APIRouter, HTTPException, Query

from ...core.config import MAIL_TIMEOUT, MAIL_URL
from ...core.logging import get_logger

logger = get_logger("api.mail")

router = APIRouter(prefix="/mail", tags=["mail"])

# Per-account lock: a second click while a browser-backed read is still running
# must wait, not start a competing read on the same data dir.
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()

# email -> (saved_at, payload) of the last successful inbox read.
_last_good: dict[str, tuple[float, dict]] = {}
_LAST_GOOD_TTL = 1800


_chan_cache: tuple[float, dict] | None = None
_chan_guard = threading.Lock()
_CHAN_TTL = 30


def _channels() -> dict:
    """email -> how mail can be read, or [] when no path exists.

    Asking first turns a 5-second doomed read into an immediate, explainable
    answer. Both upstream calls are cheap (cached server-side).
    """
    global _chan_cache
    with _chan_guard:
        if _chan_cache and time.time() - _chan_cache[0] < _CHAN_TTL:
            return _chan_cache[1]
    out: dict[str, list[str]] = {}
    try:
        with urllib.request.urlopen(MAIL_URL + "/pool/status", timeout=30) as resp:
            for p in json.loads(resp.read()).get("profiles", []):
                modes = []
                if p.get("has_profile"):
                    modes.append("浏览器 profile")
                if p.get("gprof") is not None:
                    modes.append("共用托管浏览器")
                out[p["email"].lower()] = modes
    except Exception as e:
        logger.warning("mail channel check failed (browser hosts): %s", e)
        return {}
    try:
        req = urllib.request.Request(
            MAIL_URL + "/accounts", b"{}", headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            for a in json.loads(resp.read()).get("accounts", []):
                out.setdefault(a["email"].lower(), []).append("手机 token")
    except Exception as e:
        logger.warning("mail channel check failed (phone tokens): %s", e)
    with _chan_guard:
        _chan_cache = (time.time(), out)
    return out


def _require_channel(email: str) -> None:
    modes = _channels().get(email.lower())
    if modes is None:
        return  # unknown account: let the upstream decide
    if not modes:
        raise HTTPException(
            status_code=409,
            detail=(
                "这个号没有可用的读信通道：既没有浏览器托管，手机账号库里也没有它的 token。"
                "先在浏览器里登录它（或把它加进共用托管浏览器）再读信。"
            ),
        )


def _lock_for(email: str) -> threading.Lock:
    key = email.lower()
    with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = _locks[key] = threading.Lock()
        return lock


def _post(path: str, body: dict) -> dict:
    """POST to the mail service; one retry on a connection-level failure."""
    data = json.dumps(body).encode()
    last: Exception | None = None
    for attempt in range(2):
        req = urllib.request.Request(
            MAIL_URL + path,
            data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=MAIL_TIMEOUT) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:400]
            raise HTTPException(status_code=502, detail=f"mail service: {detail}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            # Down or still waking up: worth one more try before giving up.
            last = e
            if attempt == 0:
                time.sleep(1)
    raise HTTPException(
        status_code=503,
        detail=f"mail service unreachable at {MAIL_URL}: {last}",
    )


# Upstream raises bare Python exceptions whose text is not written for a person
# looking at a modal; map the cases we can act on and pass the rest through.
_HINTS = (
    (
        ("没有这个号的托管", "手机上没有这个号"),
        "这个号没有可用的读信通道：既没有浏览器托管，手机账号库里也没有它的 token。",
    ),
    (
        ("We couldn't verify it's you", "signin/rejected"),
        "Google 风控拦住了这个号的登录，需要人工在浏览器里过验证。",
    ),
    (
        ("登录页", "ChallengeError"),
        "托管浏览器里的登录态失效了，需要重新登录这个号。",
    ),
    (
        ("共用托管浏览器没开",),
        "共用托管浏览器没运行，启动它之后再试。",
    ),
)


def _friendly(detail: str) -> str:
    """Drop the Python exception prefix; keep only the hint when we have one."""
    text = detail
    for prefix in ("RuntimeError: ", "TypeError: ", "ValueError: "):
        if text.startswith(prefix):
            text = text[len(prefix):]
    for needles, hint in _HINTS:
        if any(n in text for n in needles):
            return hint
    return text


def _fail(detail: str) -> HTTPException:
    return HTTPException(status_code=502, detail=_friendly(detail))


@router.get("/status")
def mail_status() -> dict:
    """Which accounts can currently read mail, and how."""
    try:
        with urllib.request.urlopen(MAIL_URL + "/pool/status", timeout=30) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        return {"ok": False, "reachable": False, "error": str(e), "profiles": []}
    return {"ok": True, "reachable": True, **data}


@router.get("/{name}/inbox")
def mail_inbox(
    name: str,
    limit: int = Query(25, ge=1, le=100),
    force: bool = False,
) -> dict:
    _require_channel(name)
    with _lock_for(name):
        payload = _post("/pool/inbox", {"email": name, "limit": limit, "force": force})
        if payload.get("ok"):
            _last_good[name.lower()] = (time.time(), payload)
            return payload
        cached = _last_good.get(name.lower())
        if cached and time.time() - cached[0] < _LAST_GOOD_TTL:
            saved_at, old = cached
            return {
                **old,
                "stale": True,
                "stale_at": int(saved_at),
                "error": payload.get("error") or "读取失败",
            }
        raise _fail(payload.get("error") or "读取失败")


@router.get("/{name}/message/{mid}")
def mail_message(
    name: str,
    mid: str,
    msg_id: str = "",
    thread_id: str = "",
) -> dict:
    with _lock_for(name):
        payload = _post(
            "/message",
            {"email": name, "id": mid, "msg_id": msg_id, "thread_id": thread_id},
        )
    if not payload.get("ok"):
        raise _fail(payload.get("error") or "读取失败")
    return payload
