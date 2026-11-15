"""Account credentials: password and TOTP for the accounts behind a profile.

FoxProfile itself only stores browser environments; the passwords and 2FA
seeds live in a separate JSON file owned by whoever runs this box. This router
reads that file (path from FOXPROFILE_CREDS_FILE) so the panel can show the
login details next to the profile instead of the operator hunting through it.

Read-only by design: editing credentials here would make this a password
vault, which is a different product with a different threat model.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import time

from fastapi import APIRouter, HTTPException

from ...core.config import CREDS_FILE
from ...core.logging import get_logger

logger = get_logger("api.credentials")

router = APIRouter(prefix="/credentials", tags=["credentials"])

_TOTP_STEP = 30
_TOTP_DIGITS = 6


def _totp(secret: str, at: float | None = None) -> dict:
    """Current RFC 6238 code for a base32 seed (SHA-1, 6 digits, 30s)."""
    raw = secret.strip().replace(" ", "").upper()
    raw += "=" * (-len(raw) % 8)
    try:
        key = base64.b32decode(raw, casefold=True)
    except Exception as e:
        raise ValueError(f"2FA 密钥不是合法的 base32: {e}") from e
    counter = int((at if at is not None else time.time()) // _TOTP_STEP)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF)
    code %= 10 ** _TOTP_DIGITS
    left = _TOTP_STEP - int(time.time() % _TOTP_STEP)
    return {"code": str(code).zfill(_TOTP_DIGITS), "seconds_left": left}


def _load() -> dict:
    if not CREDS_FILE:
        raise HTTPException(
            status_code=404,
            detail="没有配置凭据文件（启动时设置 FOXPROFILE_CREDS_FILE 指向账号 JSON）。",
        )
    try:
        with open(CREDS_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"凭据文件不存在：{CREDS_FILE}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"凭据文件读不了：{e}")
    if isinstance(data, dict) and isinstance(data.get("accounts"), (dict, list)):
        data = data["accounts"]
    if isinstance(data, list):
        data = {a.get("email", ""): a for a in data if a.get("email")}
    return data


def _entry(name: str) -> dict:
    for key, value in _load().items():
        if key.lower() == name.lower():
            return value if isinstance(value, dict) else {}
    raise HTTPException(status_code=404, detail=f"凭据文件里没有这个号：{name}")


@router.get("/{name}")
def credentials(name: str) -> dict:
    """Password and 2FA for one account. Values are never logged."""
    e = _entry(name)
    secret = e.get("secret") or ""
    totp: dict | None = None
    if secret:
        try:
            totp = _totp(secret)
        except ValueError as err:
            totp = {"error": str(err), "code": "", "seconds_left": 0}
    return {
        "email": name,
        "password": e.get("password") or "",
        "password_note": e.get("password_note") or "",
        "totp_secret": secret,
        "totp_secret_old": e.get("old_secret") or "",
        "totp": totp,
        "totp_updated_at": e.get("totp_updated_at") or "",
        "recovery": e.get("recovery") or "",
        "recovery_code": e.get("recovery_code") or "",
        "rec_state": e.get("recState") or "",
        "notes": e.get("notes") or "",
        "device": e.get("device") or "",
        "bought_at": e.get("boughtAt") or "",
        "period": _TOTP_STEP,
    }
