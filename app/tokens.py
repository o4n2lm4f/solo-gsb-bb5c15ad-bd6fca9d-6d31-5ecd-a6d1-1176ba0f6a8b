"""Capability token issuing and verification (HMAC-SHA256).

Token wire format (URL-safe, no padding)::

    <base64url(payload)>.<base64url(hmac_sha256(payload, secret))>

``payload`` is a compact JSON object with sorted keys::

    {
      "v":   1,                 # token version
      "kid": "2026-09",         # signing key id, selected on verify (exact)
      "m":   "GET",             # bound HTTP method (canonical, upper case)
      "p":   "/files/report",   # bound canonical path
      "iat": 1727000000,        # issued-at, unix seconds
      "exp": 1727000300,        # expiry, unix seconds
      "jti": "u0m...",          # unique token id (also the replay nonce)
      "one": true,              # one-time use?
      "sub": "alice",           # optional subject / caller identity
      "ext": {...}              # optional arbitrary JSON claims
    }

The signature covers the method and path as part of the payload, so a token
cannot be moved to another endpoint or verb without breaking the MAC. The
``kid`` claim sits inside the signed payload as well: it selects *exactly
one* verification key, so rotating the ring never requires trying every
key. Tokens without ``kid`` (issued before key-ring support) can only be
verified against the explicitly configured legacy secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import posixpath
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from .config import Keyring
from .db import Database

TOKEN_VERSION = 1
_ALGORITHM = "sha256"
SEP_RUN_RE = re.compile(r"/+")

#: Sentinel distinguishing "kid not supplied" (use the ring's active key)
#: from an explicit ``kid=None`` (mint a legacy kid-less token).
_UNSET: Any = object()


class TokenError(Exception):
    """Raised when a token fails verification.

    ``code`` is a stable machine-readable string returned by the HTTP API:

    malformed / bad_signature / bad_payload / unknown_key / expired /
    method_mismatch / path_mismatch / nonce_replayed / subject_revoked
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def canonical_path(path: str) -> str:
    """Canonicalise a URL *path* for signing / verification.

    The input is expected to be the percent-decoded path (FastAPI's
    ``request.url.path``). We:

    * collapse repeated slashes (including leading ``//``),
    * resolve ``.`` / ``..`` segments,
    * drop any trailing slash (except the root).

    Issuer and verifier therefore agree on one unambiguous string even for
    inputs such as ``//files/../files/x/``.
    """
    if not path:
        return "/"
    # posixpath.normpath deliberately preserves a leading '//'; collapse it
    # (and any other duplicate slashes) ourselves first.
    collapsed = SEP_RUN_RE.sub("/", path)
    normalised = posixpath.normpath(collapsed)
    if normalised != "/" and normalised.endswith("/"):
        normalised = normalised.rstrip("/") or "/"
    return normalised


def canonical_method(method: str) -> str:
    return method.strip().upper()


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as exc:
        raise TokenError("malformed", "token segment is not valid base64url") from exc


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def build_payload(
    *,
    method: str,
    path: str,
    expires_at: int,
    issued_at: int,
    nonce: str,
    one_time: bool,
    kid: str | None = None,
    subject: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"v": TOKEN_VERSION}
    # Only tokens signed by a named ring key carry a kid; passing None keeps
    # the wire format of legacy kid-less tokens reproducible.
    if kid is not None:
        payload["kid"] = str(kid)
    payload.update(
        {
            "m": canonical_method(method),
            "p": canonical_path(path),
            "iat": int(issued_at),
            "exp": int(expires_at),
            "jti": nonce,
            "one": bool(one_time),
        }
    )
    if subject is not None:
        payload["sub"] = str(subject)
    if extra:
        payload["ext"] = extra
    return payload


def _payload_to_bytes(payload: dict[str, Any]) -> bytes:
    # sort_keys makes the canonical encoding stable for everyone.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


@dataclass
class IssuedToken:
    token: str
    payload: dict[str, Any]
    method: str
    path: str
    expires_at: int
    expires_in: int
    one_time: bool
    nonce: str
    kid: str | None = None


def issue_token(
    keyring: Keyring,
    *,
    method: str,
    path: str,
    ttl_seconds: int,
    one_time: bool = False,
    kid: str | None | object = _UNSET,
    subject: str | None = None,
    extra: dict[str, Any] | None = None,
    now: int | None = None,
    nonce: str | None = None,
) -> IssuedToken:
    """Sign a new token with the key ring's active (first) key.

    By default the ring's active ``kid`` is written into the protected
    payload. Pass ``kid=None`` explicitly to mint a legacy kid-less token
    (e.g. in migration tooling or tests).
    """
    now = int(time.time()) if now is None else now
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    method = canonical_method(method)
    path = canonical_path(path)
    nonce = nonce or new_nonce()
    expires_at = now + int(ttl_seconds)
    if kid is _UNSET:
        kid = keyring.active_kid
        secret_key = keyring.active_secret
    elif kid is None:
        secret_key = keyring.active_secret
    else:
        secret_key = keyring.get_secret(str(kid))
        if secret_key is None:  # issuing must always use a configured key
            raise ValueError(f"unknown signing kid {kid!r}")
        kid = str(kid)
    payload = build_payload(
        method=method,
        path=path,
        expires_at=expires_at,
        issued_at=now,
        nonce=nonce,
        one_time=one_time,
        kid=kid,
        subject=subject,
        extra=extra,
    )
    payload_b = _payload_to_bytes(payload)
    signature = hmac.new(secret_key, payload_b, hashlib.sha256).digest()
    token = f"{_b64url_encode(payload_b)}.{_b64url_encode(signature)}"
    return IssuedToken(
        token=token,
        payload=payload,
        method=method,
        path=path,
        expires_at=expires_at,
        expires_in=ttl_seconds,
        one_time=one_time,
        nonce=nonce,
        kid=kid,
    )


@dataclass
class VerifiedToken:
    payload: dict[str, Any]
    method: str
    path: str
    expires_at: int
    nonce: str
    one_time: bool
    subject: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    kid: str | None = None


def parse_token(token: str) -> tuple[dict[str, Any], bytes, bytes]:
    """Split and decode an unverified token into (payload, payload_b, sig).

    ``payload_b`` are the exact canonical JSON bytes that were signed.
    """
    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenError("malformed", "token must be '<payload>.<signature>'")
    payload_part, signature_part = token.split(".", 1)
    if not payload_part or not signature_part:
        raise TokenError("malformed", "token has an empty segment")
    payload_b = _b64url_decode(payload_part)
    signature = _b64url_decode(signature_part)
    try:
        payload = json.loads(payload_b.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TokenError("malformed", "token payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise TokenError("malformed", "token payload must be a JSON object")
    return payload, payload_b, signature


def _require_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise TokenError("bad_payload", f"claim {key!r} must be a non-empty string")
    return value


def _require_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TokenError("bad_payload", f"claim {key!r} must be an integer")
    return value


def _select_verification_key(
    payload: dict[str, Any], keyring: Keyring
) -> tuple[bytes, str | None]:
    """Pick exactly one verification key for a parsed (untrusted) payload.

    A payload with a ``kid`` claim is verified against that one key only —
    the ring is never walked trying each secret. Tokens without ``kid`` can
    only be checked against the configured legacy secret. Both unknown
    cases fail with ``unknown_key``.
    """
    if "kid" in payload:
        kid = payload["kid"]
        if not isinstance(kid, str) or not kid:
            raise TokenError("bad_payload", "claim 'kid' must be a non-empty string")
        secret = keyring.get_secret(kid)
        if secret is None:
            raise TokenError(
                "unknown_key", f"unknown signing key id {kid!r} (key removed from ring?)"
            )
        return secret, kid

    # Legacy kid-less token: the explicit legacy secret is the only option.
    if keyring.legacy_secret is None:
        raise TokenError(
            "unknown_key",
            "token has no 'kid' claim and no CAPABILITY_LEGACY_SECRET is configured",
        )
    return keyring.legacy_secret, None


def verify_token(
    token: str,
    *,
    keyring: Keyring,
    method: str,
    path: str,
    db: Database,
    consume: bool = True,
    now: int | None = None,
) -> VerifiedToken:
    """Verify a capability token for *method* + *path*.

    Verification order:

    1. structure (parse / base64 / JSON),
    2. key selection: the signed ``kid`` claim selects exactly one ring key;
       tokens without ``kid`` may only use the legacy secret. There is no
       fallback and the ring is never probed (``unknown_key`` otherwise),
    3. HMAC signature with the selected key (constant-time compare),
    4. payload claim types and version,
    5. expiry,
    6. method binding,
    7. path binding,
    8. subject revocation + one-time nonce consumption, decided inside a
       single SQLite transaction: a token whose ``iat`` is not after the
       subject's revocation cutoff is rejected with ``subject_revoked``
       and its nonce is *not* burned.

    ``consume=False`` performs a stateless dry run: a valid one-time token
    is *not* burned, which is useful for HTTP ``HEAD`` preflights. The
    revocation check still applies — a revoked subject fails even a dry run.
    """
    now = int(time.time()) if now is None else now
    payload, payload_b, signature = parse_token(token)

    secret_key, kid = _select_verification_key(payload, keyring)

    expected = hmac.new(secret_key, payload_b, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise TokenError("bad_signature", "token signature does not match")

    if payload.get("v") != TOKEN_VERSION:
        raise TokenError("bad_payload", f"unsupported token version: {payload.get('v')!r}")
    token_method = _require_str(payload, "m")
    token_path = _require_str(payload, "p")
    issued_at = _require_int(payload, "iat")
    expires_at = _require_int(payload, "exp")
    nonce = _require_str(payload, "jti")
    one_time = payload.get("one")
    if not isinstance(one_time, bool):
        raise TokenError("bad_payload", "claim 'one' must be a boolean")
    if issued_at > expires_at:
        raise TokenError("bad_payload", "claim 'iat' must not be after 'exp'")

    subject = payload.get("sub")
    if subject is not None and not isinstance(subject, str):
        raise TokenError("bad_payload", "claim 'sub' must be a string")
    extra = payload.get("ext", {})
    if not isinstance(extra, dict):
        raise TokenError("bad_payload", "claim 'ext' must be a JSON object")

    if now >= expires_at:
        raise TokenError("expired", "token has expired")

    if token_method != canonical_method(method):
        raise TokenError(
            "method_mismatch",
            f"token is bound to {token_method}, request used {canonical_method(method)}",
        )

    if token_path != canonical_path(path):
        raise TokenError(
            "path_mismatch",
            f"token is bound to {token_path!r}, request path was {canonical_path(path)!r}",
        )

    outcome = db.check_revocation_and_consume_nonce(
        subject=subject,
        issued_at=issued_at,
        nonce=nonce,
        expires_at=expires_at,
        consume=one_time and consume,
    )
    if outcome == "subject_revoked":
        raise TokenError(
            "subject_revoked",
            f"subject {subject!r} is revoked for tokens issued at or before the cutoff",
        )
    if outcome == "nonce_replayed":
        raise TokenError("nonce_replayed", "one-time token has already been used")

    return VerifiedToken(
        payload=payload,
        method=token_method,
        path=token_path,
        expires_at=expires_at,
        nonce=nonce,
        one_time=one_time,
        subject=subject,
        extra=extra,
        kid=kid,
    )
