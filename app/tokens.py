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
      "del": "<parent token>",  # optional: parent token delegated from
      "ext": {...}              # optional arbitrary JSON claims
    }

A delegated token carries the *full* parent token string in its signed
``del`` claim, so the whole delegation chain is self-contained: verifying
one token means walking ``del`` links back to the root. Every layer is
checked independently (signature, expiry, subject revocation, one-time
nonce) and each child must stay inside its parent's constraints (same
method, a path underneath the parent's, no later expiry, same subject).
Chains deeper than :data:`MAX_DELEGATION_DEPTH` layers are rejected.

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

#: Maximum number of tokens in a delegation chain, the root issued token
#: being depth 1. A delegated child is depth 2; the 4th delegated hop
#: (depth 5) is refused. Keeps chain verification bounded.
MAX_DELEGATION_DEPTH = 4

#: Sentinel distinguishing "kid not supplied" (use the ring's active key)
#: from an explicit ``kid=None`` (mint a legacy kid-less token).
_UNSET: Any = object()


class TokenError(Exception):
    """Raised when a token fails verification.

    ``code`` is a stable machine-readable string returned by the HTTP API:

    malformed / bad_signature / bad_payload / unknown_key / expired /
    method_mismatch / path_mismatch / nonce_replayed / subject_revoked /
    chain_too_deep / delegation_denied
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


def path_is_within(child_path: str, parent_path: str) -> bool:
    """Return True when *child_path* is *parent_path* itself or a sub-path.

    Both arguments must already be canonical (see :func:`canonical_path`):
    the root is ``"/"`` and no other canonical path ends with ``/``. The
    check is segment based, so ``/files-evil`` is *not* contained by
    ``/files`` — a plain ``str.startswith`` would accept it.
    """
    if parent_path == "/":
        return True
    return child_path == parent_path or child_path.startswith(parent_path + "/")


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
    delegated_from: str | None = None,
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
    if delegated_from is not None:
        payload["del"] = str(delegated_from)
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
    delegated_from: str | None = None,
    extra: dict[str, Any] | None = None,
    now: int | None = None,
    nonce: str | None = None,
) -> IssuedToken:
    """Sign a new token with the key ring's active (first) key.

    By default the ring's active ``kid`` is written into the protected
    payload. Pass ``kid=None`` explicitly to mint a legacy kid-less token
    (e.g. in migration tooling or tests). ``delegated_from`` embeds the
    parent token string in the signed ``del`` claim; the delegation
    constraints themselves are enforced by :func:`delegate_token`.
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
        delegated_from=delegated_from,
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
    #: Number of tokens in the delegation chain (a directly issued token is
    #: depth 1; its first delegation is depth 2, and so on).
    chain_depth: int = 1


@dataclass
class _Layer:
    """One verified token while walking a delegation chain (depth 1 = root)."""

    token: str
    payload: dict[str, Any]
    method: str
    path: str
    issued_at: int
    expires_at: int
    nonce: str
    one_time: bool
    subject: str | None
    kid: str | None
    depth: int


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


def _authenticate_layer(token: str, keyring: Keyring, now: int) -> _Layer:
    """Statelessly verify one token: structure, key, MAC, claims, expiry.

    This is the part applied independently to *every* token in a delegation
    chain. Stateful checks (revocation, one-time nonces) happen once for the
    whole chain in :meth:`Database.check_chain_revocation_and_consume_nonces`.
    """
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
    if not isinstance(payload.get("ext", {}), dict):
        raise TokenError("bad_payload", "claim 'ext' must be a JSON object")
    delegated = payload.get("del")
    if delegated is not None and (not isinstance(delegated, str) or not delegated):
        raise TokenError("bad_payload", "claim 'del' must be a non-empty string")

    if now >= expires_at:
        raise TokenError("expired", "token has expired")

    return _Layer(
        token=token,
        payload=payload,
        method=token_method,
        path=token_path,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        one_time=one_time,
        subject=subject,
        kid=kid,
        depth=0,
    )


def _check_child_within_parent(child: _Layer, parent: _Layer) -> None:
    """Re-derive the delegation constraints from the signed layers.

    Issuing-time checks are not trusted: verification proves from the two
    signed payloads alone that the child never escapes the parent's method,
    path segment, expiry window or subject.
    """
    where = f"delegated token at depth {child.depth}"
    if child.method != parent.method:
        raise TokenError(
            "delegation_denied",
            f"{where} binds {child.method}, its parent only grants {parent.method}",
        )
    if not path_is_within(child.path, parent.path):
        raise TokenError(
            "delegation_denied",
            f"{where} targets {child.path!r}, outside its parent path {parent.path!r}",
        )
    if child.expires_at > parent.expires_at:
        raise TokenError(
            "delegation_denied",
            f"{where} outlives its parent (child exp {child.expires_at} > parent exp "
            f"{parent.expires_at})",
        )
    if child.subject != parent.subject:
        raise TokenError(
            "delegation_denied",
            f"{where} subject {child.subject!r} differs from parent subject "
            f"{parent.subject!r}",
        )
    if not parent.issued_at <= child.issued_at <= parent.expires_at:
        raise TokenError(
            "delegation_denied",
            f"{where} was not issued while its parent was valid",
        )


def _walk_chain(leaf_token: str, keyring: Keyring, now: int) -> list[_Layer]:
    """Authenticate the leaf and every ancestor linked via ``del``.

    Returns the layers leaf-first (index 0 is the presented token, the last
    entry is the originally issued root). Each layer's own signature, key
    and expiry are verified, the chain must not exceed
    :data:`MAX_DELEGATION_DEPTH` tokens, and every child/parent pair is
    re-checked for the delegation constraints.
    """
    layers: list[_Layer] = []
    seen: set[str] = set()
    current = leaf_token
    while True:
        hop = len(layers) + 1
        try:
            layer = _authenticate_layer(current, keyring, now)
        except TokenError as exc:
            if hop == 1:
                raise
            # Keep the machine-readable code/HTTP status; say which ancestor failed.
            raise TokenError(
                exc.code, f"delegated parent at hop {hop}: {exc.message}"
            ) from None
        layers.append(layer)

        parent_token = layer.payload.get("del")
        if parent_token is None:
            break
        if parent_token == current or parent_token in seen or parent_token == leaf_token:
            raise TokenError("bad_payload", "delegation chain contains a cycle")
        seen.add(current)
        current = parent_token

    total = len(layers)
    if total > MAX_DELEGATION_DEPTH:
        raise TokenError(
            "chain_too_deep",
            f"delegation chain is {total} tokens deep; maximum is {MAX_DELEGATION_DEPTH}",
        )

    # Leaf first, root last: assign depth from the root (root = depth 1).
    for index, layer in enumerate(layers):
        layer.depth = total - index

    for child, parent in zip(layers, layers[1:]):
        _check_child_within_parent(child, parent)

    return layers


def _chain_stateful_check(layers: list[_Layer], db: Database, *, consume: bool) -> None:
    """Run revocation + nonce logic for every layer in ONE SQLite transaction."""
    entries = [
        {
            "subject": layer.subject,
            "issued_at": layer.issued_at,
            "nonce": layer.nonce,
            "expires_at": layer.expires_at,
            "one_time": layer.one_time,
        }
        for layer in layers
    ]
    outcome = db.check_chain_revocation_and_consume_nonces(entries, consume=consume)
    if outcome == "subject_revoked":
        revoked_subject = next(
            (layer.subject for layer in layers if layer.subject is not None), None
        )
        raise TokenError(
            "subject_revoked",
            f"subject {revoked_subject!r} is revoked for a token in the delegation chain",
        )
    if outcome == "nonce_replayed":
        raise TokenError(
            "nonce_replayed", "a one-time token in the delegation chain has already been used"
        )


def inspect_chain(
    token: str,
    *,
    keyring: Keyring,
    db: Database,
    now: int | None = None,
) -> VerifiedToken:
    """Verify a token and its whole chain without binding it to a request.

    Used when minting a delegation: the parent must itself be valid (every
    ancestor signature, expiry, revocation and one-time nonce passes), but
    there is no HTTP method/path to bind it to. Nonces are never consumed,
    so presenting a parent for delegation does not burn it.
    """
    now = int(time.time()) if now is None else now
    layers = _walk_chain(token, keyring, now)
    _chain_stateful_check(layers, db, consume=False)
    leaf = layers[0]
    return VerifiedToken(
        payload=leaf.payload,
        method=leaf.method,
        path=leaf.path,
        expires_at=leaf.expires_at,
        nonce=leaf.nonce,
        one_time=leaf.one_time,
        subject=leaf.subject,
        extra=leaf.payload.get("ext", {}),
        kid=leaf.kid,
        chain_depth=len(layers),
    )


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
    """Verify a capability token (and its delegation chain) for method+path.

    Verification order:

    1. structure (parse / base64 / JSON) for the leaf and every ancestor in
       its signed ``del`` chain,
    2. key selection per layer: the signed ``kid`` claim selects exactly one
       ring key; tokens without ``kid`` may only use the legacy secret. The
       ring is never probed (``unknown_key`` otherwise),
    3. HMAC signature of every layer (constant-time compare),
    4. payload claim types and version of every layer,
    5. expiry of every layer — an expired/revoked parent invalidates the
       whole chain,
    6. delegation containment for each child/parent pair: same method, path
       inside the parent's, no later expiry, same subject,
    7. chain length limit (:data:`MAX_DELEGATION_DEPTH`),
    8. method and path binding of the presented (leaf) token,
    9. subject revocation for *every* layer + one-time nonce consumption for
       *every* one-time layer, all decided inside a single SQLite
       transaction. A revoked ancestor rejects the leaf without burning any
       nonce; a burned ancestor nonce rejects the whole chain — a one-time
       token can never be widened into reusable delegated children.

    ``consume=False`` performs a stateless dry run: nonces are not burned
    (useful for ``HEAD`` preflights and for delegation issuance), but
    revocation and replay state are still enforced.
    """
    now = int(time.time()) if now is None else now
    layers = _walk_chain(token, keyring, now)
    leaf = layers[0]

    request_method = canonical_method(method)
    request_path = canonical_path(path)
    if leaf.method != request_method:
        raise TokenError(
            "method_mismatch",
            f"token is bound to {leaf.method}, request used {request_method}",
        )
    if leaf.path != request_path:
        raise TokenError(
            "path_mismatch",
            f"token is bound to {leaf.path!r}, request path was {request_path!r}",
        )

    _chain_stateful_check(layers, db, consume=consume)

    return VerifiedToken(
        payload=leaf.payload,
        method=leaf.method,
        path=leaf.path,
        expires_at=leaf.expires_at,
        nonce=leaf.nonce,
        one_time=leaf.one_time,
        subject=leaf.subject,
        extra=leaf.payload.get("ext", {}),
        kid=leaf.kid,
        chain_depth=len(layers),
    )


@dataclass
class DelegatedToken:
    issued: IssuedToken
    chain_depth: int
    parent_nonce: str
    parent_expires_at: int


def delegate_token(
    parent_token: str,
    *,
    keyring: Keyring,
    db: Database,
    method: str,
    path: str,
    ttl_seconds: int,
    subject: str | None = None,
    now: int | None = None,
) -> DelegatedToken:
    """Mint a child capability that stays inside its parent's constraints.

    The parent (with its full delegation chain) is verified first via
    :func:`inspect_chain` — without consuming nonces. The child is then
    narrowed on every axis:

    * **method**: must equal the parent's method exactly;
    * **path**: must equal or sit segment-wise underneath the parent's path;
    * **expiry**: ``min(requested ttl, parent remaining lifetime)`` — a child
      can never outlive its parent;
    * **subject**: must equal the parent subject; a subject may not be
      introduced or changed by delegation (omit it to inherit);
    * **one-time**: inherited from the parent — a one-time token can never
      be widened into a reusable child.

    The complete parent token string is embedded in the child's signed
    ``del`` claim, which is what recursive verification walks later.
    """
    now = int(time.time()) if now is None else now
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")

    parent = inspect_chain(parent_token, keyring=keyring, db=db, now=now)

    if parent.chain_depth >= MAX_DELEGATION_DEPTH:
        raise TokenError(
            "chain_too_deep",
            f"parent token is already at delegation depth {parent.chain_depth}; "
            f"the limit is {MAX_DELEGATION_DEPTH}",
        )

    child_method = canonical_method(method)
    child_path = canonical_path(path)
    if child_method != parent.method:
        raise TokenError(
            "method_mismatch",
            f"parent grants {parent.method}, cannot delegate {child_method}",
        )
    if not path_is_within(child_path, parent.path):
        raise TokenError(
            "path_mismatch",
            f"parent path {parent.path!r} does not cover requested path {child_path!r}",
        )
    if subject is not None and subject != parent.subject:
        raise TokenError(
            "delegation_denied",
            f"parent subject is {parent.subject!r}, cannot delegate to {subject!r}",
        )

    child_expires_at = min(now + int(ttl_seconds), parent.expires_at)
    effective_ttl = child_expires_at - now
    if effective_ttl <= 0:
        raise TokenError("expired", "parent token has no remaining lifetime to delegate")

    issued = issue_token(
        keyring,
        method=child_method,
        path=child_path,
        ttl_seconds=effective_ttl,
        one_time=parent.one_time,
        subject=parent.subject,
        delegated_from=parent_token,
        now=now,
    )
    return DelegatedToken(
        issued=issued,
        chain_depth=parent.chain_depth + 1,
        parent_nonce=parent.nonce,
        parent_expires_at=parent.expires_at,
    )
