"""FastAPI application: issue and verify short-lived HMAC capability tokens.

Run locally::

    uvicorn app.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, JSONResponse

from .config import Settings, load_settings
from .db import Database
from .schemas import (
    IssuedTokenResponse,
    IssueTokenRequest,
    RevocationEntry,
    RevocationListResponse,
    RevokeSubjectRequest,
    RevokeSubjectResponse,
    VerifyTokenRequest,
    VerifyTokenResponse,
)
from .tokens import (
    TokenError,
    canonical_method,
    canonical_path,
    issue_token,
    verify_token,
)

logger = logging.getLogger("capability_api")

#: TokenError code -> HTTP status.
_ERROR_STATUS = {
    "malformed": status.HTTP_401_UNAUTHORIZED,
    "bad_signature": status.HTTP_401_UNAUTHORIZED,
    "bad_payload": status.HTTP_401_UNAUTHORIZED,
    "unknown_key": status.HTTP_401_UNAUTHORIZED,
    "expired": status.HTTP_401_UNAUTHORIZED,
    "nonce_replayed": status.HTTP_401_UNAUTHORIZED,
    "subject_revoked": status.HTTP_401_UNAUTHORIZED,
    "method_mismatch": status.HTTP_403_FORBIDDEN,
    "path_mismatch": status.HTTP_403_FORBIDDEN,
}

#: Delete expired consumed nonces and stale revocations periodically.
_PURGE_INTERVAL_SECONDS = 10 * 60


def _http_error(exc: TokenError) -> HTTPException:
    """Translate a TokenError into an HTTPException with a stable JSON body.

    ``http_exception_handler`` (registered after app creation) flattens
    ``detail`` so clients always receive
    ``{"error": <code>, "detail": <message>}``.
    """
    http_status = _ERROR_STATUS.get(exc.code, status.HTTP_400_BAD_REQUEST)
    return HTTPException(
        status_code=http_status,
        detail={"error": exc.code, "detail": exc.message},
        headers={"WWW-Authenticate": "CapabilityToken"},
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail
    if isinstance(detail, dict) and "error" in detail:
        return JSONResponse(status_code=exc.status_code, content=detail, headers=exc.headers)
    if isinstance(detail, list):  # RequestValidationError payload
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "validation_error", "detail": detail},
            headers=exc.headers,
        )
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": "http_error", "detail": str(detail)},
        headers=exc.headers,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> None:
    settings = load_settings()
    db = Database(settings.db_path)
    os.makedirs(settings.files_dir, exist_ok=True)

    removed_nonces, removed_revocations = db.purge_expired(max_token_ttl=settings.max_ttl)
    if removed_nonces or removed_revocations:
        logger.info(
            "Purged %d expired nonce rows and %d stale revocation rows at startup",
            removed_nonces,
            removed_revocations,
        )

    if settings.ephemeral:
        logger.warning(
            "Neither CAPABILITY_KEYRING nor CAPABILITY_SECRET is set: generated an "
            "ephemeral signing key (kid=%s). Tokens will not survive a restart. "
            "Configure CAPABILITY_KEYRING in production.",
            settings.keyring.active_kid,
        )
    else:
        logger.info(
            "Capability key ring ready: active kid=%s, %d verification key(s)%s",
            settings.keyring.active_kid,
            len(settings.keyring),
            ", legacy kid-less tokens accepted" if settings.keyring.legacy_secret else "",
        )

    app.state.settings = settings
    app.state.db = db

    async def purge_loop() -> None:
        while True:
            await asyncio.sleep(_PURGE_INTERVAL_SECONDS)
            try:
                db.purge_expired(max_token_ttl=settings.max_ttl)
            except Exception:  # noqa: BLE001 - background housekeeping must never crash
                logger.exception("Periodic nonce/revocation purge failed")

    purge_task = asyncio.create_task(purge_loop())
    try:
        yield
    finally:
        purge_task.cancel()
        try:
            await purge_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Capability Token API",
    version="1.2.0",
    description=(
        "Issue short-lived HMAC-signed capability tokens for HTTP operations "
        "(e.g. file downloads) and verify method/path binding, expiry, "
        "signature, one-time nonces and subject-level revocation."
    ),
    lifespan=lifespan,
)
app.add_exception_handler(HTTPException, http_exception_handler)


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Database:
    return request.app.state.db


SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[Database, Depends(get_db)]


def require_issuer_key(
    settings: SettingsDep,
    x_issuer_key: Annotated[str | None, Header(alias="X-Issuer-Key")] = None,
) -> None:
    """Gate token issuance behind an optional shared key."""
    if settings.issuer_key is not None:
        provided = x_issuer_key or ""
        if not hmac.compare_digest(provided.encode("utf-8"), settings.issuer_key.encode("utf-8")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "unauthorized", "detail": "invalid or missing X-Issuer-Key"},
            )


IssuerGuard = Depends(require_issuer_key)


def require_admin_key(
    settings: SettingsDep,
    x_admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None,
) -> None:
    """Gate revocation management behind a dedicated admin key.

    Fails closed: when CAPABILITY_ADMIN_KEY is not configured the admin
    endpoints are disabled (503) rather than left unauthenticated.
    """
    if settings.admin_key is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "admin_key_not_configured",
                "detail": "revocation management is disabled; set CAPABILITY_ADMIN_KEY",
            },
        )
    provided = x_admin_key or ""
    if not hmac.compare_digest(provided.encode("utf-8"), settings.admin_key.encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "detail": "invalid or missing X-Admin-Key"},
        )


AdminGuard = Depends(require_admin_key)


@app.get("/health", tags=["meta"])
def health(request: Request) -> dict[str, object]:
    db: Database = request.app.state.db
    with db.connect() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "time": int(time.time())}


@app.post(
    "/tokens/issue",
    response_model=IssuedTokenResponse,
    tags=["tokens"],
    dependencies=[IssuerGuard],
)
def issue(body: IssueTokenRequest, settings: SettingsDep) -> IssuedTokenResponse:
    ttl = body.ttl_seconds or settings.default_ttl
    ttl = min(ttl, settings.max_ttl)

    issued = issue_token(
        settings.keyring,
        method=body.method,
        path=body.path,
        ttl_seconds=ttl,
        one_time=body.one_time,
        subject=body.subject,
        extra=body.extra,
    )
    logger.info(
        "Issued token jti=%s kid=%s %s %s exp=%s one_time=%s sub=%s",
        issued.nonce,
        issued.kid,
        issued.method,
        issued.path,
        issued.expires_at,
        issued.one_time,
        issued.payload.get("sub"),
    )
    return IssuedTokenResponse(
        token=issued.token,
        token_id=issued.nonce,
        kid=issued.kid,
        method=issued.method,
        path=issued.path,
        issued_at=issued.payload["iat"],
        expires_at=issued.expires_at,
        expires_in=issued.expires_in,
        one_time=issued.one_time,
        subject=body.subject,
    )


@app.post("/tokens/verify", response_model=VerifyTokenResponse, tags=["tokens"])
def verify(body: VerifyTokenRequest, settings: SettingsDep, db: DbDep) -> VerifyTokenResponse:
    try:
        verified = verify_token(
            body.token,
            keyring=settings.keyring,
            method=canonical_method(body.method),
            path=canonical_path(body.path),
            db=db,
            consume=body.consume,
        )
    except TokenError as exc:
        raise _http_error(exc) from exc

    now = int(time.time())
    return VerifyTokenResponse(
        valid=True,
        kid=verified.kid,
        method=verified.method,
        path=verified.path,
        expires_at=verified.expires_at,
        expires_in=max(0, verified.expires_at - now),
        one_time=verified.one_time,
        consumed=verified.one_time and body.consume,
        token_id=verified.nonce,
        subject=verified.subject,
        extra=verified.extra,
    )


@app.post(
    "/tokens/revoke-subject",
    response_model=RevokeSubjectResponse,
    tags=["admin"],
    dependencies=[AdminGuard],
)
def revoke_subject(body: RevokeSubjectRequest, db: DbDep) -> RevokeSubjectResponse:
    """Revoke every token a subject was issued at or before a cutoff time.

    Verification compares the token's ``iat`` against the stored cutoff
    inside the same SQLite transaction that consumes one-time nonces, so a
    revoked token is rejected with ``401 subject_revoked`` without burning
    its nonce. Pass ``restore=true`` to lift the revocation.
    """
    if body.restore:
        removed = db.delete_subject_revocation(body.subject)
        if removed:
            logger.info("Subject restored sub=%s", body.subject)
        return RevokeSubjectResponse(subject=body.subject, revoked=False, restored=removed)

    cutoff = body.cutoff if body.cutoff is not None else int(time.time())
    entry = db.set_subject_revocation(body.subject, cutoff)
    logger.info("Subject revoked sub=%s cutoff=%s", body.subject, cutoff)
    return RevokeSubjectResponse(
        subject=entry["subject"],
        revoked=True,
        restored=False,
        cutoff=entry["cutoff"],
        created_at=entry["created_at"],
        updated_at=entry["updated_at"],
    )


@app.get(
    "/tokens/revocations",
    response_model=RevocationListResponse,
    tags=["admin"],
    dependencies=[AdminGuard],
)
def list_revocations(db: DbDep) -> RevocationListResponse:
    """List all persisted subject revocations (including not-yet-purged ones)."""
    entries = [RevocationEntry(**row) for row in db.list_subject_revocations()]
    return RevocationListResponse(revocations=entries, count=len(entries))


def _extract_token(
    request: Request,
    token: str | None,
    authorization: str | None,
    x_capability_token: str | None,
) -> str:
    if token:
        return token.strip()
    if x_capability_token:
        return x_capability_token.strip()
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.strip().lower() == "capability" or scheme.strip().lower() == "bearer":
            if value.strip():
                return value.strip()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "malformed",
            "detail": "missing token: provide ?token=, Authorization: Bearer <token> "
            "or X-Capability-Token",
        },
        headers={"WWW-Authenticate": "CapabilityToken"},
    )


@app.get("/files/{file_path:path}", include_in_schema=False)
def download_file(
    request: Request,
    file_path: str,
    settings: SettingsDep,
    db: DbDep,
    token: Annotated[str | None, Query(description="Capability token")] = None,
    authorization: Annotated[str | None, Header()] = None,
    x_capability_token: Annotated[str | None, Header(alias="X-Capability-Token")] = None,
):
    """Demonstration of a guarded HTTP operation: GET a file with a capability."""
    raw_token = _extract_token(request, token, authorization, x_capability_token)

    # The token is bound to the *canonical* request path, not the file name,
    # so e.g. //files/./x normalises identically on both sides.
    request_path = canonical_path(request.url.path)
    try:
        verified = verify_token(
            raw_token,
            keyring=settings.keyring,
            method=request.method,
            path=request_path,
            db=db,
            consume=True,
        )
    except TokenError as exc:
        raise _http_error(exc) from exc

    # Resolve inside files_dir and defeat traversal attempts outright.
    base_dir = Path(settings.files_dir).resolve(strict=False)
    target = (base_dir / file_path).resolve(strict=False)
    try:
        target.relative_to(base_dir)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="path not allowed")
    if not target.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="file not found")

    logger.info("Download served jti=%s sub=%s file=%s", verified.nonce, verified.subject, target)
    return FileResponse(
        target,
        filename=target.name,
        headers={"X-Capability-Id": verified.nonce},
    )


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)
