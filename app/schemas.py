"""Pydantic request / response models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class IssueTokenRequest(BaseModel):
    method: str = Field(
        ..., min_length=1, max_length=16, description="HTTP method the token is bound to, e.g. GET"
    )
    path: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Path the token is bound to, e.g. /files/report.pdf",
    )
    ttl_seconds: int | None = Field(
        default=None, ge=1, le=24 * 3600, description="Lifetime in seconds (server may cap it)"
    )
    one_time: bool = Field(default=False, description="If true the token can be consumed once only")
    subject: str | None = Field(default=None, max_length=256)
    extra: dict[str, Any] | None = Field(default=None, description="Arbitrary extra claims")

    @field_validator("path")
    @classmethod
    def _path_must_start_with_slash(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("path must start with '/'")
        return value

    @field_validator("method")
    @classmethod
    def _method_must_be_token(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned.replace("-", "").isalnum():
            raise ValueError("method must be an HTTP method token like GET or POST")
        return cleaned


class IssuedTokenResponse(BaseModel):
    token: str
    token_id: str
    kid: str | None = Field(
        default=None, description="Id of the ring key that signed this token"
    )
    method: str
    path: str
    issued_at: int
    expires_at: int
    expires_in: int
    one_time: bool
    subject: str | None = None


class VerifyTokenRequest(BaseModel):
    token: str = Field(..., min_length=1, description="The capability token to verify")
    method: str = Field(
        ..., min_length=1, max_length=16, description="HTTP method to check against"
    )
    path: str = Field(
        ..., min_length=1, max_length=2048, description="Resource path to check against"
    )
    consume: bool = Field(
        default=True,
        description="Consume the one-time nonce on success. Use false for a dry run",
    )

    @field_validator("path")
    @classmethod
    def _verify_path_must_start_with_slash(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("path must start with '/'")
        return value


class VerifyTokenResponse(BaseModel):
    valid: bool
    kid: str | None = Field(
        default=None,
        description="Ring key id that verified the token (null for legacy kid-less tokens)",
    )
    method: str
    path: str
    expires_at: int
    expires_in: int
    one_time: bool
    consumed: bool
    token_id: str
    subject: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class RevokeSubjectRequest(BaseModel):
    subject: str = Field(
        ..., min_length=1, max_length=256, description="Subject to revoke or restore"
    )
    cutoff: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Revoke tokens with iat <= cutoff (unix seconds). Defaults to now. "
            "Ignored when restore=true"
        ),
    )
    restore: bool = Field(
        default=False, description="If true, remove the subject's revocation instead"
    )


class RevokeSubjectResponse(BaseModel):
    subject: str
    revoked: bool = Field(description="Whether a revocation is in effect after this call")
    restored: bool = Field(
        default=False, description="True when this call removed an existing revocation"
    )
    cutoff: int | None = None
    created_at: int | None = None
    updated_at: int | None = None


class RevocationEntry(BaseModel):
    subject: str
    cutoff: int
    created_at: int
    updated_at: int


class RevocationListResponse(BaseModel):
    revocations: list[RevocationEntry]
    count: int


class ErrorResponse(BaseModel):
    error: str
    detail: str
