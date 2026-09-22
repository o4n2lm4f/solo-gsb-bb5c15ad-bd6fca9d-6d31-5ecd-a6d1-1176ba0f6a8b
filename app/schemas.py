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


class TokenConstraints(BaseModel):
    """Effective constraints that ultimately govern the token."""

    method: str
    path: str
    expires_at: int
    subject: str | None = None
    one_time: bool = False


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
    chain_depth: int = Field(
        default=1,
        description="Delegation chain depth; a directly issued token is 1",
    )
    constraints: TokenConstraints | None = Field(
        default=None,
        description="Final effective constraints (method/path/expiry/subject)",
    )


class DelegateTokenRequest(BaseModel):
    parent_token: str = Field(
        ..., min_length=1, description="The parent capability token delegating authority"
    )
    method: str = Field(
        ..., min_length=1, max_length=16, description="HTTP method the child is bound to"
    )
    path: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Resource path the child is bound to; must be under the parent path",
    )
    ttl_seconds: int = Field(
        ...,
        ge=1,
        le=24 * 3600,
        description="Requested lifetime in seconds; capped to the parent's remaining lifetime",
    )
    subject: str | None = Field(
        default=None,
        max_length=256,
        description="Must equal the parent subject; omit to inherit it",
    )

    @field_validator("path")
    @classmethod
    def _delegate_path_must_start_with_slash(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("path must start with '/'")
        return value

    @field_validator("method")
    @classmethod
    def _delegate_method_must_be_token(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned.replace("-", "").isalnum():
            raise ValueError("method must be an HTTP method token like GET or POST")
        return cleaned


class DelegatedTokenResponse(IssuedTokenResponse):
    parent_token_id: str = Field(description="jti of the token delegated from")
    parent_expires_at: int = Field(
        description="Parent expiry; the child can never outlive this"
    )
    ttl_capped_to_parent: bool = Field(
        description="True when the requested ttl was shortened to the parent's remaining lifetime"
    )


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
    chain_depth: int = Field(
        default=1,
        description="Number of tokens in the verified delegation chain (root token = 1)",
    )
    constraints: TokenConstraints | None = Field(
        default=None,
        description="Final effective constraints after walking the whole delegation chain",
    )


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
