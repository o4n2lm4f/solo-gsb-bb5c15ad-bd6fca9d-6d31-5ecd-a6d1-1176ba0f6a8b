"""Application configuration loaded from environment variables.

No third-party accounts are required: the only secrets are the HMAC keys used
to sign tokens. The preferred configuration is an ordered *key ring*
(``CAPABILITY_KEYRING``) that enables zero-downtime key rotation:

* the first ``kid:secret`` entry signs every newly issued token,
* every entry can verify tokens (looked up **exactly** by the ``kid`` claim),
* tokens without a ``kid`` claim (issued by older versions) can only be
  verified with ``CAPABILITY_LEGACY_SECRET`` — the ring is never probed.

The legacy single-variable mode (``CAPABILITY_SECRET``) still works but is
mutually exclusive with ``CAPABILITY_KEYRING``. If neither is provided an
ephemeral random key is generated at startup (tokens then become invalid
across restarts).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"Environment variable {name} must be an integer, got {raw!r}") from exc
    return value


#: Synthetic kid used when the service runs in legacy CAPABILITY_SECRET mode.
DEFAULT_KID = "default"
#: Synthetic kid used for the process-local random key.
EPHEMERAL_KID = "ephemeral"


@dataclass(frozen=True)
class Keyring:
    """Ordered HMAC signing keys.

    ``entries`` preserves configuration order: the first entry is the active
    signing key and *every* entry is a valid verification key. Lookup is an
    exact ``kid`` match — verification never iterates the ring trying keys.

    ``legacy_secret`` verifies only tokens that carry no ``kid`` claim; it is
    never used for signing.
    """

    entries: tuple[tuple[str, bytes], ...]
    legacy_secret: bytes | None = None

    def __post_init__(self) -> None:
        if not self.entries:
            raise RuntimeError("key ring must contain at least one signing key")

    @property
    def active_kid(self) -> str:
        return self.entries[0][0]

    @property
    def active_secret(self) -> bytes:
        return self.entries[0][1]

    @property
    def kids(self) -> tuple[str, ...]:
        return tuple(kid for kid, _secret in self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def get_secret(self, kid: str) -> bytes | None:
        """Return the secret for *kid* or ``None`` — never falls through."""
        for entry_kid, secret in self.entries:
            if entry_kid == kid:
                return secret
        return None


def parse_keyring(raw: str) -> tuple[tuple[str, bytes], ...]:
    """Parse ``CAPABILITY_KEYRING`` content into ordered ``(kid, secret)``.

    Format: comma-separated ``kid:secret`` entries. The split happens on the
    *first* colon, so a secret may itself contain colons. Startup fails hard
    on empty entries, missing/empty kids, empty secrets or duplicate kids —
    a misconfigured rotation must never boot into a state where the wrong key
    is used silently.
    """
    entries: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for position, part in enumerate(raw.split(","), start=1):
        item = part.strip()
        if not item:
            raise RuntimeError(
                f"CAPABILITY_KEYRING entry #{position} is empty; expected 'kid:secret'"
            )
        kid, separator, secret = item.partition(":")
        kid = kid.strip()
        if not separator or not kid:
            raise RuntimeError(
                f"CAPABILITY_KEYRING entry #{position} is malformed: expected 'kid:secret', "
                f"got {item!r}"
            )
        if secret == "":
            raise RuntimeError(
                f"CAPABILITY_KEYRING entry #{position} (kid={kid!r}) has an empty secret"
            )
        if kid in seen:
            raise RuntimeError(f"CAPABILITY_KEYRING contains a duplicate kid {kid!r}")
        seen.add(kid)
        entries.append((kid, secret.encode("utf-8")))
    return tuple(entries)


@dataclass(frozen=True)
class Settings:
    #: Ordered HMAC keys (first one signs, all verify) plus optional legacy key.
    keyring: Keyring
    #: SQLite database file path (env: CAPABILITY_DB_PATH).
    db_path: str
    #: Directory that backs the guarded GET /files/{name} resource.
    files_dir: str
    #: Default token lifetime in seconds.
    default_ttl: int
    #: Hard upper bound for token lifetime in seconds.
    max_ttl: int
    #: Optional shared key guarding POST /tokens/issue (header X-Issuer-Key).
    issuer_key: str | None
    #: Optional shared key guarding the revocation admin endpoints
    #: (header X-Admin-Key). When unset those endpoints are disabled (503).
    admin_key: str | None
    #: True when no signing key was configured and a random key is used.
    ephemeral: bool


def load_settings() -> Settings:
    keyring_raw = os.environ.get("CAPABILITY_KEYRING", "").strip()
    secret_raw = os.environ.get("CAPABILITY_SECRET", "").strip()
    legacy_raw = os.environ.get("CAPABILITY_LEGACY_SECRET", "").strip()

    # Conflict: the two configuration styles must not be mixed, otherwise the
    # operator could not tell which key actually signed a given token.
    if keyring_raw and secret_raw:
        raise RuntimeError(
            "CAPABILITY_KEYRING and CAPABILITY_SECRET must not be set at the same time; "
            "migrate CAPABILITY_SECRET into the key ring "
            "(e.g. CAPABILITY_KEYRING='<new-kid>:<new-secret>,default:"
            "<old-capability-secret>') or use CAPABILITY_LEGACY_SECRET for "
            "tokens issued before key-ring support"
        )

    ephemeral = not keyring_raw and not secret_raw
    if keyring_raw:
        entries = parse_keyring(keyring_raw)
        # Explicit opt-in only: kid-less tokens are rejected unless the
        # operator configured a legacy verification key.
        legacy_secret = legacy_raw.encode("utf-8") if legacy_raw else None
    elif secret_raw:
        # Backwards-compatible single-key mode. The same secret implicitly
        # serves as the legacy verifier so pre-upgrade kid-less tokens keep
        # working; new tokens are still issued with a kid.
        entries = ((DEFAULT_KID, secret_raw.encode("utf-8")),)
        legacy_secret = (legacy_raw or secret_raw).encode("utf-8")
    else:
        # 32-byte URL-safe random key for this process only.
        entries = ((EPHEMERAL_KID, secrets.token_urlsafe(32).encode("utf-8")),)
        legacy_secret = legacy_raw.encode("utf-8") if legacy_raw else None

    issuer_key = os.environ.get("CAPABILITY_ISSUER_KEY", "").strip() or None
    admin_key = os.environ.get("CAPABILITY_ADMIN_KEY", "").strip() or None
    files_dir = os.environ.get("CAPABILITY_FILES_DIR", os.path.join(os.getcwd(), "files"))

    default_ttl = _int_env("CAPABILITY_DEFAULT_TTL", 300)
    max_ttl = _int_env("CAPABILITY_MAX_TTL", 3600)
    if default_ttl <= 0 or max_ttl <= 0 or default_ttl > max_ttl:
        raise RuntimeError(
            "CAPABILITY_DEFAULT_TTL and CAPABILITY_MAX_TTL must be positive and "
            "default <= max"
        )

    return Settings(
        keyring=Keyring(entries, legacy_secret=legacy_secret),
        db_path=os.environ.get(
            "CAPABILITY_DB_PATH", os.path.join(os.getcwd(), "data", "capabilities.db")
        ),
        files_dir=files_dir,
        default_ttl=default_ttl,
        max_ttl=max_ttl,
        issuer_key=issuer_key,
        admin_key=admin_key,
        ephemeral=ephemeral,
    )
