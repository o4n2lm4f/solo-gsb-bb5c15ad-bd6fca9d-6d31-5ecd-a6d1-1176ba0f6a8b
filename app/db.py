"""SQLite storage for consumed one-time nonces and subject revocations.

Only nonces of *one-time* tokens need to be remembered server side: the
signature and expiry of every other claim are verified statelessly. Subject
revocations are the second stateful piece: an administrator can invalidate
every token a subject was issued at or before a cutoff time.

Both concerns are mutated inside ``BEGIN IMMEDIATE`` transactions. In
particular, the revocation check and the nonce consumption of a single
verification run in *one* transaction, so a revoked token never burns its
nonce and a verification racing a revocation is decided atomically.
"""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator, Literal

SCHEMA = """
CREATE TABLE IF NOT EXISTS consumed_nonces (
    nonce      TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_consumed_nonces_expires_at
    ON consumed_nonces (expires_at);

CREATE TABLE IF NOT EXISTS subject_revocations (
    subject    TEXT PRIMARY KEY,
    cutoff     INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) WITHOUT ROWID;
"""

#: Outcome of the atomic revocation-check + nonce-consumption transaction.
VerifyOutcome = Literal["ok", "subject_revoked", "nonce_replayed"]


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        # Initialise the schema eagerly so first request never blocks on it.
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 5000")
            yield conn
        finally:
            conn.close()

    # -- verification ------------------------------------------------------

    def check_revocation_and_consume_nonce(
        self,
        *,
        subject: str | None,
        issued_at: int,
        nonce: str,
        expires_at: int,
        consume: bool,
    ) -> VerifyOutcome:
        """Check subject revocation and consume a nonce in ONE transaction.

        The revocation lookup and the nonce insert share a single
        ``BEGIN IMMEDIATE`` transaction, so a revocation committed
        concurrently either blocks the nonce burn or is itself blocked by
        the committed burn — the two can never half-apply. A revoked token
        returns ``"subject_revoked"`` and its nonce is *not* consumed.

        ``consume=False`` performs the revocation check only (dry run);
        subject-less tokens that do not need consumption stay fully
        stateless and never touch the database.
        """
        if subject is None and not consume:
            return "ok"
        with self.connect() as conn:
            try:
                # IMMEDIATE acquires a RESERVED lock immediately, turning
                # racing writers into a clean serialisation instead of a
                # mid-transaction SQLITE_BUSY upgrade failure.
                conn.execute("BEGIN IMMEDIATE")
                if subject is not None:
                    row = conn.execute(
                        "SELECT cutoff FROM subject_revocations WHERE subject = ?",
                        (subject,),
                    ).fetchone()
                    if row is not None and issued_at <= row["cutoff"]:
                        conn.rollback()
                        return "subject_revoked"
                if consume:
                    cursor = conn.execute(
                        "INSERT OR IGNORE INTO consumed_nonces (nonce, expires_at) VALUES (?, ?)",
                        (nonce, expires_at),
                    )
                    if cursor.rowcount != 1:
                        conn.rollback()
                        return "nonce_replayed"
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return "ok"

    # -- subject revocations ------------------------------------------------

    def set_subject_revocation(
        self, subject: str, cutoff: int, now: int | None = None
    ) -> dict[str, Any]:
        """Create or replace the revocation cutoff for *subject*.

        Re-revoking keeps the original ``created_at`` and only moves the
        cutoff / ``updated_at``. Returns the stored row.
        """
        now = int(time.time()) if now is None else now
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO subject_revocations (subject, cutoff, created_at, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(subject) DO UPDATE SET
                        cutoff = excluded.cutoff,
                        updated_at = excluded.updated_at
                    """,
                    (subject, int(cutoff), now, now),
                )
                row = conn.execute(
                    "SELECT subject, cutoff, created_at, updated_at "
                    "FROM subject_revocations WHERE subject = ?",
                    (subject,),
                ).fetchone()
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return dict(row)

    def get_subject_revocation(self, subject: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT subject, cutoff, created_at, updated_at "
                "FROM subject_revocations WHERE subject = ?",
                (subject,),
            ).fetchone()
        return dict(row) if row is not None else None

    def delete_subject_revocation(self, subject: str) -> bool:
        """Remove a subject's revocation (restore access).

        Returns ``True`` when a revocation actually existed.
        """
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.execute(
                    "DELETE FROM subject_revocations WHERE subject = ?", (subject,)
                )
                removed = cursor.rowcount == 1
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return removed

    def list_subject_revocations(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT subject, cutoff, created_at, updated_at "
                "FROM subject_revocations ORDER BY subject"
            ).fetchall()
        return [dict(row) for row in rows]

    # -- housekeeping --------------------------------------------------------

    def purge_expired(self, now: int | None = None, *, max_token_ttl: int) -> tuple[int, int]:
        """Delete rows that can no longer influence verification.

        * consumed nonces whose token has expired;
        * subject revocations whose cutoff is so far in the past that every
          token they could still revoke (``iat <= cutoff`` with a lifetime
          of at most ``max_token_ttl`` seconds) has already expired:
          ``cutoff + max_token_ttl <= now``.

        Returns ``(nonces_removed, revocations_removed)``.
        """
        now = int(time.time()) if now is None else now
        with self.connect() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                nonces = conn.execute(
                    "DELETE FROM consumed_nonces WHERE expires_at < ?", (now,)
                )
                revocations = conn.execute(
                    "DELETE FROM subject_revocations WHERE cutoff + ? <= ?",
                    (max_token_ttl, now),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        return nonces.rowcount, revocations.rowcount
