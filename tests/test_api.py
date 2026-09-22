"""End-to-end tests for the Capability Token API.

Runs fully in-process via FastAPI's TestClient against an isolated temp
directory — no network, Docker, or third-party account needed:

    python tests/test_api.py
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="capapi-test-")
os.environ["CAPABILITY_KEYRING"] = "ring-active:active-secret,ring-old:old-secret"
os.environ["CAPABILITY_LEGACY_SECRET"] = "legacy-secret"
os.environ["CAPABILITY_DB_PATH"] = os.path.join(_tmp, "test.db")
os.environ["CAPABILITY_FILES_DIR"] = os.path.join(_tmp, "files")
os.environ["CAPABILITY_DEFAULT_TTL"] = "300"
os.environ["CAPABILITY_MAX_TTL"] = "3600"
os.environ["CAPABILITY_ADMIN_KEY"] = "test-admin-key"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from app.config import Keyring, parse_keyring  # noqa: E402
from app.main import app  # noqa: E402
from app import tokens as tokenlib  # noqa: E402

FILES_DIR = Path(os.environ["CAPABILITY_FILES_DIR"])
FILES_DIR.mkdir(parents=True, exist_ok=True)
(FILES_DIR / "hello.txt").write_text("hello capability world\n", encoding="utf-8")

#: Secrets from the configured test ring (first entry signs new tokens).
ACTIVE_KID = "ring-active"
OLD_KID = "ring-old"
LEGACY_SECRET = b"legacy-secret"
#: A kid that no ring contains: tokens claiming it must fail unknown_key.
UNKNOWN_KID = "ring-gone"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class CapabilityApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Context-manager use triggers the lifespan (DB init, dirs, purge loop).
        cls._cm = TestClient(app)
        cls.client = cls._cm.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._cm.__exit__(None, None, None)

    # -- helpers -----------------------------------------------------------

    def issue(self, **overrides):
        body = {"method": "GET", "path": "/files/hello.txt", "ttl_seconds": 60}
        body.update(overrides)
        resp = self.client.post("/tokens/issue", json=body)
        self.assertEqual(resp.status_code, 200, resp.text)
        return resp.json()

    def delegate(self, parent_token, **overrides):
        body = {
            "parent_token": parent_token,
            "method": "GET",
            "path": "/files/hello.txt",
            "ttl_seconds": 60,
        }
        body.update(overrides)
        return self.client.post("/tokens/delegate", json=body)

    def delegate_core(self, parent_token, **overrides):
        body = {
            "keyring": app.state.settings.keyring,
            "db": app.state.db,
            "method": "GET",
            "path": "/files/hello.txt",
            "ttl_seconds": 60,
        }
        body.update(overrides)
        return tokenlib.delegate_token(parent_token, **body)

    def verify(self, token, method="GET", path="/files/hello.txt", consume=True):
        return self.client.post(
            "/tokens/verify",
            json={"token": token, "method": method, "path": path, "consume": consume},
        )

    def admin_headers(self):
        return {"X-Admin-Key": "test-admin-key"}

    def revoke(self, subject, cutoff=None, restore=False, headers=None):
        body = {"subject": subject, "restore": restore}
        if cutoff is not None:
            body["cutoff"] = cutoff
        return self.client.post(
            "/tokens/revoke-subject",
            json=body,
            headers=headers if headers is not None else self.admin_headers(),
        )

    def list_revocations(self, headers=None):
        return self.client.get(
            "/tokens/revocations",
            headers=headers if headers is not None else self.admin_headers(),
        )

    # -- issuing -----------------------------------------------------------

    def test_01_issue_token_shape(self):
        data = self.issue(subject="alice", extra={"ticket": "T-1"})
        self.assertEqual(data["method"], "GET")
        self.assertEqual(data["path"], "/files/hello.txt")
        self.assertEqual(data["expires_in"], 60)
        self.assertFalse(data["one_time"])
        self.assertEqual(data["subject"], "alice")
        self.assertRegex(data["token"], r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

    def test_02_ttl_is_capped_to_max(self):
        data = self.issue(ttl_seconds=10_000)
        self.assertEqual(data["expires_in"], 3600)

    def test_03_path_is_canonicalised_on_issue(self):
        data = self.issue(path="//files/./hello.txt/")
        self.assertEqual(data["path"], "/files/hello.txt")

    def test_04_issuer_key_gate_when_configured(self):
        # Dynamic reconfiguration: enable the issuer key just for this test.
        from dataclasses import replace

        settings = app.state.settings
        app.state.settings = replace(settings, issuer_key="s3cret")
        try:
            resp = self.client.post(
                "/tokens/issue", json={"method": "GET", "path": "/files/hello.txt"}
            )
            self.assertEqual(resp.status_code, 401)
            resp = self.client.post(
                "/tokens/issue",
                json={"method": "GET", "path": "/files/hello.txt"},
                headers={"X-Issuer-Key": "wrong"},
            )
            self.assertEqual(resp.status_code, 401)
            resp = self.client.post(
                "/tokens/issue",
                json={"method": "GET", "path": "/files/hello.txt"},
                headers={"X-Issuer-Key": "s3cret"},
            )
            self.assertEqual(resp.status_code, 200)
        finally:
            app.state.settings = settings

    #-- verification -------------------------------------------------------

    def test_05_verify_valid_multi_use_repeatedly(self):
        data = self.issue()
        for _ in range(3):
            resp = self.verify(data["token"])
            self.assertEqual(resp.status_code, 200, resp.text)
            self.assertTrue(resp.json()["valid"])
            self.assertFalse(resp.json()["consumed"])

    def test_06_wrong_signature_rejected(self):
        data = self.issue()
        payload, sig = data["token"].split(".")
        # Flip the FIRST character of the signature: the first base64 symbol
        # carries the top 6 bits of the digest, so the decoded bytes are
        # guaranteed to differ (flipping the last symbol can be a no-op when
        # the trailing 2 bits happen to be zero).
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        resp = self.verify(f"{payload}.{flipped}")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "bad_signature")

    def test_07_tampered_payload_rejected(self):
        data = self.issue(path="/files/hello.txt")
        payload, _sig = data["token"].split(".")
        payload_b = base64.urlsafe_b64decode(payload + "==")
        tampered = json.loads(payload_b)
        tampered["p"] = "/files/secret.txt"
        new_payload = _b64(json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode())
        resp = self.verify(f"{new_payload}.{data['token'].split('.')[1]}")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "bad_signature")

    def test_08_method_binding(self):
        data = self.issue(method="GET")
        resp = self.verify(data["token"], method="DELETE")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "method_mismatch")

    def test_09_path_binding(self):
        data = self.issue(path="/files/hello.txt")
        resp = self.verify(data["token"], path="/files/other.txt")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "path_mismatch")

    def test_10_path_canonicalisation_matches(self):
        data = self.issue(path="/files/hello.txt")
        resp = self.verify(data["token"], path="//files/./hello.txt/")
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_11_expired_token_rejected(self):
        # Hand-craft an already-expired token signed with the correct key.
        from app.main import app as real_app

        issued = tokenlib.issue_token(
            real_app.state.settings.keyring,
            method="GET",
            path="/files/hello.txt",
            ttl_seconds=1,
            now=int(time.time()) - 10,
        )
        resp = self.verify(issued.token)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "expired")

    def test_12_malformed_tokens(self):
        for bad in ["nodot", ".", "abc.!!!", "a.b"]:
            resp = self.verify(bad)
            self.assertEqual(resp.status_code, 401, f"expected 401 for {bad!r}: {resp.text}")
            self.assertEqual(resp.json()["error"], "malformed")

    def test_12b_empty_token_is_a_client_error(self):
        resp = self.verify("")
        self.assertEqual(resp.status_code, 422)

    # -- one-time nonce ----------------------------------------------------

    def test_13_one_time_token_used_once(self):
        data = self.issue(one_time=True)
        first = self.verify(data["token"])
        self.assertEqual(first.status_code, 200, first.text)
        self.assertTrue(first.json()["consumed"])

        second = self.verify(data["token"])
        self.assertEqual(second.status_code, 401)
        self.assertEqual(second.json()["error"], "nonce_replayed")

    def test_14_dry_run_does_not_burn_token(self):
        data = self.issue(one_time=True)
        dry = self.verify(data["token"], consume=False)
        self.assertEqual(dry.status_code, 200)
        self.assertFalse(dry.json()["consumed"])
        real = self.verify(data["token"], consume=True)
        self.assertEqual(real.status_code, 200)
        self.assertTrue(real.json()["consumed"])

    def test_15_concurrent_replays_only_one_wins(self):
        # TestClient serialises requests, so hit the verification core in real
        # threads to prove the SQLite nonce insert is atomic under contention.
        from app.db import Database

        data = self.issue(one_time=True)
        settings = app.state.settings
        db: Database = app.state.db
        outcomes: list[str] = []
        lock = threading.Lock()

        def attempt():
            try:
                tokenlib.verify_token(
                    data["token"],
                    keyring=settings.keyring,
                    method="GET",
                    path="/files/hello.txt",
                    db=db,
                    consume=True,
                )
                result = "ok"
            except tokenlib.TokenError as exc:
                result = exc.code
            with lock:
                outcomes.append(result)

        barrier = threading.Barrier(12)

        def gated():
            barrier.wait()  # maximise the race window
            attempt()

        threads = [threading.Thread(target=gated) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(outcomes.count("ok"), 1, outcomes)
        self.assertEqual(outcomes.count("nonce_replayed"), 11, outcomes)

    def test_16_distinct_one_time_tokens_both_work(self):
        a = self.issue(one_time=True)
        b = self.issue(one_time=True)
        self.assertEqual(self.verify(a["token"]).status_code, 200)
        self.assertEqual(self.verify(b["token"]).status_code, 200)
        self.assertEqual(self.verify(a["token"]).status_code, 401)
        self.assertEqual(self.verify(b["token"]).status_code, 401)

    # -- guarded resource --------------------------------------------------

    def test_17_download_without_token_unauthorized(self):
        resp = self.client.get("/files/hello.txt")
        self.assertEqual(resp.status_code, 401)

    def test_18_download_with_valid_one_time_token(self):
        data = self.issue(method="GET", path="/files/hello.txt", one_time=True)

        via_query = self.client.get(f"/files/hello.txt?token={data['token']}")
        self.assertEqual(via_query.status_code, 200, via_query.text)
        self.assertIn("hello capability world", via_query.text)
        self.assertEqual(via_query.headers["X-Capability-Id"], data["token_id"])

        replay = self.client.get(f"/files/hello.txt?token={data['token']}")
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(replay.json()["error"], "nonce_replayed")

    def test_19_download_via_bearer_and_header(self):
        for header_name, value in (
            ("Authorization", "Bearer {t}"),
            ("X-Capability-Token", "{t}"),
        ):
            data = self.issue()
            resp = self.client.get("/files/hello.txt", headers={header_name: value.format(t=data["token"])})
            self.assertEqual(resp.status_code, 200, resp.text)

    def test_20_download_method_binding_blocks_head_token_on_get(self):
        # Token bound to HEAD cannot be used for GET.
        issued = tokenlib.issue_token(
            app.state.settings.keyring,
            method="HEAD",
            path="/files/hello.txt",
            ttl_seconds=60,
        )
        resp = self.client.get(f"/files/hello.txt?token={issued.token}")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "method_mismatch")

    def test_21_download_missing_file_returns_404_and_burns_nonce(self):
        data = self.issue(path="/files/does-not-exist.txt", one_time=True)
        resp = self.client.get(f"/files/does-not-exist.txt?token={data['token']}")
        self.assertEqual(resp.status_code, 404)
        replay = self.client.get(f"/files/does-not-exist.txt?token={data['token']}")
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(replay.json()["error"], "nonce_replayed")

    def test_22_traversal_is_blocked(self):
        # A token cannot be minted that escapes the files directory even via
        # normalised dot-segments: /files/../x canonicalises to /x, and the
        # filesystem layer additionally guards resolved paths.
        data = self.issue(path="/x", one_time=True)
        resp = self.client.get(f"/x?token={data['token']}")
        # /x is not a file route at all -> FastAPI 404 (no matching route).
        self.assertIn(resp.status_code, (404, 403))

    def test_23_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")

    # -- subject revocation -------------------------------------------------

    def test_24_admin_endpoints_require_key(self):
        from dataclasses import replace

        settings = app.state.settings

        # Fail closed: without a configured admin key the endpoints are 503.
        app.state.settings = replace(settings, admin_key=None)
        try:
            resp = self.revoke("revo-guard", headers={})
            self.assertEqual(resp.status_code, 503)
            self.assertEqual(resp.json()["error"], "admin_key_not_configured")
            resp = self.list_revocations(headers={})
            self.assertEqual(resp.status_code, 503)
        finally:
            app.state.settings = settings

        # Configured: missing or wrong key -> 401, correct key -> 200.
        self.assertEqual(self.revoke("revo-guard", headers={}).status_code, 401)
        self.assertEqual(
            self.revoke("revo-guard", headers={"X-Admin-Key": "wrong"}).status_code, 401
        )
        self.assertEqual(self.list_revocations(headers={}).status_code, 401)
        resp = self.revoke("revo-guard")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(resp.json()["revoked"])
        self.revoke("revo-guard", restore=True)

    def test_25_revoke_blocks_old_tokens_new_ones_still_work(self):
        subject = "revo-basic"
        keyring = app.state.settings.keyring
        now = int(time.time())
        old = tokenlib.issue_token(
            keyring,
            method="GET",
            path="/files/hello.txt",
            ttl_seconds=300,
            subject=subject,
            now=now - 60,
        )
        # Not revoked yet -> valid.
        self.assertEqual(self.verify(old.token).status_code, 200)

        resp = self.revoke(subject, cutoff=now - 30)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertTrue(body["revoked"])
        self.assertEqual(body["cutoff"], now - 30)

        # iat (now-60) <= cutoff (now-30) -> revoked, even though unexpired.
        resp = self.verify(old.token)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "subject_revoked")

        # A token issued after the cutoff is unaffected.
        fresh = tokenlib.issue_token(
            keyring,
            method="GET",
            path="/files/hello.txt",
            ttl_seconds=300,
            subject=subject,
            now=now,
        )
        self.assertEqual(self.verify(fresh.token).status_code, 200, fresh.token)
        self.revoke(subject, restore=True)

    def test_26_cutoff_boundary_is_inclusive(self):
        subject = "revo-boundary"
        keyring = app.state.settings.keyring
        now = int(time.time())
        at_cutoff = tokenlib.issue_token(
            keyring, method="GET", path="/files/hello.txt",
            ttl_seconds=300, subject=subject, now=now,
        )
        after_cutoff = tokenlib.issue_token(
            keyring, method="GET", path="/files/hello.txt",
            ttl_seconds=300, subject=subject, now=now + 1,
        )
        self.revoke(subject, cutoff=now)
        # "不晚于" — iat == cutoff is revoked; iat == cutoff + 1 is not.
        resp = self.verify(at_cutoff.token)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "subject_revoked")
        self.assertEqual(self.verify(after_cutoff.token).status_code, 200)
        self.revoke(subject, restore=True)

    def test_27_revoked_one_time_token_keeps_its_nonce(self):
        subject = "revo-keep-nonce"
        data = self.issue(one_time=True, subject=subject)
        # Future cutoff deterministically covers the just-issued token.
        self.revoke(subject, cutoff=int(time.time()) + 5)

        resp = self.verify(data["token"])
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "subject_revoked")

        # Restore: the revoked attempt must NOT have consumed the nonce.
        resp = self.revoke(subject, restore=True)
        self.assertTrue(resp.json()["restored"])
        resp = self.verify(data["token"])
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertTrue(resp.json()["consumed"])
        # And now it is genuinely burned.
        resp = self.verify(data["token"])
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "nonce_replayed")

    def test_28_restore_unknown_subject_is_a_noop(self):
        resp = self.revoke("revo-never-existed", restore=True)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertFalse(body["revoked"])
        self.assertFalse(body["restored"])

    def test_29_revocations_listing(self):
        self.revoke("revo-list-a", cutoff=1000)
        self.revoke("revo-list-b", cutoff=2000)
        try:
            resp = self.list_revocations()
            self.assertEqual(resp.status_code, 200, resp.text)
            entries = {e["subject"]: e for e in resp.json()["revocations"]}
            self.assertEqual(resp.json()["count"], len(entries))
            self.assertEqual(entries["revo-list-a"]["cutoff"], 1000)
            self.assertEqual(entries["revo-list-b"]["cutoff"], 2000)
            self.assertIn("created_at", entries["revo-list-a"])
            self.assertIn("updated_at", entries["revo-list-a"])

            # Re-revoking moves the cutoff and keeps a single row.
            self.revoke("revo-list-a", cutoff=1500)
            entries = {e["subject"]: e for e in self.list_revocations().json()["revocations"]}
            self.assertEqual(entries["revo-list-a"]["cutoff"], 1500)
        finally:
            self.revoke("revo-list-a", restore=True)
            self.revoke("revo-list-b", restore=True)
        entries = {e["subject"]: e for e in self.list_revocations().json()["revocations"]}
        self.assertNotIn("revo-list-a", entries)
        self.assertNotIn("revo-list-b", entries)

    def test_30_dry_run_still_enforces_revocation(self):
        subject = "revo-dry-run"
        data = self.issue(one_time=True, subject=subject)
        self.revoke(subject, cutoff=int(time.time()) + 5)
        # consume=false is a dry run, but revocation is not optional.
        resp = self.verify(data["token"], consume=False)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "subject_revoked")
        # The dry run did not burn the nonce either.
        self.revoke(subject, restore=True)
        self.assertEqual(self.verify(data["token"]).status_code, 200)

    def test_31_concurrent_verifications_all_blocked_by_revocation(self):
        # 12 racing verifications of a revoked one-time token: every one gets
        # subject_revoked and the nonce survives to be used after a restore.
        from app.db import Database

        subject = "revo-race-blocked"
        data = self.issue(one_time=True, subject=subject)
        self.revoke(subject, cutoff=int(time.time()) + 30)
        settings = app.state.settings
        db: Database = app.state.db
        outcomes: list[str] = []
        lock = threading.Lock()

        def attempt():
            try:
                tokenlib.verify_token(
                    data["token"],
                    keyring=settings.keyring,
                    method="GET",
                    path="/files/hello.txt",
                    db=db,
                    consume=True,
                )
                result = "ok"
            except tokenlib.TokenError as exc:
                result = exc.code
            with lock:
                outcomes.append(result)

        barrier = threading.Barrier(12)

        def gated():
            barrier.wait()
            attempt()

        threads = [threading.Thread(target=gated) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(outcomes.count("subject_revoked"), 12, outcomes)

        # None of the 12 attempts consumed the nonce.
        self.revoke(subject, restore=True)
        self.assertEqual(self.verify(data["token"]).status_code, 200)

    def test_32_concurrent_verify_vs_revoke_is_atomic(self):
        # Each verification and the revocation commit are single IMMEDIATE
        # transactions, so every racing token ends up exactly one of:
        # verified (nonce burned) or subject_revoked (nonce intact).
        from app.db import Database

        subject = "revo-race"
        settings = app.state.settings
        db: Database = app.state.db
        tokens = [self.issue(one_time=True, subject=subject)["token"] for _ in range(8)]
        outcomes: dict[str, str] = {}
        lock = threading.Lock()
        barrier = threading.Barrier(len(tokens) + 1)

        def attempt(token):
            barrier.wait()
            try:
                tokenlib.verify_token(
                    token,
                    keyring=settings.keyring,
                    method="GET",
                    path="/files/hello.txt",
                    db=db,
                    consume=True,
                )
                result = "ok"
            except tokenlib.TokenError as exc:
                result = exc.code
            with lock:
                outcomes[token] = result

        threads = [threading.Thread(target=attempt, args=(t,)) for t in tokens]
        for t in threads:
            t.start()
        barrier.wait()  # release the verifiers, then revoke mid-race
        db.set_subject_revocation(subject, int(time.time()) + 30)
        for t in threads:
            t.join()

        # No token may report a replay: each was presented exactly once.
        self.assertEqual(set(outcomes.values()) - {"ok", "subject_revoked"}, set(), outcomes)

        db.delete_subject_revocation(subject)
        for token, outcome in outcomes.items():
            resp = self.verify(token)
            if outcome == "ok":
                # Won the race -> nonce was consumed back then.
                self.assertEqual(resp.status_code, 401, token)
                self.assertEqual(resp.json()["error"], "nonce_replayed")
            else:
                # Lost to the revocation -> nonce was never consumed.
                self.assertEqual(resp.status_code, 200, token)

    def test_33_stale_revocations_are_purged(self):
        from app.db import Database

        db: Database = app.state.db
        settings = app.state.settings
        now = int(time.time())
        # Cutoff so old that any token it could revoke has long expired.
        db.set_subject_revocation("revo-purge-old", now - 2 * settings.max_ttl, now=now - 2 * settings.max_ttl)
        db.set_subject_revocation("revo-purge-fresh", now, now=now)

        nonces_removed, revocations_removed = db.purge_expired(
            now=now, max_token_ttl=settings.max_ttl
        )
        self.assertGreaterEqual(revocations_removed, 1)
        self.assertIsNone(db.get_subject_revocation("revo-purge-old"))
        self.assertIsNotNone(db.get_subject_revocation("revo-purge-fresh"))
        db.delete_subject_revocation("revo-purge-fresh")

    # -- key ring / zero-downtime rotation ---------------------------------

    @staticmethod
    def _raw_token(payload: dict, secret: bytes) -> str:
        """Sign an arbitrary payload dict with an arbitrary secret."""
        import hashlib
        import hmac as _hmac

        payload_b = tokenlib._payload_to_bytes(payload)
        signature = _hmac.new(secret, payload_b, hashlib.sha256).digest()
        return f"{tokenlib._b64url_encode(payload_b)}.{tokenlib._b64url_encode(signature)}"

    def _payload(self, **overrides):
        now = int(time.time())
        payload = tokenlib.build_payload(
            method="GET",
            path="/files/hello.txt",
            expires_at=now + 120,
            issued_at=now,
            nonce=tokenlib.new_nonce(),
            one_time=False,
            kid=ACTIVE_KID,
        )
        payload.update(overrides)
        # kid=None means a genuinely kid-less legacy token, not {"kid": null}.
        if payload.get("kid") is None:
            payload.pop("kid", None)
        return payload

    def test_34_issued_token_carries_active_kid_in_signed_payload(self):
        data = self.issue()
        self.assertEqual(data["kid"], ACTIVE_KID)
        payload_b = base64.urlsafe_b64decode(data["token"].split(".")[0] + "==")
        self.assertEqual(json.loads(payload_b)["kid"], ACTIVE_KID)

        resp = self.verify(data["token"])
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["kid"], ACTIVE_KID)

    def test_35_rotated_old_key_still_verifies_unexpired_tokens(self):
        # A token signed by the secondary ring entry (the previous active key).
        issued = tokenlib.issue_token(
            app.state.settings.keyring,
            method="GET",
            path="/files/hello.txt",
            ttl_seconds=120,
            kid=OLD_KID,
        )
        self.assertEqual(issued.kid, OLD_KID)
        resp = self.verify(issued.token)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["kid"], OLD_KID)

        # And it works against the real download endpoint too.
        issued2 = tokenlib.issue_token(
            app.state.settings.keyring,
            method="GET",
            path="/files/hello.txt",
            ttl_seconds=120,
            kid=OLD_KID,
        )
        resp = self.client.get(f"/files/hello.txt?token={issued2.token}")
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_36_unknown_kid_is_rejected_unknown_key_without_probing(self):
        # Claims a kid the ring does not contain; signature is irrelevant —
        # no key may be tried. Must fail before/without a signature check.
        token = self._raw_token(self._payload(kid=UNKNOWN_KID), b"some-outsider-secret")
        resp = self.verify(token)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "unknown_key")

        # Same guarantee on the guarded download endpoint.
        resp = self.client.get(f"/files/hello.txt?token={token}")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "unknown_key")

    def test_37_removing_old_key_rejects_its_tokens_immediately(self):
        from dataclasses import replace

        settings = app.state.settings
        issued = tokenlib.issue_token(
            settings.keyring,
            method="GET",
            path="/files/hello.txt",
            ttl_seconds=120,
            kid=OLD_KID,
        )
        self.assertEqual(self.verify(issued.token).status_code, 200)

        # Simulate redeploying with the old entry removed from the ring.
        shrunk = Keyring((settings.keyring.entries[0],), legacy_secret=LEGACY_SECRET)
        app.state.settings = replace(settings, keyring=shrunk)
        try:
            resp = self.verify(issued.token)
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.json()["error"], "unknown_key")
        finally:
            app.state.settings = settings

    def test_38_legacy_kidless_token_verifies_only_with_legacy_secret(self):
        # A token issued before key-ring support: no kid claim, signed with
        # what is now CAPABILITY_LEGACY_SECRET.
        token = self._raw_token(self._payload(kid=None), LEGACY_SECRET)
        resp = self.verify(token)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertIsNone(resp.json()["kid"])

    def test_39_kidless_token_rejected_when_no_legacy_secret(self):
        from dataclasses import replace

        settings = app.state.settings
        token = self._raw_token(self._payload(kid=None), LEGACY_SECRET)
        ring_without_legacy = Keyring(settings.keyring.entries, legacy_secret=None)
        app.state.settings = replace(settings, keyring=ring_without_legacy)
        try:
            resp = self.verify(token)
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.json()["error"], "unknown_key")
        finally:
            app.state.settings = settings

    def test_40_ring_is_never_walked_for_kidless_tokens(self):
        # A kid-less token signed with an actual RING key must NOT verify:
        # key selection routes kid-less tokens to the legacy secret only,
        # so the HMAC differs -> bad_signature, never a ring trial success.
        token = self._raw_token(self._payload(kid=None), b"old-secret")
        resp = self.verify(token)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "bad_signature")

    def test_41_kid_is_signed_so_switching_it_breaks_the_mac(self):
        issued = tokenlib.issue_token(
            app.state.settings.keyring,
            method="GET",
            path="/files/hello.txt",
            ttl_seconds=120,
            kid=OLD_KID,
        )
        payload_part, sig_part = issued.token.split(".")
        raw = json.loads(base64.urlsafe_b64decode(payload_part + "=="))
        # Attacker relabels the token to the active kid without re-signing.
        raw["kid"] = ACTIVE_KID
        token = f"{_b64(json.dumps(raw, sort_keys=True, separators=(',', ':')).encode())}.{sig_part}"
        resp = self.verify(token)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "bad_signature")

    def test_42_full_rotation_is_zero_downtime_then_old_key_dropped(self):
        from dataclasses import replace

        settings = app.state.settings
        # Tokens in flight before the rotation: active and old.
        pre_active = self.issue()["token"]
        pre_old = tokenlib.issue_token(
            settings.keyring,
            method="GET",
            path="/files/hello.txt",
            ttl_seconds=120,
            kid=OLD_KID,
        ).token

        # Rotation rollout: prepend the new key, keep both previous keys.
        rotated = Keyring(
            (
                ("ring-2026-09", b"new-secret"),
                (ACTIVE_KID, b"active-secret"),
                (OLD_KID, b"old-secret"),
            ),
            legacy_secret=LEGACY_SECRET,
        )
        app.state.settings = replace(settings, keyring=rotated)
        try:
            # Every previously issued, unexpired token still verifies.
            self.assertEqual(self.verify(pre_active).status_code, 200)
            self.assertEqual(self.verify(pre_old).status_code, 200)
            # New tokens are signed by the new first entry.
            data = self.issue()
            self.assertEqual(data["kid"], "ring-2026-09")
            self.assertEqual(self.verify(data["token"]).status_code, 200)
        finally:
            app.state.settings = settings

        # After the overlap window: drop the oldest key; its tokens die now,
        # the rest keep working.
        dropped = Keyring(
            (("ring-2026-09", b"new-secret"), (ACTIVE_KID, b"active-secret")),
            legacy_secret=LEGACY_SECRET,
        )
        app.state.settings = replace(settings, keyring=dropped)
        try:
            resp = self.verify(pre_old)
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.json()["error"], "unknown_key")
            self.assertEqual(self.verify(pre_active).status_code, 200)
        finally:
            app.state.settings = settings

    def test_42b_non_string_kid_claim_is_bad_payload(self):
        token = self._raw_token(self._payload(kid=123), b"active-secret")
        resp = self.verify(token)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "bad_payload")

    # -- configuration / startup validation -------------------------------

    def test_43_parse_keyring_order_and_colon_secret(self):
        entries = parse_keyring("k1:secret-one, k2 :sec:with:colons ,k3:third")
        self.assertEqual(
            entries,
            (("k1", b"secret-one"), ("k2", b"sec:with:colons"), ("k3", b"third")),
        )
        ring = Keyring(entries)
        self.assertEqual(ring.active_kid, "k1")
        self.assertEqual(ring.active_secret, b"secret-one")
        self.assertEqual(ring.get_secret("k2"), b"sec:with:colons")
        self.assertIsNone(ring.get_secret("nope"))

    def test_44_startup_rejects_bad_keyring_config(self):
        bad_values = [
            "k1:secret,,k2:other",      # empty entry
            "k1:secret,k2",             # missing colon / secret
            "k1:",                      # empty secret
            "k1:secret,k1:other",       # duplicate kid
            ":secret",                  # empty kid
        ]
        for raw in bad_values:
            with self.assertRaises(RuntimeError, msg=raw):
                parse_keyring(raw)

    def test_45_startup_rejects_conflicting_and_rejects_empty_ring(self):
        from app.config import load_settings

        saved = {
            k: os.environ.get(k)
            for k in ("CAPABILITY_KEYRING", "CAPABILITY_SECRET", "CAPABILITY_LEGACY_SECRET")
        }
        try:
            os.environ["CAPABILITY_KEYRING"] = "k1:s1"
            os.environ["CAPABILITY_SECRET"] = "solo-secret"
            with self.assertRaises(RuntimeError):
                load_settings()

            os.environ.pop("CAPABILITY_SECRET", None)
            os.environ["CAPABILITY_KEYRING"] = " , "
            with self.assertRaises(RuntimeError):
                load_settings()
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_46_legacy_single_secret_mode_still_boots_and_verifies(self):
        from dataclasses import replace

        from app.config import DEFAULT_KID, load_settings

        saved = {
            k: os.environ.get(k)
            for k in ("CAPABILITY_KEYRING", "CAPABILITY_SECRET", "CAPABILITY_LEGACY_SECRET")
        }
        old_settings = app.state.settings
        try:
            os.environ.pop("CAPABILITY_KEYRING", None)
            os.environ["CAPABILITY_SECRET"] = "solo-secret"
            os.environ.pop("CAPABILITY_LEGACY_SECRET", None)
            solo = load_settings()
            self.assertEqual(solo.keyring.active_kid, DEFAULT_KID)
            self.assertEqual(solo.keyring.active_secret, b"solo-secret")
            # The same secret implicitly verifies pre-upgrade kid-less tokens.
            self.assertEqual(solo.keyring.legacy_secret, b"solo-secret")

            app.state.settings = solo
            data = self.issue()
            self.assertEqual(data["kid"], DEFAULT_KID)
            self.assertEqual(self.verify(data["token"]).status_code, 200)

            old_token = self._raw_token(self._payload(kid=None), b"solo-secret")
            self.assertEqual(self.verify(old_token).status_code, 200)
        finally:
            app.state.settings = old_settings
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


    # -- delegation ---------------------------------------------------------

    def test_47_delegate_happy_path_response_shape(self):
        root = self.issue(path="/files", ttl_seconds=120, subject="alice")
        resp = self.delegate(root["token"], path="/files/hello.txt", ttl_seconds=60)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["chain_depth"], 2)
        self.assertEqual(body["parent_token_id"], root["token_id"])
        self.assertEqual(body["parent_expires_at"], root["expires_at"])
        self.assertFalse(body["ttl_capped_to_parent"])
        self.assertEqual(body["subject"], "alice")
        self.assertEqual(body["path"], "/files/hello.txt")
        self.assertEqual(body["method"], "GET")
        self.assertEqual(body["constraints"]["path"], "/files/hello.txt")
        self.assertEqual(body["constraints"]["subject"], "alice")
        # The signed payload embeds the full parent token under "del".
        payload_b = base64.urlsafe_b64decode(body["token"].split(".")[0] + "==")
        payload = json.loads(payload_b)
        self.assertEqual(payload["del"], root["token"])

        # Verification reports depth 2 and the final constraints.
        v = self.verify(body["token"])
        self.assertEqual(v.status_code, 200, v.text)
        vj = v.json()
        self.assertTrue(vj["valid"])
        self.assertEqual(vj["chain_depth"], 2)
        self.assertEqual(vj["constraints"]["path"], "/files/hello.txt")
        self.assertEqual(vj["constraints"]["expires_at"], body["expires_at"])

        # Plain root tokens still report depth 1 and constraints.
        v0 = self.verify(root["token"], path="/files")
        self.assertEqual(v0.json()["chain_depth"], 1)

    def test_48_delegate_ttl_is_capped_to_parent_remaining_life(self):
        root = self.issue(path="/files", ttl_seconds=30)
        resp = self.delegate(root["token"], path="/files/hello.txt", ttl_seconds=3600)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertTrue(body["ttl_capped_to_parent"])
        self.assertLessEqual(body["expires_at"], root["expires_at"])
        self.assertLessEqual(body["expires_in"], 30)

    def test_49_delegate_path_must_be_under_parent(self):
        root = self.issue(path="/files", ttl_seconds=60)
        # Same prefix but different segment is denied.
        resp = self.delegate(root["token"], path="/files-evil/x")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "path_mismatch")
        # Outside entirely.
        resp = self.delegate(root["token"], path="/admin")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "path_mismatch")
        # Sub-path and the exact path are fine.
        for ok_path in ("/files/hello.txt", "/files"):
            self.assertEqual(
                self.delegate(root["token"], path=ok_path).status_code, 200, ok_path
            )

    def test_50_delegate_method_and_subject_must_match(self):
        root = self.issue(path="/files", ttl_seconds=60, subject="alice")
        resp = self.delegate(root["token"], method="POST", path="/files/x")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "method_mismatch")
        resp = self.delegate(root["token"], path="/files/x", subject="bob")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "delegation_denied")
        # Omitting subject inherits the parent's; repeating it identically works.
        self.assertEqual(
            self.delegate(root["token"], path="/files/x").json()["subject"], "alice"
        )
        self.assertEqual(
            self.delegate(root["token"], path="/files/y", subject="alice").status_code, 200
        )

    def test_51_delegate_invalid_parent_is_rejected(self):
        # Malformed parent.
        resp = self.delegate("not-a-token", path="/files/x")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "malformed")
        # Method-unrelated check still validates the parent on its own terms:
        # an unrelated token signed properly but bound elsewhere is valid as a
        # parent, but cannot cover the requested path.
        other = self.issue(path="/other", ttl_seconds=60)
        resp = self.delegate(other["token"], path="/files/x")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "path_mismatch")

    def test_52_chain_depth_limit_four(self):
        # Build a legal chain root..depth4 through the HTTP API.
        current = self.issue(path="/files", ttl_seconds=300)["token"]
        for depth in range(2, 5):
            resp = self.delegate(current, path="/files/hello.txt", ttl_seconds=60)
            self.assertEqual(resp.status_code, 200, f"depth {depth}: {resp.text}")
            self.assertEqual(resp.json()["chain_depth"], depth)
            current = resp.json()["token"]
        # The fifth delegation is refused at issuance.
        resp = self.delegate(current, path="/files/hello.txt", ttl_seconds=10)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "chain_too_deep")
        # The depth-4 token still verifies and downloads.
        self.assertEqual(self.verify(current).status_code, 200)
        dl = self.client.get(f"/files/hello.txt?token={current}")
        self.assertEqual(dl.status_code, 200, dl.text)
        self.assertEqual(dl.headers["X-Capability-Chain-Depth"], "4")

    def test_53_forged_fifth_layer_is_rejected_at_verify(self):
        # A validly signed but over-deep chain cannot be presented directly.
        current = self.issue(path="/files", ttl_seconds=300)["token"]
        for _ in range(3):
            current = self.delegate(current, path="/files/hello.txt", ttl_seconds=60).json()[
                "token"
            ]
        # Hand-mint a well-formed child of the depth-4 token with the real key.
        depth4_parent = current
        now = int(time.time())
        payload = tokenlib.build_payload(
            method="GET",
            path="/files/hello.txt",
            expires_at=now + 30,
            issued_at=now,
            nonce=tokenlib.new_nonce(),
            one_time=False,
            kid=ACTIVE_KID,
            delegated_from=depth4_parent,
        )
        token = self._raw_token(payload, b"active-secret")
        resp = self.verify(token)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "chain_too_deep")

    def test_54_recursive_checks_expired_or_tampered_ancestor(self):
        settings = app.state.settings
        now = int(time.time())
        # Parent that has expired by now.
        expired = tokenlib.issue_token(
            settings.keyring,
            method="GET",
            path="/files",
            ttl_seconds=10,
            subject="alice",
            now=now - 30,
        )
        resp = self.delegate(expired.token, path="/files/hello.txt", ttl_seconds=10)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "expired")

        # Tamper the embedded parent inside an otherwise valid child: the
        # child's HMAC still covers the (now altered) "del" string, so we must
        # rebuild the child signature after changing it — which proves the
        # chain walk catches an invalid embedded token.
        root = tokenlib.issue_token(
            settings.keyring, method="GET", path="/files", ttl_seconds=120, subject="alice"
        )
        child = self.delegate_core(root.token, path="/files/hello.txt", ttl_seconds=60).issued
        payload = dict(child.payload)
        payload["del"] = payload["del"].replace(payload["del"][0], "X", 1)
        forged = self._raw_token(payload, b"active-secret")
        resp = self.verify(forged)
        self.assertEqual(resp.status_code, 401)
        self.assertIn(resp.json()["error"], ("malformed", "bad_signature", "bad_payload"))

    def test_55_child_outliving_parent_is_rejected_even_if_signed(self):
        settings = app.state.settings
        now = int(time.time())
        parent = tokenlib.issue_token(
            settings.keyring, method="GET", path="/files", ttl_seconds=10, subject="alice"
        )
        # Forge a child signed by the active key that lives longer than parent.
        payload = tokenlib.build_payload(
            method="GET",
            path="/files/hello.txt",
            expires_at=now + 300,
            issued_at=now,
            nonce=tokenlib.new_nonce(),
            one_time=False,
            kid=ACTIVE_KID,
            subject="alice",
            delegated_from=parent.token,
        )
        forged = self._raw_token(payload, b"active-secret")
        resp = self.verify(forged)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "delegation_denied")

    def test_56_revoked_parent_invalidates_children(self):
        subject = "del-revo"
        root = self.issue(path="/files", ttl_seconds=600, subject=subject)
        child = self.delegate(root["token"], path="/files/hello.txt", ttl_seconds=60).json()
        # Both work initially.
        self.assertEqual(self.verify(root["token"], path="/files").status_code, 200)
        self.assertEqual(self.verify(child["token"]).status_code, 200)
        # Revoke the subject: the whole chain dies.
        self.revoke(subject, cutoff=int(time.time()) + 5)
        self.assertEqual(self.verify(root["token"], path="/files").status_code, 401)
        resp = self.verify(child["token"])
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "subject_revoked")
        # Restore and both work again (checks never burn nonces for multi-use).
        self.revoke(subject, restore=True)
        self.assertEqual(self.verify(child["token"]).status_code, 200)

    def test_57_one_time_parent_makes_whole_chain_single_use(self):
        root = self.issue(path="/files", ttl_seconds=300, one_time=True, subject="ot-del")
        child = self.delegate(root["token"], path="/files/hello.txt", ttl_seconds=60).json()
        self.assertTrue(child["one_time"])
        # Dry run burns nothing.
        self.assertEqual(self.verify(child["token"], consume=False).status_code, 200)
        # First real use consumes every one-time nonce in the chain.
        first = self.verify(child["token"])
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.json()["consumed"])
        self.assertEqual(self.verify(child["token"]).status_code, 401)
        # The parent cannot be replayed either — no privilege widening.
        resp = self.verify(root["token"], path="/files")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json()["error"], "nonce_replayed")

    def test_58_delegated_download_serves_and_checks_chain(self):
        root = self.issue(path="/files", ttl_seconds=120, subject="dl-del")
        child = self.delegate(root["token"], path="/files/hello.txt", ttl_seconds=60).json()
        resp = self.client.get(f"/files/hello.txt?token={child['token']}")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertIn("hello capability world", resp.text)
        self.assertEqual(resp.headers["X-Capability-Chain-Depth"], "2")
        # A child bound to a sub-path cannot download elsewhere.
        root2 = self.issue(path="/files", ttl_seconds=120)
        child2 = self.delegate(root2["token"], path="/files/hello.txt", ttl_seconds=60).json()
        resp = self.client.get(f"/files/other.txt?token={child2['token']}")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json()["error"], "path_mismatch")

    def test_59_delegate_requires_ttl_and_validates_request(self):
        root = self.issue(path="/files", ttl_seconds=120)
        base = {"parent_token": root["token"], "method": "GET", "path": "/files/x"}
        # Missing ttl_seconds -> 422.
        resp = self.client.post("/tokens/delegate", json=base)
        self.assertEqual(resp.status_code, 422)
        # ttl <= 0 -> 422.
        resp = self.client.post("/tokens/delegate", json={**base, "ttl_seconds": 0})
        self.assertEqual(resp.status_code, 422)
        # path without leading slash -> 422.
        resp = self.client.post(
            "/tokens/delegate", json={**base, "path": "files/x", "ttl_seconds": 10}
        )
        self.assertEqual(resp.status_code, 422)
        # Missing parent token -> 422.
        resp = self.client.post(
            "/tokens/delegate",
            json={"method": "GET", "path": "/files/x", "ttl_seconds": 10},
        )
        self.assertEqual(resp.status_code, 422)

    def test_60_path_within_helper_is_segment_aware(self):
        self.assertTrue(tokenlib.path_is_within("/files/a", "/files"))
        self.assertTrue(tokenlib.path_is_within("/files", "/files"))
        self.assertTrue(tokenlib.path_is_within("/anything", "/"))
        self.assertFalse(tokenlib.path_is_within("/files-evil", "/files"))
        self.assertFalse(tokenlib.path_is_within("/filesx", "/files"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
