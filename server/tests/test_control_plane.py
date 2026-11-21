"""Focused control-plane tests; run with: python -m unittest discover -s tests"""
import base64
import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

_TEMP = tempfile.TemporaryDirectory()
os.environ["VPN_DB_PATH"] = str(Path(_TEMP.name) / "control.db")
os.environ["WG_ENDPOINT"] = "vpn.example.invalid:51820"
os.environ["WG_SERVER_PUBLIC_KEY"] = base64.b64encode(b"s" * 32).decode()
os.environ["VPN_ADMIN_KEY"] = "test-admin-key-for-unit-tests-only-32"

import control_plane as cp  # noqa: E402


class ControlPlaneTests(unittest.TestCase):
    def setUp(self):
        with cp.db() as conn:
            conn.execute("DELETE FROM devices")
            conn.execute("DELETE FROM invites")

    def add_invite(self, token, expires=None):
        with cp.db() as conn:
            conn.execute(
                "INSERT INTO invites(token_hash, expires_at) VALUES (?, ?)",
                (hashlib.sha256(token.encode()).hexdigest(),
                 expires if expires is not None else int(time.time()) + 60),
            )

    def test_enrollment_adds_only_ipv4_default_route(self):
        token = "invite-token-for-unit-test-0001-extra"
        public_key = base64.b64encode(b"p" * 32).decode()
        self.add_invite(token)
        with patch.object(cp, "wg") as wg_mock:
            result = cp.enroll(cp.EnrollRequest(
                invitation=token, device_name="Test phone", public_key=public_key
            ))
        self.assertEqual(result["allowed_ips"], "0.0.0.0/0")
        self.assertEqual(result["assigned_address"].count("/32"), 1)
        wg_mock.assert_called_once_with(
            "set", cp.WG_INTERFACE, "peer", public_key,
            "allowed-ips", result["assigned_address"]
        )
        with cp.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 1)
            self.assertIsNotNone(conn.execute(
                "SELECT used_at FROM invites"
            ).fetchone()[0])

    def test_expired_invitation_is_rejected_without_adding_peer(self):
        token = "invite-token-for-unit-test-0002-extra"
        self.add_invite(token, expires=int(time.time()) - 1)
        public_key = base64.b64encode(b"q" * 32).decode()
        with patch.object(cp, "wg") as wg_mock:
            with self.assertRaises(cp.HTTPException) as caught:
                cp.enroll(cp.EnrollRequest(
                    invitation=token, device_name="Expired", public_key=public_key
                ))
        self.assertEqual(caught.exception.status_code, 403)
        wg_mock.assert_not_called()

    def test_data_plane_readiness_requires_interface_forwarding_and_dns(self):
        completed = type("Completed", (), {"stdout": "1"})()
        with patch.object(cp.subprocess, "run", return_value=completed), \
             patch.object(cp, "check_dns_resolver", return_value=True):
            status = cp.data_plane_status()
        self.assertEqual(status["status"], "ready")
        self.assertTrue(all(status["checks"].values()))

    def test_data_plane_readiness_reports_missing_forwarding(self):
        completed = type("Completed", (), {"stdout": "0"})()
        with patch.object(cp.subprocess, "run", return_value=completed), \
             patch.object(cp, "check_dns_resolver", return_value=True):
            status = cp.data_plane_status()
        self.assertEqual(status["status"], "not_ready")
        self.assertFalse(status["checks"]["ipv4_forwarding"])

    def test_invalid_wireguard_public_key_is_rejected(self):
        with self.assertRaises(cp.HTTPException) as caught:
            cp.enroll(cp.EnrollRequest(
                invitation="invite-token-for-unit-test-0003-extra",
                device_name="Bad key",
                public_key=base64.b64encode(b"x" * 31).decode(),
            ))
        self.assertEqual(caught.exception.status_code, 400)


    def test_enrollment_rate_limit_allows_ten_attempts_then_blocks(self):
        with cp.db() as conn:
            conn.execute("DELETE FROM enrollment_rate_limits")
        for attempt in range(cp.ENROLLMENT_RATE_MAX):
            self.assertTrue(cp.record_enrollment_attempt("192.0.2.10", now=1000 + attempt))
        self.assertFalse(cp.record_enrollment_attempt("192.0.2.10", now=1010))

    def test_enrollment_rate_limit_resets_after_window(self):
        with cp.db() as conn:
            conn.execute("DELETE FROM enrollment_rate_limits")
        for attempt in range(cp.ENROLLMENT_RATE_MAX + 1):
            cp.record_enrollment_attempt("192.0.2.11", now=1000 + attempt)
        self.assertTrue(cp.record_enrollment_attempt(
            "192.0.2.11", now=1000 + cp.ENROLLMENT_RATE_WINDOW
        ))

    def test_enrollment_rate_limits_are_separate_per_source(self):
        with cp.db() as conn:
            conn.execute("DELETE FROM enrollment_rate_limits")
        for attempt in range(cp.ENROLLMENT_RATE_MAX + 1):
            cp.record_enrollment_attempt("192.0.2.12", now=2000 + attempt)
        self.assertTrue(cp.record_enrollment_attempt("192.0.2.13", now=2010))

    def test_admin_key_requires_at_least_32_utf8_bytes(self):
        with self.assertRaises(RuntimeError):
            cp.load_admin_key("too-short")
        self.assertEqual(
            cp.load_admin_key("a" * 32),
            "a" * 32,
        )

    def test_admin_readiness_endpoint_requires_admin_key(self):
        with self.assertRaises(cp.HTTPException) as caught:
            cp.admin_data_plane_health(x_admin_key=None)
        self.assertEqual(caught.exception.status_code, 401)

    def test_admin_readiness_endpoint_returns_data_plane_checks(self):
        expected = {
            "status": "not_ready",
            "checks": {
                "wireguard_interface": False,
                "ipv4_forwarding": True,
                "dns_resolver": True,
            },
            "note": "test note",
        }
        with patch.object(cp, "data_plane_status", return_value=expected):
            result = cp.admin_data_plane_health(x_admin_key="test-admin-key-for-unit-tests-only-32")
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
