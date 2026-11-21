"""Regression checks for the hardened control-plane systemd unit."""
import configparser
import unittest
from pathlib import Path


class ControlPlaneServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.unit_path = Path(__file__).resolve().parents[1] / "simplevpn-control-plane.service"
        cls.unit = configparser.ConfigParser(interpolation=None, strict=False)
        with cls.unit_path.open(encoding="utf-8") as handle:
            cls.unit.read_file(handle)

    def test_api_runs_as_unprivileged_service_account(self):
        self.assertEqual(self.unit["Service"]["User"], "simplevpn")
        self.assertEqual(self.unit["Service"]["Group"], "simplevpn")
        self.assertNotEqual(self.unit["Service"]["User"], "root")

    def test_api_binds_only_to_loopback(self):
        command = self.unit["Service"]["ExecStart"]
        self.assertIn("--host 127.0.0.1", command)
        self.assertNotIn("--host 0.0.0.0", command)

    def test_service_filesystem_is_restricted(self):
        service = self.unit["Service"]
        self.assertEqual(service["ProtectSystem"], "strict")
        self.assertEqual(service["ProtectHome"], "true")
        self.assertEqual(service["PrivateTmp"], "true")
        self.assertEqual(service["ReadWritePaths"], "/var/lib/simplevpn")

    def test_sudo_setuid_exception_is_explicit(self):
        # sudo needs its setuid transition to invoke the single allowlisted
        # root-owned helper; the API process itself remains unprivileged.
        self.assertEqual(self.unit["Service"]["NoNewPrivileges"], "false")


if __name__ == "__main__":
    unittest.main()
