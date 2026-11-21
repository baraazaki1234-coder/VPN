"""Tests for the narrow privileged WireGuard helper command allowlist."""
import base64
import unittest

from wg_helper import build_command, WG_BIN


class WireGuardHelperTests(unittest.TestCase):
    def setUp(self):
        self.key = base64.b64encode(b"k" * 32).decode("ascii")

    def test_show_operations_are_fixed(self):
        self.assertEqual(build_command(["show-interface", "wg0"]),
                         [WG_BIN, "show", "wg0"])
        self.assertEqual(build_command(["show-dump", "wg0"]),
                         [WG_BIN, "show", "wg0", "dump"])

    def test_add_peer_only_accepts_single_ipv4_host(self):
        self.assertEqual(build_command(["add-peer", "wg0", self.key, "10.77.0.9"]),
                         [WG_BIN, "set", "wg0", "peer", self.key,
                          "allowed-ips", "10.77.0.9/32"])

    def test_remove_peer_is_fixed(self):
        self.assertEqual(build_command(["remove-peer", "wg0", self.key]),
                         [WG_BIN, "set", "wg0", "peer", self.key, "remove"])

    def test_rejects_arbitrary_operations_and_extra_arguments(self):
        for args in (["syncconf", "wg0", "/tmp/file"],
                     ["show-interface", "wg0", "extra"],
                     ["add-peer", "wg0", self.key, "10.0.0.1", "extra"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                build_command(args)

    def test_rejects_invalid_interface(self):
        with self.assertRaises(ValueError):
            build_command(["show-interface", "wg0;id"])

    def test_rejects_invalid_public_key(self):
        with self.assertRaises(ValueError):
            build_command(["remove-peer", "wg0", "not-a-key"])

    def test_rejects_ipv6_and_invalid_peer_address(self):
        for address in ("2001:db8::1", "10.77.0.1/24", "not-an-ip"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                build_command(["add-peer", "wg0", self.key, address])


if __name__ == "__main__":
    unittest.main()
