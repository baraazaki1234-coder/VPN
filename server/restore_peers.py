"""Restore enrolled, non-revoked peers after wg0 is brought up."""
import os
import sqlite3
import subprocess
import sys

DB_PATH = os.getenv("VPN_DB_PATH", "/var/lib/simplevpn/control.db")
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WG_BIN = os.getenv("WG_BIN", "wg")


def main() -> int:
    with sqlite3.connect(DB_PATH, timeout=15) as conn:
        peers = conn.execute(
            "SELECT public_key, address FROM devices WHERE revoked_at IS NULL ORDER BY created_at"
        ).fetchall()
    for public_key, address in peers:
        result = subprocess.run(
            [WG_BIN, "set", WG_INTERFACE, "peer", public_key, "allowed-ips", address + "/32"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode:
            print("Failed to restore a WireGuard peer; check wg permissions and interface.", file=sys.stderr)
            return result.returncode or 1
    print(f"Restored {len(peers)} enrolled WireGuard peers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
