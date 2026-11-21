#!/usr/bin/env python3
"""Narrow privileged WireGuard command boundary for the unprivileged API."""
import base64
import ipaddress
import re
import subprocess
import sys

WG_BIN = "/usr/bin/wg"
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")


def validate_interface(value):
    if not INTERFACE_RE.fullmatch(value):
        raise ValueError("invalid interface")
    return value


def validate_public_key(value):
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("invalid public key") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("invalid public key")
    return value


def validate_ipv4(value):
    address = ipaddress.ip_address(value)
    if address.version != 4:
        raise ValueError("only IPv4 peer addresses are supported")
    return str(address)


def build_command(argv):
    if not argv:
        raise ValueError("missing operation")
    operation, *args = argv
    if operation in ("show-interface", "show-dump") and len(args) == 1:
        interface = validate_interface(args[0])
        return [WG_BIN, "show", interface] + (["dump"] if operation == "show-dump" else [])
    if operation == "add-peer" and len(args) == 3:
        interface = validate_interface(args[0])
        public_key = validate_public_key(args[1])
        address = validate_ipv4(args[2])
        return [WG_BIN, "set", interface, "peer", public_key, "allowed-ips", address + "/32"]
    if operation == "remove-peer" and len(args) == 2:
        interface = validate_interface(args[0])
        public_key = validate_public_key(args[1])
        return [WG_BIN, "set", interface, "peer", public_key, "remove"]
    raise ValueError("unsupported operation or argument count")


def main(argv=None):
    try:
        command = build_command(list(sys.argv[1:] if argv is None else argv))
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
