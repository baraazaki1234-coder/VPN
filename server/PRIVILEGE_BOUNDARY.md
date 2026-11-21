# Restricted WireGuard helper deployment

The API process must run as an unprivileged account named `simplevpn`. It must
not run as root and must not have direct access to the WireGuard device or
configuration. The API invokes only the root-owned helper at
`/usr/local/sbin/simplevpn-wg-helper` through non-interactive sudo.

## Install the helper

From a trusted checkout on the Linux server:

```sh
sudo install -o root -g root -m 0755 server/wg_helper.py /usr/local/sbin/simplevpn-wg-helper
sudo install -o root -g root -m 0440 server/simplevpn-control-plane.sudoers /etc/sudoers.d/simplevpn-control-plane
sudo visudo -cf /etc/sudoers.d/simplevpn-control-plane
```

Confirm that the actual WireGuard binary is `/usr/bin/wg`; if not, update
`WG_BIN` in the helper source before installing it. The helper is deliberately
not configurable through the API environment. Its root-owned file and parent
directories must not be writable by the API account.

The sudoers rule permits invoking this one helper with arguments. This is safe
only because the helper accepts a fixed operation allowlist, validates the
interface name, canonical Wireguard public key, and single IPv4 peer address,
and constructs the final argument vector itself. It never invokes a shell and
never accepts arbitrary WireGuard subcommands. Do not broaden the rule to
`NOPASSWD: ALL`, a shell, Python, or the `wg` binary itself.

## API service account

Run the FastAPI service as the dedicated unprivileged `simplevpn` account.
Set these environment values in its protected environment file:

```ini
WG_HELPER=/usr/local/sbin/simplevpn-wg-helper
SUDO_BIN=/usr/bin/sudo
```

The account needs write access only to its SQLite state directory and read
access to its environment file. It should not own the helper, sudoers file,
WireGuard configuration, or server private key. Keep the environment file
root-owned and readable only by root and the service account.

The peer restoration oneshot is a separate boot-time service and may retain
its narrowly scoped root execution because it reads the protected database and
re-adds stored peers after `wg0` starts. It is not the network-facing API.

## Verification before public exposure

1. Run `python -m unittest discover -s tests` from `server/`.
2. Verify the API account cannot execute `wg` directly.
3. Verify it can invoke only the installed helper through `sudo -n`.
4. Test enroll, list, and revoke against a disposable WireGuard interface.
5. Keep the API bound to localhost behind a correctly configured HTTPS reverse
   proxy, and add host firewall restrictions and administrative audit logging.

This helper narrows the privilege boundary; it does not configure WireGuard,
UDP reachability, forwarding, NAT, DNS, or prove end-to-end VPN connectivity.
