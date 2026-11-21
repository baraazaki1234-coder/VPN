# VPN server

The Android client uses the official WireGuard tunnel library. A real Linux WireGuard endpoint is required; this folder includes a small control-plane API foundation in `control_plane.py`.

See [CONTROL_PLANE.md](CONTROL_PLANE.md) for enrollment, one-time invitations, device administration, and deployment requirements.

The control plane does not deploy a server or configure NAT/DNS/firewall automatically. `restore_peers.py` and its systemd unit are provided as an untested starting point for restoring enrolled peers after reboot. Enrollment requests have a persistent application-level limit of 10 attempts per source address per 10-minute window. This does not replace edge/proxy rate limiting. Do not expose the API publicly without HTTPS, a dedicated least-privilege WireGuard helper, trusted reverse-proxy configuration, and audit logging. The API refuses to start if `VPN_ADMIN_KEY` is shorter than 32 UTF-8 bytes.


Starter configuration examples are provided in `wg0.conf.example`, `vpn.env.example`, and `sysctl.d/99-simplevpn.conf`. They contain placeholders and must be reviewed for the target Linux host; they do not install firewall/NAT or DNS services.
