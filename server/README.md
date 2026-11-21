# VPN server

The Android client uses the official WireGuard tunnel library. A real Linux WireGuard endpoint is required; this folder includes a small control-plane API foundation in `control_plane.py`.

See [CONTROL_PLANE.md](CONTROL_PLANE.md) for enrollment, one-time invitations, device administration, and deployment requirements.

The control plane does not deploy a server, configure NAT/DNS/firewall automatically, or persist peers across server reboot yet. Do not expose it publicly without HTTPS, a dedicated least-privilege WireGuard helper, rate limiting, and audit logging.
