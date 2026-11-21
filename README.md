# VPN

A simple native Android WireGuard client with a separate self-hosted Linux control plane.

## Android client

- Neutral interface, Arabic and English.
- Dark, light, and system appearance.
- Import and validate standard WireGuard profiles.
- Connect/disconnect through Android's VPN permission flow.
- Live transfer counters for the active WireGuard tunnel.
- Android Always-on VPN and lockdown setup guidance.

## Network design

WireGuard is the encrypted UDP tunnel. Its standard protocol provides authenticated encryption, peer identity, integrity checks, and replay protection. Network packets are routed through Android's VPN TUN interface; on the server, WireGuard delivers decrypted packets to its TUN interface for routing, firewall policy, DNS, and NAT.

DNS must be configured to use a resolver reachable through the VPN. Android lockdown is controlled by the operating system and must be enabled by the user in Android VPN settings.

## Control plane

The `server/` directory contains an initial FastAPI control plane with 15-minute one-use invitations, server-side IP allocation, public-key enrollment, device listing, traffic counters, and revocation. The Android app has a registration screen that generates the WireGuard key pair locally, sends only the public key over HTTPS, and stores the private key/profile encrypted with Android Keystore AES-GCM. Admin authentication uses a separate secret that must never be embedded in the Android app.

See [server/CONTROL_PLANE.md](server/CONTROL_PLANE.md).

## Not complete / not verified

- No VPN server is deployed or selected.
- Android enrollment is not yet integrated with the API.
- Server NAT, firewall, DNS, peer persistence, and traffic accounting still need implementation.
- Endpoint auto-selection needs multiple real WireGuard servers; public DNS services are not VPN endpoints.
- No APK has been built and no Android device test has been run. Building remains deferred until explicitly requested.
