# Architecture and delivery plan

## Client

The Android app is a native Kotlin application. It imports a standard WireGuard profile, validates it with the official WireGuard tunnel parser, and asks Android to authorize the VPN service before activating the userspace WireGuard backend.

## Server

A working tunnel also requires a reachable WireGuard server listening on UDP. The Android client alone cannot create an internet exit node. The server must have:
- A public or otherwise reachable UDP endpoint.
- IP forwarding and NAT configured for the chosen egress interface.
- A unique server key and a separate client key.
- A peer entry matching the client's public key and tunnel address.

A computer on a home network can be used only if it stays online and the network/router permits inbound UDP forwarding. Do not expose a machine or change router settings without the owner's permission.

## Verification gates

The app's local state changing to “connected” means the Android backend accepted the tunnel configuration. It does not prove that the remote server is reachable or that traffic is exiting through it. Before calling the VPN operational, verify:
1. A recent WireGuard handshake with the server.
2. Bidirectional transfer counters increase.
3. DNS resolution works through the intended route.
4. IPv4 and IPv6 routing do not leak traffic outside the tunnel.
5. Disconnect restores normal network routing.

## Milestones

- [x] Native Android project foundation.
- [x] Import and parse WireGuard profiles.
- [x] WireGuard backend and Android VPN permission flow.
- [ ] Persistent tunnel lifecycle and visible connection statistics.
- [ ] Server-side provisioning for a machine the owner controls.
- [ ] End-to-end connectivity and leak testing.
- [ ] Build APK only after the user explicitly asks for a build.
