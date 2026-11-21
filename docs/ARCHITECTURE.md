# Architecture and security plan

## Android client

The app is a native Kotlin application using the official WireGuard tunnel library. It imports and parses standard WireGuard profiles, requests Android VPN consent, starts/stops the backend, and displays transfer counters.

## Kill switch

Android owns the Always-on VPN and lockdown controls. The app opens Android VPN settings and explains the two user-controlled options:
1. Always-on VPN for this app.
2. Block connections without VPN.

These controls are not silently enabled by the app. The user should confirm the system settings and test behavior before relying on the protection.

## Real server requirement

A functional VPN requires at least one reachable WireGuard server listening on UDP, with forwarding/NAT and matching client/server peer keys. The app alone is not an internet exit node.

## Automatic endpoint selection

Do not treat Cloudflare or Google public DNS/HTTPS endpoints as VPN servers. They can be used as independent network-quality probes, but traffic can only be routed through an endpoint that actually runs WireGuard and has a matching client profile.

When multiple real WireGuard profiles exist, a safe selector should:
- Measure reachability and handshake recency for each configured peer.
- Compare latency over multiple samples, not one noisy measurement.
- Require a meaningful improvement before switching (hysteresis).
- Avoid rapid oscillation and impose a cooldown after switching.
- Verify the new endpoint's handshake and bidirectional transfer before reporting success.
- Keep the old endpoint until the replacement is confirmed, where backend constraints permit.

A ping to a public DNS server does not measure VPN server latency and must never be presented as a server failover result.

## Verification gates

Before describing the VPN as operational, verify:
- A recent WireGuard handshake.
- Bidirectional transfer counters increase.
- DNS works through the intended tunnel route.
- IPv4 and IPv6 routes do not leak around the tunnel.
- Android lockdown blocks non-VPN traffic when the tunnel is down.
- Disconnect restores ordinary routing.

## Milestones

- [x] Native Android project foundation.
- [x] Import and parse WireGuard profiles.
- [x] Connect/disconnect backend integration.
- [x] Live transfer counters.
- [x] Neutral interface, Arabic/English, dark/light/system settings.
- [x] Shortcut to Android VPN settings for lockdown setup.
- [ ] Real WireGuard server deployment.
- [ ] Multiple real endpoint profiles and measured failover.
- [ ] End-to-end leak and reconnect tests.
- [ ] Build APK only when requested.
