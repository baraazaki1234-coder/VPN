# VPN

A simple native Android WireGuard client.

## Current app features

- Neutral interface without product branding.
- Arabic and English UI.
- Dark and light appearance modes, plus follow-system option.
- Import and validate standard WireGuard `.conf` profiles.
- Save the selected profile in app-private storage.
- Connect/disconnect through Android's VPN consent flow.
- Display live WireGuard transfer counters while the tunnel is active.
- Restore the saved profile when Android starts the VPN service in Always-on mode.
- Shortcut and instructions for Android's Always-on VPN and Block connections without VPN settings.

## Important limitations

This repository does not yet include a VPN server or a pool of VPN endpoints. A valid profile from a reachable WireGuard server is required for actual internet traffic. The app's local tunnel state is not proof of a successful remote handshake or working internet route.

Android controls the Always-on VPN and lockdown switches. The app supports Android's Always-on startup callback and can open the system VPN settings, but the user must enable the switches there. Test lockdown behavior before relying on it.

Automatic server selection will only be implemented for real WireGuard endpoints with valid peer configurations. Public DNS and HTTPS test services such as Google or Cloudflare are useful for measuring general network reachability, but they are not interchangeable WireGuard exit servers.

## Build status

No APK has been built. Build and device testing remain deferred until explicitly requested.
