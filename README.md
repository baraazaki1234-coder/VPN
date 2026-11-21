# Novra VPN

Native Android WireGuard client foundation.

## Implemented in this branch

- Native Android application (not a WebView/PWA).
- Arabic-first starter interface with Novra branding.
- Imports standard WireGuard `.conf` profiles through Android's document picker.
- Validates the profile with the official WireGuard tunnel parser.
- Stores the selected profile in app-private storage.
- Starts and stops the userspace WireGuard backend through Android's VPN permission flow.

## Important server requirement

This repository does not yet contain a VPN server. A valid peer configuration from a server is required before traffic can pass through a real tunnel. The app must not be described as providing a working internet VPN until a server endpoint is deployed and connectivity, DNS, routing, and handshake behavior are verified.

The tunnel library is published on Maven Central as `com.wireguard.android:tunnel` and is licensed under Apache-2.0. See the [official WireGuard Android project](https://github.com/WireGuard/wireguard-android).

## Build status

No APK has been built. Build and device testing are intentionally deferred.
