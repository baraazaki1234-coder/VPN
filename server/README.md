# Novra VPN server

The server component is not deployed yet.

A standard WireGuard server needs a reachable UDP endpoint. A free Cloudflare Worker URL is not itself a WireGuard UDP server. A home Linux machine may be used for a private test if it remains online and the network owner allows inbound UDP forwarding; otherwise a suitable server host is required.

The Android app expects a normal WireGuard client profile. Keep private keys private, never commit generated `.conf` files or private keys to this repository, and only configure machines and networks you own or are authorized to administer.

See [the architecture plan](../docs/ARCHITECTURE.md) for the required verification gates.
