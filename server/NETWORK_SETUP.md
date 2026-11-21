# Linux WireGuard data-plane setup checklist

The control plane and Android client do not replace the Linux WireGuard data plane. Configure a real Linux host with a reachable UDP port and a WireGuard interface before attempting to connect clients.

## Required interface properties

The enrollment API currently gives clients an IPv4-only default route (`0.0.0.0/0`). This is intentional: do not add `::/0` until IPv6 forwarding, firewalling, and return routing are configured and tested.

- Create `wg0` with the server private key stored only on the server.
- Use a private VPN subnet matching `VPN_NETWORK` (default `10.77.0.0/24`).
- Assign the server an address such as `10.77.0.1/24`; do not allocate that address to a client.
- Listen on the UDP port used in `WG_ENDPOINT`.
- Allow the UDP listener through the host firewall and any router/firewall in front of the host.
- Enable IPv4 forwarding.
- Configure forwarding from `wg0` to the selected internet uplink and return traffic from the uplink to `wg0`.
- Configure source NAT/masquerading for the VPN subnet on the internet uplink. Keep firewall rules scoped to the VPN subnet and required interfaces.
- Provide a DNS resolver reachable at `VPN_DNS` from the VPN subnet. Do not advertise a DNS address that is not actually listening and reachable.
- Configure IPv6 deliberately. Until IPv6 forwarding and firewall policy are configured, do not advertise an IPv6 default route to clients.

## Peer persistence

The enrollment API adds peers to the live WireGuard interface. `restore_peers.py` re-adds all non-revoked database peers after `wg0` starts. Install `simplevpn-restore-peers.service` after adjusting its paths and interface dependency to match the host.

Example environment file location: `/etc/simplevpn/control-plane.env`. Restrict it to root and the service account that needs the settings. Never put server private keys or the admin key in the Android app or Git.

## Control-plane unit tests

From this directory, install `requirements.txt`, then run:

```sh
python -m unittest discover -s tests
```

These focused tests cover enrollment success, invitation expiry, public-key validation, and the IPv4-only route contract. They do not replace a live WireGuard integration test.

## Routing and NAT verification

Before enabling Android lockdown, test with one authorized device:
1. Confirm a recent WireGuard handshake.
2. Confirm the device can reach the VPN gateway address.
3. Confirm DNS queries reach the configured resolver through the tunnel.
4. Confirm IPv4 internet routing works and the observed public egress address belongs to the VPN server's uplink.
5. Confirm return traffic is routed to the correct peer.
6. Disconnect the tunnel and verify Android lockdown blocks non-VPN traffic.

This repository does not install firewall/NAT rules automatically. Exact firewall commands depend on the Linux distribution, firewall manager, and uplink interface; avoid mixing unmanaged iptables/nftables rules with an existing firewall configuration.


## Configuration templates

This directory includes starter files, not a turnkey server installer:

- `wg0.conf.example`: WireGuard interface skeleton. Replace the private-key placeholder on the server only.
- `vpn.env.example`: control-plane environment template. Generate a fresh random admin secret and keep the real file outside Git.
- `sysctl.d/99-simplevpn.conf`: enables IPv4 forwarding. Review local policy before installing.

Suggested preparation (review paths and ownership for your distribution):

1. Create a dedicated `simplevpn` service account and protected state directory.
2. Copy the example environment file to `/etc/simplevpn/control-plane.env`, replace all placeholders, and restrict access (for example, root-owned mode `0600`).
3. Create the WireGuard server keypair on the Linux host and place only its private key in the host's protected WireGuard configuration.
4. Install the sysctl snippet only after confirming that this host is intended to route traffic; then apply it using your distribution's normal sysctl procedure.
5. Configure the firewall/NAT and a real DNS resolver separately. The example intentionally does not guess your WAN interface or overwrite firewall rules.

The API currently invokes `wg` directly. Do not expose the API to the public internet or run it as an unrestricted privileged service. Before production deployment, replace direct command execution with a narrowly scoped privileged helper, add rate limiting and audit logging, and put the API behind HTTPS. The admin dashboard is not an authentication substitute; protect it at the reverse proxy as well.

The readiness endpoint checks that WireGuard responds, IPv4 forwarding is enabled, and the configured DNS address answers a small UDP query. It does **not** validate NAT, firewall policy, public routing, or end-to-end client traffic.
