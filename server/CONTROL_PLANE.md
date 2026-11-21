# Control plane and enrollment

This is a self-hosted control-plane foundation for a standard WireGuard server. It does not create a VPN server by itself and it does not make a Cloudflare Worker into a UDP endpoint.

## Security model

- WireGuard is the data plane: UDP transport, authenticated encryption, peer public-key identity, replay protection, and packet integrity are handled by WireGuard. Do not add a custom encryption envelope around WireGuard packets.
- Each Android device must generate its Wireguard private key locally. Only its public key is sent to `POST /v1/enroll`; the private key must never leave Android.
- An invitation is a random one-time bearer token. Only its SHA-256 hash is stored; it expires after 900 seconds and can be consumed once.
- The server allocates one /32 address and adds the public key to the existing `wg0` interface.
- The response includes public connection parameters only. Android combines them with its locally held private key to build the client profile.
- The admin API uses a separate `VPN_ADMIN_KEY`. Keep it out of the Android app, URLs, logs, source control, and browser local storage. Use HTTPS and a strong random value.

## Environment

Required environment variables:

- `WG_ENDPOINT`: public hostname or IP and UDP port, e.g. `vpn.example.net:51820`
- `WG_SERVER_PUBLIC_KEY`: public key for the server peer
- `VPN_ADMIN_KEY`: independent high-entropy administration secret
- `VPN_NETWORK`: address pool, default `10.77.0.0/24`
- `VPN_DNS`: DNS resolver reachable through the tunnel, default `10.77.0.1`
- `WG_INTERFACE`: WireGuard interface, default `wg0`
- `VPN_DB_PATH`: SQLite database path

Run behind a TLS reverse proxy, with the service user restricted to only the required WireGuard operations. The simple subprocess integration currently invokes `wg`; production deployment should constrain privileges with a dedicated privileged helper or tightly scoped sudoers rule rather than running the whole web process as root.

## Run

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn control_plane:app --host 127.0.0.1 --port 8080
```

Open `/admin` through the HTTPS reverse proxy. The admin page keeps the key only in the current page memory. Create an invitation and enter it in a future Android enrollment screen.

## API

- `POST /v1/admin/invites` with `X-Admin-Key`; returns a one-time invitation.
- `POST /v1/enroll` with invitation, device name, and WireGuard public key.
- `GET /v1/admin/devices` with `X-Admin-Key`; lists enrolled peers.
- `POST /v1/admin/devices/{id}/revoke` with `X-Admin-Key`; removes the peer from the live interface.

## Important remaining work

- The Android enrollment UI and local WireGuard key generation/profile assembly are not connected to this API yet.
- Configure the server's WireGuard interface, forwarding, firewall, NAT/masquerading, and DNS resolver separately.
- Persist peers into the server's WireGuard configuration so they survive reboot; this initial API currently updates the live interface only.
- Add rate limiting, audit logs, backup/restore, key rotation, and a dedicated privilege boundary before exposing this service publicly.
- The device API and dashboard expose per-peer byte counters and latest handshake from `wg show`; refresh the page to update them. Counters are cumulative for the currently loaded interface and may reset when the interface is recreated.
- Do not enable Android lockdown until a real server is configured and the full route and DNS path have been tested.
