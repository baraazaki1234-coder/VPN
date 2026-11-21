# Network quality and automatic endpoint selection

## What the client can measure

The phone can measure latency and reachability to public HTTPS/DNS test services such as Cloudflare and Google. These measurements describe the current internet path to those services. They do not prove that either service is a WireGuard VPN endpoint, and they do not create an encrypted VPN route through that service.

## What is required for failover

Automatic switching requires at least two real WireGuard servers. Each server needs:
- A reachable UDP endpoint.
- A separate valid client profile/peer configuration.
- Correct routing and DNS settings.
- A health check that confirms a recent WireGuard handshake and traffic transfer.

## Selection policy

Use several samples and compare median latency. Switch only when the candidate is healthy and materially better than the active server. Use a cooldown and hysteresis to avoid frequent switching. Do not switch to a public DNS resolver merely because its ping is lower.

## No fabricated speed claims

A server's ping is not the same as throughput. Real speed testing requires a controlled endpoint and must account for upload/download throughput, packet loss, and stability. Do not claim a speed improvement based on a single ICMP or HTTPS request.
