import base64
import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
import socket
import sqlite3
import struct
import subprocess
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("VPN_DB_PATH", "/var/lib/simplevpn/control.db")
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WG_ENDPOINT = os.environ["WG_ENDPOINT"]  # public host:UDP port
WG_SERVER_PUBLIC_KEY = os.environ["WG_SERVER_PUBLIC_KEY"]
VPN_NETWORK = ipaddress.ip_network(os.getenv("VPN_NETWORK", "10.77.0.0/24"))
VPN_DNS = os.getenv("VPN_DNS", "10.77.0.1")
VPN_GATEWAY = os.getenv("VPN_GATEWAY", str(next(VPN_NETWORK.hosts())))
def load_admin_key(value: str) -> str:
    if len(value.encode("utf-8")) < 32:
        raise RuntimeError("VPN_ADMIN_KEY must contain at least 32 UTF-8 bytes")
    return value


ADMIN_KEY = load_admin_key(os.environ["VPN_ADMIN_KEY"])
INVITE_TTL = 15 * 60
WG_BIN = os.getenv("WG_BIN", "wg")

app = FastAPI(title="VPN Control Plane", docs_url=None, redoc_url=None)


@contextmanager
def db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS invites (
            token_hash TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL,
            used_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            public_key TEXT NOT NULL UNIQUE,
            address TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            revoked_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS enrollment_rate_limits (
            client_ip TEXT PRIMARY KEY,
            window_started_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL
        );
        """)


init_db()


# Limit unauthenticated invitation guesses per source address. The counter is
# persisted in SQLite so restarting the API does not reset the protection.
ENROLLMENT_RATE_WINDOW = 10 * 60
ENROLLMENT_RATE_MAX = 10


def record_enrollment_attempt(client_ip: str, now: Optional[int] = None) -> bool:
    now = int(time.time()) if now is None else int(now)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO enrollment_rate_limits(client_ip, window_started_at, attempts)
            VALUES (?, ?, 1)
            ON CONFLICT(client_ip) DO UPDATE SET
                window_started_at = CASE
                    WHEN excluded.window_started_at - enrollment_rate_limits.window_started_at >= ?
                    THEN excluded.window_started_at
                    ELSE enrollment_rate_limits.window_started_at
                END,
                attempts = CASE
                    WHEN excluded.window_started_at - enrollment_rate_limits.window_started_at >= ?
                    THEN 1
                    ELSE enrollment_rate_limits.attempts + 1
                END
            """,
            (client_ip, now, ENROLLMENT_RATE_WINDOW, ENROLLMENT_RATE_WINDOW),
        )
        row = conn.execute(
            "SELECT attempts FROM enrollment_rate_limits WHERE client_ip = ?",
            (client_ip,),
        ).fetchone()
        return row["attempts"] <= ENROLLMENT_RATE_MAX


@app.middleware("http")
async def limit_enrollment_requests(request, call_next):
    if request.url.path == "/v1/enroll" and request.method == "POST":
        client_ip = request.client.host if request.client else "unknown"
        if not record_enrollment_attempt(client_ip):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many enrollment attempts; try again later"},
                headers={"Retry-After": str(ENROLLMENT_RATE_WINDOW)},
            )
    return await call_next(request)


def admin_auth(value: Optional[str]):
    if not value or not hmac.compare_digest(value, ADMIN_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")


def valid_public_key(value: str) -> bool:
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == 32 and base64.b64encode(raw).decode() == value
    except Exception:
        return False


def wg(*args: str):
    result = subprocess.run([WG_BIN, *args], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise HTTPException(status_code=502, detail="WireGuard operation failed")


def allocate_ip(conn):
    used = {row["address"] for row in conn.execute("SELECT address FROM devices")}
    for host in VPN_NETWORK.hosts():
        address = str(host)
        if address not in {VPN_DNS, VPN_GATEWAY} and address not in used:
            return address
    raise HTTPException(status_code=409, detail="VPN address pool exhausted")


class InviteRequest(BaseModel):
    label: str = Field(default="New device", min_length=1, max_length=64)


class EnrollRequest(BaseModel):
    invitation: str = Field(min_length=32, max_length=128)
    device_name: str = Field(min_length=1, max_length=64)
    public_key: str = Field(min_length=43, max_length=44)


@app.get("/health")
def health():
    # Liveness only: confirms that the API process can answer requests.
    return {"status": "ok"}


def check_dns_resolver():
    """Send a small DNS A query to the configured resolver over UDP."""
    try:
        resolver = ipaddress.ip_address(VPN_DNS)
        if resolver.version != 4:
            return False
        query_id = secrets.randbelow(65536)
        # QNAME = example.com, QTYPE=A, QCLASS=IN.
        packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        packet += b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2.0)
            sock.sendto(packet, (str(resolver), 53))
            response, _ = sock.recvfrom(2048)
        if len(response) < 12:
            return False
        response_id, flags = struct.unpack("!HH", response[:4])
        return response_id == query_id and bool(flags & 0x8000) and (flags & 0x000F) == 0
    except (OSError, ValueError):
        return False


def data_plane_status():
    checks = {}
    try:
        subprocess.run([WG_BIN, "show", WG_INTERFACE], capture_output=True,
                       text=True, timeout=5, check=True)
        checks["wireguard_interface"] = True
    except (OSError, subprocess.SubprocessError):
        checks["wireguard_interface"] = False
    try:
        result = subprocess.run(
            ["sysctl", "-n", "net.ipv4.ip_forward"],
            capture_output=True, text=True, timeout=3, check=True
        )
        checks["ipv4_forwarding"] = result.stdout.strip() == "1"
    except (OSError, subprocess.SubprocessError):
        checks["ipv4_forwarding"] = False
    checks["dns_resolver"] = check_dns_resolver()
    return {
        "status": "ready" if all(checks.values()) else "not_ready",
        "checks": checks,
        "note": "These checks do not prove upstream NAT, firewall, or public internet return routing."
    }


@app.get("/v1/admin/health")
def admin_data_plane_health(x_admin_key: Optional[str] = Header(default=None)):
    admin_auth(x_admin_key)
    return data_plane_status()


@app.post("/v1/admin/invites")
def create_invite(body: InviteRequest, x_admin_key: Optional[str] = Header(default=None)):
    admin_auth(x_admin_key)
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).hexdigest()
    expires = int(time.time()) + INVITE_TTL
    with db() as conn:
        conn.execute("INSERT INTO invites(token_hash, expires_at) VALUES (?, ?)", (digest, expires))
    # The raw invitation is returned once and is never stored.
    return {"invitation": token, "expires_at": expires, "ttl_seconds": INVITE_TTL, "label": body.label}


@app.post("/v1/enroll")
def enroll(body: EnrollRequest):
    if not valid_public_key(body.public_key):
        raise HTTPException(status_code=400, detail="Invalid WireGuard public key")
    digest = hashlib.sha256(body.invitation.encode()).hexdigest()
    peer_added = False
    try:
        # Keep the invitation claim, device row, and live peer in sync. SQLite
        # rolls back the claim/row on failure; the compensating wg operation
        # removes a peer if the database insert or commit fails afterwards.
        with db() as conn:
            now = int(time.time())
            claimed = conn.execute(
                "UPDATE invites SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?",
                (now, digest, now)
            )
            if claimed.rowcount != 1:
                raise HTTPException(status_code=403, detail="Invitation is invalid, expired, or already used")
            if conn.execute("SELECT 1 FROM devices WHERE public_key = ?", (body.public_key,)).fetchone():
                raise HTTPException(status_code=409, detail="This device key is already enrolled")
            address = allocate_ip(conn)
            device_id = str(uuid.uuid4())
            wg("set", WG_INTERFACE, "peer", body.public_key, "allowed-ips", address + "/32")
            peer_added = True
            conn.execute(
                "INSERT INTO devices(id, name, public_key, address, created_at) VALUES (?, ?, ?, ?, ?)",
                (device_id, body.device_name, body.public_key, address, now)
            )
    except Exception:
        if peer_added:
            try:
                wg("set", WG_INTERFACE, "peer", body.public_key, "remove")
            except Exception:
                # Keep the original request failure, but make a failed
                # compensating operation visible to service logs/monitoring.
                logger.exception(
                    "WireGuard enrollment rollback failed for public key %s",
                    body.public_key,
                )
        raise
    return {
        "device_id": device_id,
        "assigned_address": address + "/32",
        "server_endpoint": WG_ENDPOINT,
        "server_public_key": WG_SERVER_PUBLIC_KEY,
        "dns": VPN_DNS,
        "allowed_ips": "0.0.0.0/0",
        "persistent_keepalive": 25
    }


@app.get("/v1/admin/devices")
def list_devices(x_admin_key: Optional[str] = Header(default=None)):
    admin_auth(x_admin_key)
    with db() as conn:
        rows = conn.execute(
            "SELECT id, name, public_key, address, created_at, revoked_at FROM devices ORDER BY created_at DESC"
        ).fetchall()
    peer_stats = {}
    try:
        dump = subprocess.run([WG_BIN, "show", WG_INTERFACE, "dump"], capture_output=True,
                              text=True, timeout=10, check=True).stdout
        for line in dump.splitlines()[1:]:
            fields = line.split("\t")
            if len(fields) >= 8:
                peer_stats[fields[0]] = {
                    "latest_handshake": int(fields[4]),
                    "received_bytes": int(fields[5]),
                    "sent_bytes": int(fields[6])
                }
    except Exception:
        peer_stats = {}
    return {"devices": [
        {"id": r["id"], "name": r["name"], "address": r["address"],
         "created_at": r["created_at"], "revoked": r["revoked_at"] is not None,
         "peer_configured": r["public_key"] in peer_stats,
         "latest_handshake": peer_stats.get(r["public_key"], {}).get("latest_handshake", 0),
         "received_bytes": peer_stats.get(r["public_key"], {}).get("received_bytes", 0),
         "sent_bytes": peer_stats.get(r["public_key"], {}).get("sent_bytes", 0)}
        for r in rows
    ]}


@app.post("/v1/admin/devices/{device_id}/revoke")
def revoke_device(device_id: str, x_admin_key: Optional[str] = Header(default=None)):
    admin_auth(x_admin_key)
    peer_removed = False
    public_key = None
    address = None
    try:
        with db() as conn:
            row = conn.execute(
                "SELECT public_key, address, revoked_at FROM devices WHERE id = ?",
                (device_id,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Device not found")
            if row["revoked_at"] is None:
                public_key = row["public_key"]
                address = row["address"]
                wg("set", WG_INTERFACE, "peer", public_key, "remove")
                peer_removed = True
                conn.execute(
                    "UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                    (int(time.time()), device_id),
                )
    except Exception:
        # If SQLite fails after WireGuard removed the peer (including at commit),
        # restore the peer so the database remains the source of truth.
        if peer_removed and public_key and address:
            try:
                wg(
                    "set", WG_INTERFACE, "peer", public_key,
                    "allowed-ips", address + "/32",
                )
            except Exception:
                # Preserve the original exception while making possible
                # database/WireGuard divergence visible to service monitoring.
                logger.exception(
                    "WireGuard peer restore failed after revocation error for device %s",
                    device_id,
                )
        raise
    return {"revoked": True}


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return ADMIN_HTML


ADMIN_HTML = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Admin</title>
<style>
body{font:15px system-ui;background:#111318;color:#eef0f4;margin:0;padding:24px}
main{max-width:900px;margin:auto}section,article{background:#1c2028;border:1px solid #303642;border-radius:12px;padding:16px;margin:12px 0}
input,button{font:inherit;padding:10px;border-radius:8px;border:1px solid #465064;background:#151922;color:inherit}
button{cursor:pointer;background:#315d9b;border:0;margin:4px}small{color:#aab2c0}.row{display:flex;gap:8px;flex-wrap:wrap}
code{overflow-wrap:anywhere}
</style><main><h1>VPN administration</h1><section><label>Admin key <input id="key" type="password" autocomplete="off"></label>
<div class="row"><button onclick="refresh()">Refresh devices</button><button onclick="invite()">Create 15-minute invitation</button><button onclick="checkServer()">Check server readiness</button></div>
<p id="message" aria-live="polite"></p></section><section><h2>Devices</h2><div id="devices">Enter the admin key to load devices.</div></section>
<script>
const key=()=>document.getElementById('key').value;
const msg=t=>document.getElementById('message').textContent=t;
async function api(path,method='GET',body){const r=await fetch(path,{method,headers:{'X-Admin-Key':key(),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});const d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d}
async function refresh(){try{const d=await api('/v1/admin/devices');document.getElementById('devices').innerHTML=d.devices.map(x=>'<article><b>'+esc(x.name)+'</b><p><code>'+esc(x.address)+'</code> · '+(x.revoked?'Revoked':'Enabled')+' · '+(x.peer_configured?'Peer loaded':'Peer missing')+'</p><small>Received: '+Number(x.received_bytes||0).toLocaleString()+' B · Sent: '+Number(x.sent_bytes||0).toLocaleString()+' B · Last handshake: '+(x.latest_handshake?new Date(x.latest_handshake*1000).toLocaleString():'Never')+'</small>'+(x.revoked?'':'<button onclick="revoke(\''+x.id+'\')">Revoke</button>')+'</article>').join('')||'No devices';msg('Updated')}catch(e){msg(e.message)}}
async function invite(){try{const d=await api('/v1/admin/invites','POST',{label:'Device'});msg('One-time invitation (copy it now; expires in 15 minutes): '+d.invitation)}catch(e){msg(e.message)}}\nasync function checkServer(){try{const d=await api('/v1/admin/health');msg('Server '+d.status+' · '+Object.entries(d.checks).map(([k,v])=>k+': '+(v?'OK':'FAILED')).join(' · ')+' · '+d.note)}catch(e){msg(e.message)}}
async function revoke(id){if(!confirm('Revoke this device?'))return;try{await api('/v1/admin/devices/'+id+'/revoke','POST');await refresh()}catch(e){msg(e.message)}}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
setInterval(()=>{if(key())refresh()},10000);
</script></main></html>"""
