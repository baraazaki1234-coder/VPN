import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import sqlite3
import subprocess
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

DB_PATH = os.getenv("VPN_DB_PATH", "/var/lib/simplevpn/control.db")
WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WG_ENDPOINT = os.environ["WG_ENDPOINT"]  # public host:UDP port
WG_SERVER_PUBLIC_KEY = os.environ["WG_SERVER_PUBLIC_KEY"]
VPN_NETWORK = ipaddress.ip_network(os.getenv("VPN_NETWORK", "10.77.0.0/24"))
VPN_DNS = os.getenv("VPN_DNS", "10.77.0.1")
ADMIN_KEY = os.environ["VPN_ADMIN_KEY"]
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
        """)


init_db()


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
        if address != VPN_DNS and address not in used:
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
    return {"status": "ok"}


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
    with db() as conn:
        now = int(time.time())
        # Claim the invitation atomically so concurrent requests cannot reuse it.
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
        # The database transaction rolls back the invitation claim if wg fails.
        wg("set", WG_INTERFACE, "peer", body.public_key, "allowed-ips", address + "/32")
        conn.execute(
            "INSERT INTO devices(id, name, public_key, address, created_at) VALUES (?, ?, ?, ?, ?)",
            (device_id, body.device_name, body.public_key, address, now)
        )
    return {
        "device_id": device_id,
        "assigned_address": address + "/32",
        "server_endpoint": WG_ENDPOINT,
        "server_public_key": WG_SERVER_PUBLIC_KEY,
        "dns": VPN_DNS,
        "allowed_ips": "0.0.0.0/0, ::/0",
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
    with db() as conn:
        row = conn.execute("SELECT public_key FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Device not found")
        if conn.execute("SELECT revoked_at FROM devices WHERE id = ?", (device_id,)).fetchone()[0] is None:
            wg("set", WG_INTERFACE, "peer", row["public_key"], "remove")
            conn.execute("UPDATE devices SET revoked_at = ? WHERE id = ?", (int(time.time()), device_id))
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
<div class="row"><button onclick="refresh()">Refresh devices</button><button onclick="invite()">Create 15-minute invitation</button></div>
<p id="message" aria-live="polite"></p></section><section><h2>Devices</h2><div id="devices">Enter the admin key to load devices.</div></section>
<script>
const key=()=>document.getElementById('key').value;
const msg=t=>document.getElementById('message').textContent=t;
async function api(path,method='GET',body){const r=await fetch(path,{method,headers:{'X-Admin-Key':key(),'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});const d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d}
async function refresh(){try{const d=await api('/v1/admin/devices');document.getElementById('devices').innerHTML=d.devices.map(x=>'<article><b>'+esc(x.name)+'</b><p><code>'+esc(x.address)+'</code> · '+(x.revoked?'Revoked':'Enabled')+' · '+(x.peer_configured?'Peer loaded':'Peer missing')+'</p><small>Received: '+Number(x.received_bytes||0).toLocaleString()+' B · Sent: '+Number(x.sent_bytes||0).toLocaleString()+' B · Last handshake: '+(x.latest_handshake?new Date(x.latest_handshake*1000).toLocaleString():'Never')+'</small>'+(x.revoked?'':'<button onclick="revoke(\''+x.id+'\')">Revoke</button>')+'</article>').join('')||'No devices';msg('Updated')}catch(e){msg(e.message)}}
async function invite(){try{const d=await api('/v1/admin/invites','POST',{label:'Device'});msg('One-time invitation (copy it now; expires in 15 minutes): '+d.invitation)}catch(e){msg(e.message)}}
async function revoke(id){if(!confirm('Revoke this device?'))return;try{await api('/v1/admin/devices/'+id+'/revoke','POST');await refresh()}catch(e){msg(e.message)}}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
</script></main></html>"""
