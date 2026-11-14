#!/usr/bin/env python3
# Resume the interrupted 2026-11-14 XHTTP batch. Safe to rerun: persistent UUID plan + exact inbound validation.
import os, sys, json, sqlite3, time, hashlib, secrets, subprocess, tempfile, shutil, ssl, urllib.request, urllib.error
from pathlib import Path

DB = "/etc/x-ui/x-ui.db"
PREFIX = "XHTTP-20261114-043426-62733"
DOMAIN = "home.680675.xyz"
H3_BASE, H2_BASE = 42404, 57696
STATE = "/root/.3xaddxhtp-resume-20261114-043426-62733.json"
BACKUP = "/root/x-ui-before-xhttp-resume-20261114-043426.db"

def fail(msg):
    raise RuntimeError(msg)

def run(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw).stdout.strip()

if os.geteuid() != 0:
    fail("Run as root.")
if not os.path.isfile(DB):
    fail("3x-ui database not found.")
if run(["systemctl","is-active","x-ui"]) != "active":
    fail("x-ui service is not active.")

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row
tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
if "inbounds" not in tables or "settings" not in tables or "api_tokens" not in tables:
    fail("Required 3x-ui database tables are missing.")
settings = dict(con.execute("SELECT key,value FROM settings").fetchall())
port = str(settings.get("webPort") or "")
base_path = str(settings.get("webBasePath") or "/").strip() or "/"
cert = str(settings.get("webCertFile") or "")
key = str(settings.get("webKeyFile") or "")
domain = str(settings.get("webDomain") or DOMAIN).strip()
if not port.isdigit() or not cert or not key or not os.path.isfile(cert) or not os.path.isfile(key):
    fail("Cannot detect panel port or TLS certificate/private key from 3x-ui settings.")
if domain != DOMAIN:
    fail(f"Panel domain changed ({domain}); expected {DOMAIN}.")
run(["openssl","x509","-in",cert,"-noout","-checkhost",DOMAIN])
run(["openssl","x509","-in",cert,"-noout","-checkend","86400"])
run(["openssl","pkey","-in",key,"-noout"])
base_path = "/" + base_path.strip("/") if base_path.strip("/") else ""
api_base = f"https://{DOMAIN}:{port}{base_path}"
resolve = f"{DOMAIN}:{port}:127.0.0.1"

def get_inbounds():
    rows = con.execute("SELECT * FROM inbounds").fetchall()
    return rows

rows = get_inbounds()
batch = [r for r in rows if str(r["remark"] or "").startswith(PREFIX + "-")]
source = [r for r in batch if r["remark"] == PREFIX + "-01-H3"]
if len(source) != 1:
    fail(f"Expected exactly one original 01-H3 inbound; found {len(source)}. No changes made.")
src = source[0]
if int(src["port"]) != H3_BASE or src["protocol"] != "vless" or not src["enable"]:
    fail("Original 01-H3 inbound does not match the expected port/protocol/enabled state.")
src_settings = json.loads(src["settings"])
src_stream = json.loads(src["stream_settings"])
source_uuid = src_settings["clients"][0]["id"]
if src_stream.get("network") != "xhttp" or src_stream.get("security") != "tls":
    fail("Original inbound is not VLESS XHTTP over TLS.")
if src_stream.get("xhttpSettings",{}).get("path") != "/xhttp/01" or src_stream.get("tlsSettings",{}).get("alpn") != ["h3"]:
    fail("Original 01-H3 path/ALPN does not match the planned batch.")

# Persist the UUIDs before the first write, so retries never regenerate pair UUIDs.
if os.path.exists(STATE):
    with open(STATE, encoding="utf-8") as f:
        plan = json.load(f)
    if plan.get("prefix") != PREFIX or plan.get("uuid1") != source_uuid:
        fail("Persistent resume plan does not match the existing 01-H3 inbound.")
else:
    plan = {"prefix": PREFIX, "uuid1": source_uuid,
            "uuids": [source_uuid] + [secrets.token_hex(16) for _ in range(4)]}
    # UUIDs 2-5 must be RFC 4122 UUIDs.
    import uuid
    plan["uuids"] = [source_uuid] + [str(uuid.uuid4()) for _ in range(4)]
    tmp = STATE + ".tmp"
    with open(tmp,"w",encoding="utf-8") as f:
        json.dump(plan,f)
    os.chmod(tmp,0o600)
    os.replace(tmp,STATE)
uuids = plan["uuids"]

def expected():
    out = {}
    for i in range(1,6):
        for kind, p, alpn in (("H3",H3_BASE+i-1,"h3"),("H2",H2_BASE+i-1,"h2")):
            remark=f"{PREFIX}-{i:02d}-{kind}"
            out[remark] = (p, uuids[i-1], kind, alpn, f"/xhttp/{i:02d}")
    return out
spec = expected()
# Validate any already-present members; only the exact original 01-H3 is expected at first run.
for r in batch:
    if r["remark"] not in spec:
        fail(f"Unexpected inbound in this batch: {r['remark']}.")
    p, uid, kind, alpn, path = spec[r["remark"]]
    s=json.loads(r["settings"]); st=json.loads(r["stream_settings"])
    if int(r["port"]) != p or r["protocol"] != "vless" or s["clients"][0]["id"] != uid:
        fail(f"Existing batch inbound {r['remark']} conflicts with the saved plan.")
    if st.get("network") != "xhttp" or st.get("security") != "tls" or st.get("tlsSettings",{}).get("alpn") != [alpn] or st.get("xhttpSettings",{}).get("path") != path:
        fail(f"Existing batch inbound {r['remark']} has unexpected XHTTP settings.")

# Ensure all still-missing target ports are free in SQLite and in the OS listener table.
existing_by_remark = {r["remark"]:r for r in rows}
used_ports = {int(r["port"]) for r in rows}
for remark,(p,uid,kind,alpn,path) in spec.items():
    if remark not in existing_by_remark and p in used_ports:
        fail(f"Target port {p} is already used by another inbound; no new entries added.")
for proto, flags in (("udp",["-lun"]),("tcp",["-ltn"])):
    listeners = run(["ss","-H",*flags])
    for remark,(p,uid,kind,alpn,path) in spec.items():
        if remark in existing_by_remark: continue
        if (kind=="H3" and proto=="udp") or (kind=="H2" and proto=="tcp"):
            if any((f":{p} " in line or line.rstrip().endswith(f":{p}")) for line in listeners.splitlines()):
                fail(f"Target {proto.upper()} port {p} is already listening; no new entries added.")

# Back up before any writes.
if not os.path.exists(BACKUP):
    dst=sqlite3.connect(BACKUP)
    con.backup(dst); dst.close(); os.chmod(BACKUP,0o600)
print("Database backup:",BACKUP)
print("Original H3 inbound confirmed; resuming the original batch with its existing UUID.")

cols={r[1] for r in con.execute("PRAGMA table_info(api_tokens)")}
required={"name","token","enabled","created_at","scope","expires_at"}
if not required.issubset(cols):
    fail("api_tokens lacks required scoped-token columns.")
token_name=f"xhttp-resume-{int(time.time())}-{secrets.token_hex(3)}"
api_token=secrets.token_hex(24)
token_hash=hashlib.sha256(api_token.encode()).hexdigest()
con.execute("INSERT INTO api_tokens (name,token,enabled,created_at,scope,expires_at) VALUES (?,?,?,?,?,?)",
            (token_name,token_hash,1,int(time.time()),"node-sync",0))
con.commit()

def api(method, path, payload=None):
    cmd=["curl","-sS","--connect-timeout","6","--max-time","35","--resolve",resolve,
         "-H",f"Authorization: Bearer {api_token}","-w","\n%{http_code}"]
    if payload is not None:
        fd,tmp=tempfile.mkstemp(prefix="xhttp-inbound-",suffix=".json")
        try:
            with os.fdopen(fd,"w") as f: json.dump(payload,f,separators=(",",":"))
            cmd += ["-H","Content-Type: application/json","--data-binary",f"@{tmp}"]
            raw=run(cmd+[f"{api_base}{path}"])
        finally:
            os.unlink(tmp)
    else:
        raw=run(cmd+[f"{api_base}{path}"])
    body,status=raw.rsplit("\n",1)
    if status!="200":
        fail(f"API {path} returned HTTP {status}: {body[:400]}")
    try: data=json.loads(body)
    except Exception as e: fail(f"API {path} returned invalid JSON: {e}; preview={body[:400]!r}")
    if not isinstance(data,dict) or not data.get("success"):
        fail(f"API {path} failed: {str(data)[:500]}")
    return data

try:
    api("GET","/panel/api/inbounds/list")
    for remark,(p,uid,kind,alpn,path) in spec.items():
        if remark in existing_by_remark:
            print("Already present, verified:",remark)
            continue
        inbound={
          "enable":True,"remark":remark,"listen":"","port":p,"protocol":"vless","expiryTime":0,"total":0,
          "settings":{"clients":[{"id":uid,"email":f"xhttp-{int(remark.split('-')[-2]):02d}","enable":True,"flow":""}],"decryption":"none"},
          "streamSettings":{"network":"xhttp","security":"tls",
            "tlsSettings":{"minVersion":"1.3","alpn":[alpn],"certificates":[{"certificateFile":cert,"keyFile":key}]},
            "xhttpSettings":{"path":path,"mode":"auto"}},
          "sniffing":{"enabled":True,"destOverride":["http","tls","quic"],"routeOnly":False}}
        print(f"Adding {remark} on {p} ...",flush=True)
        api("POST","/panel/api/inbounds/add",inbound)
        time.sleep(0.3)
        con.execute("SELECT 1")
        check=con.execute("SELECT id,port,settings,stream_settings FROM inbounds WHERE remark=?",(remark,)).fetchone()
        if not check:
            fail(f"API accepted {remark}, but it is not visible in the database yet. Stop and inspect before retry.")
        cs=json.loads(check["settings"]); cst=json.loads(check["stream_settings"])
        if int(check["port"])!=p or cs["clients"][0]["id"]!=uid or cst.get("tlsSettings",{}).get("alpn")!=[alpn]:
            fail(f"Post-create database verification failed for {remark}.")
        existing_by_remark[remark]=check
    final=con.execute("SELECT remark,port FROM inbounds WHERE remark LIKE ?",(PREFIX+"-%",)).fetchall()
    if len(final)!=10:
        fail(f"Batch currently has {len(final)}/10 inbounds. Do not rerun blindly; state file preserved at {STATE}.")
    print("\nVerified all 10 inbounds:")
    for r in final: print(f"{r['remark']}  port={r['port']}")
    print("\nResume complete. Pair 01 H2/H3 share the original UUID; pairs 02-05 use unique UUIDs shared within each pair.")
    print("Persistent resume plan:",STATE)
finally:
    try:
        con.execute("DELETE FROM api_tokens WHERE name=?",(token_name,))
        con.commit()
    except Exception as e:
        print("WARNING: could not remove temporary API token:",e,file=sys.stderr)
    con.close()
