#!/usr/bin/env bash
# 3x-ui: add five VLESS-XHTTP pairs (H2/TCP + H3/UDP), ten inbounds total.
# Default mode creates five H2/H3 pairs unattended. Use --check for read-only preflight.
set -Eeuo pipefail
umask 077

DB="/etc/x-ui/x-ui.db"

die(){ echo "ERROR: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }
[[ $EUID -eq 0 ]] || die "Run as root."
for c in curl python3 openssl ss systemctl; do need "$c"; done
[[ -s "$DB" ]] || die "3x-ui database not found: $DB"
systemctl is-active --quiet x-ui || die "x-ui service is not active."
MODE=apply
[[ "${1:-}" == "--check" ]] && MODE=check
[[ -z "${1:-}" || "${1:-}" == "--check" ]] || die "Usage: $0 [--check]"

echo "Each run creates five pairs (10 inbounds): H3/UDP and H2/TCP."

# Read the panel address directly from the 3x-ui settings database.
PANEL_SETTINGS_OUTPUT=$(python3 - "$DB" <<'PY'
import sqlite3, sys, os, re, subprocess
db = sqlite3.connect(sys.argv[1])
try:
    rows = db.execute("SELECT key, value FROM settings").fetchall()
except Exception as e:
    raise SystemExit("Cannot read 3x-ui settings table: " + str(e))
s = {str(k): "" if v is None else str(v) for k, v in rows}
port = s.get("webPort", "").strip()
base = s.get("webBasePath", "/").strip() or "/"
domain = s.get("webDomain", "").strip()
cert = s.get("webCertFile", "").strip()
key = s.get("webKeyFile", "").strip()
if not port.isdigit() or not (1 <= int(port) <= 65535):
    raise SystemExit("Invalid or missing webPort in 3x-ui settings.")
if not base.startswith("/"):
    base = "/" + base
base = base.rstrip("/") + "/"
if not cert or not key or not os.path.isfile(cert) or not os.path.isfile(key):
    raise SystemExit("Panel TLS certificate/key paths are missing or files do not exist in 3x-ui settings.")
if not domain:
    try:
        out = subprocess.check_output(["openssl", "x509", "-in", cert, "-noout", "-ext", "subjectAltName"], text=True, stderr=subprocess.DEVNULL)
        names = re.findall(r"DNS:([^,\s]+)", out)
        if names:
            domain = names[0]
        else:
            ips = re.findall(r"IP Address:([^,\s]+)", out)
            if ips:
                domain = ips[0]
    except Exception:
        pass
if not domain:
    raise SystemExit("Cannot determine node TLS SNI from webDomain or panel certificate SAN.")
print("https")
print(domain)
print(port)
print(base)
print(cert)
print(key)
PY
) || die "Failed to read panel URL from 3x-ui settings."
mapfile -t PANEL_SETTINGS <<< "$PANEL_SETTINGS_OUTPUT"
[[ "${#PANEL_SETTINGS[@]}" -eq 6 ]] || die "Unexpected panel settings response."
PANEL_SCHEME="${PANEL_SETTINGS[0]}"
PANEL_HOST="${PANEL_SETTINGS[1]}"
PANEL_PORT="${PANEL_SETTINGS[2]}"
PANEL_PATH="${PANEL_SETTINGS[3]}"
CERT="${PANEL_SETTINGS[4]}"
KEY="${PANEL_SETTINGS[5]}"
DOMAIN="$PANEL_HOST"
if [[ "$PANEL_HOST" == *:* && "$PANEL_HOST" != \[*\] ]]; then PANEL_HOST="[$PANEL_HOST]"; fi
BASE="${PANEL_SCHEME}://${PANEL_HOST}:${PANEL_PORT}${PANEL_PATH%/}"
echo "Panel URL, TLS SNI, certificate and key paths auto-detected from 3x-ui database."
echo "Detected TLS SNI: $DOMAIN"
echo "Detected certificate: $CERT"
echo "Detected private-key path: $KEY"

[[ -s "$CERT" && -s "$KEY" ]] || die "TLS certificate/key not found."
openssl x509 -in "$CERT" -noout -checkhost "$DOMAIN" >/dev/null || die "Certificate does not cover $DOMAIN."
openssl x509 -in "$CERT" -noout -checkend 86400 >/dev/null || die "Certificate expires within 24 hours."
openssl pkey -in "$KEY" -noout >/dev/null 2>&1 || die "Private key is unreadable."
# Pick random contiguous five-port blocks, independently for UDP and TCP.
# A unique prefix is generated on every run so repeated executions never clash.
PREFIX="XHTTP-$(date +%Y%m%d-%H%M%S)-$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')"
echo "Generated node prefix: $PREFIX"
read -r H3 H2 < <(python3 - "$DB" <<'PYPORT'
import random, socket, sqlite3, sys
db=sys.argv[1]
used=set()
try:
    con=sqlite3.connect(f"file:{db}?mode=ro",uri=True)
    tables={r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "inbounds" in tables:
        cols={r[1] for r in con.execute("PRAGMA table_info(inbounds)")}
        if "port" in cols:
            used={int(r[0]) for r in con.execute("SELECT port FROM inbounds") if r[0]}
    con.close()
except Exception as e:
    raise SystemExit("Cannot inspect existing inbound ports safely: "+str(e))
def block(kind):
    stype=socket.SOCK_DGRAM if kind=="UDP" else socket.SOCK_STREAM
    for _ in range(20000):
        start=random.randint(10000,60000)
        ports=range(start,start+5)
        if any(p in used for p in ports): continue
        sockets=[]
        try:
            for p in ports:
                s=socket.socket(socket.AF_INET,stype)
                s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,0)
                s.bind(("0.0.0.0",p))
                sockets.append(s)
            for s in sockets: s.close()
            return start
        except OSError:
            for s in sockets: s.close()
    raise SystemExit("No free consecutive five-port "+kind+" block found.")
print(block("UDP"),block("TCP"))
PYPORT
) || die "Unable to allocate random contiguous port blocks."
[[ "$H3" =~ ^[0-9]+$ && "$H2" =~ ^[0-9]+$ ]] || die "Invalid random port allocation."
PATH_PREFIX="/xhttp"
[[ "$PATH_PREFIX" == /* && "$PATH_PREFIX" != *" "* && "$PATH_PREFIX" != *"?"* && "$PATH_PREFIX" != *"#"* ]] || die "Invalid XHTTP path prefix."

TMP=$(mktemp -d /root/3xaddxhttp.XXXXXX)
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT
COOKIE="$TMP/cookie"
RESP="$TMP/response.json"

echo "Planned ports:"
for i in 0 1 2 3 4; do
  printf 'Pair %d: H3 UDP %d; H2 TCP %d; path %s/%02d\n' "$((i+1))" "$((H3+i))" "$((H2+i))" "$PATH_PREFIX" "$((i+1))"
done
echo "H2/H3 within each pair share one UUID. Each pair has a unique UUID."
# Create a short-lived local API token without panel credentials.
# Require the complete scoped-token schema; never modify the schema ourselves.
TOKEN_NAME="xhttp-batch-$(date +%s)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' ')"
API_TOKEN="$(openssl rand -hex 24)"
TOKEN_HASH="$(printf '%s' "$API_TOKEN" | openssl dgst -sha256 | awk '{print $NF}')"
python3 - "$DB" "$TOKEN_NAME" "$TOKEN_HASH" <<'PYTOKEN'
import sqlite3,sys,time
db,name,digest=sys.argv[1:]
con=sqlite3.connect(db)
try:
    tables={r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "api_tokens" not in tables:
        raise SystemExit("No api_tokens table: this 3x-ui version cannot use unattended local API-token auth.")
    cols={r[1] for r in con.execute("PRAGMA table_info(api_tokens)")}
    required={"name","token","enabled","created_at","scope","expires_at"}
    if not required.issubset(cols):
        raise SystemExit("api_tokens is missing scoped-token fields; refusing unsafe fallback.")
    con.execute("INSERT INTO api_tokens (name,token,enabled,created_at,scope,expires_at) VALUES (?,?,?,?,?,?)",
                (name,digest,1,int(time.time()),"node-sync",0))
    con.commit()
except Exception:
    con.rollback()
    raise
finally:
    con.close()
PYTOKEN
CURL=(curl -sS --connect-timeout 6 --max-time 30 --resolve "$DOMAIN:$PANEL_PORT:127.0.0.1" -H "Authorization: Bearer $API_TOKEN")
cleanup_token() {
  python3 - "$DB" "$TOKEN_NAME" <<'PYDEL' >/dev/null 2>&1 || true
import sqlite3,sys
con=sqlite3.connect(sys.argv[1])
con.execute("DELETE FROM api_tokens WHERE name=?",(sys.argv[2],))
con.commit()
con.close()
PYDEL
}
trap 'cleanup_token; rm -rf "$TMP"' EXIT

# Fetch current inbound list; this also validates that the configured API path works.
HTTP_STATUS="$("${CURL[@]}" -o "$RESP" -w '%{http_code}' "$BASE/panel/api/inbounds/list")" || die "Cannot connect to the local 3x-ui API."
if [[ "$HTTP_STATUS" != "200" ]]; then
  BODY="$(head -c 500 "$RESP" 2>/dev/null || true)"
  die "Inbound-list API returned HTTP $HTTP_STATUS (response: ${BODY:-<empty>}). Check panel base path, local listener and API-token compatibility."
fi
[[ -s "$RESP" ]] || die "Inbound-list API returned HTTP 200 but an empty response body."
python3 - "$RESP" "$H3" "$H2" "$PREFIX" <<'PY'
import json,sys
try:
    with open(sys.argv[1], encoding="utf-8") as f: d=json.load(f)
except Exception as e:
    raw=open(sys.argv[1],"rb").read(500).decode("utf-8","replace")
    raise SystemExit(f"Inbound-list API returned non-JSON data: {e}; response preview={raw!r}")

if not d.get("success"): raise SystemExit("Inbound-list API failed: "+str(d.get("msg","")))
items=d.get("obj") or []
ports={int(sys.argv[2])+i for i in range(5)} | {int(sys.argv[3])+i for i in range(5)}
remarks={f"{sys.argv[4]}-{i:02d}-{k}" for i in range(1,6) for k in ("H3","H2")}
for x in items:
 p=int(x.get("port",0) or 0)
 if p in ports: raise SystemExit(f"Port {p} already exists (inbound id={x.get('id')}, remark={x.get('remark')!r}); nothing created.")
 if x.get("remark") in remarks: raise SystemExit(f"Remark {x.get('remark')!r} already exists; nothing created.")
print(f"Precheck passed: {len(items)} existing inbounds; all ten planned ports and remarks are free.")
PY

# Generate stable UUID/path pairs once per execution; same pair shares UUID and path.
python3 - "$TMP" "$PREFIX" "$H3" "$H2" "$PATH_PREFIX" "$CERT" "$KEY" <<'PY'
import json,sys,uuid,os
root,prefix,h3,h2,path,cert,key=sys.argv[1:]
for i in range(1,6):
 uid=str(uuid.uuid4()); p=f"{path}/{i:02d}"
 for kind,port,alpn in (("H3",int(h3)+i-1,["h3"]),("H2",int(h2)+i-1,["h2"])):
  obj={
   "enable":True,"remark":f"{prefix}-{i:02d}-{kind}","listen":"","port":port,
   "protocol":"vless","expiryTime":0,"total":0,
   "settings":{"clients":[{"id":uid,"email":f"xhttp-{prefix.lower()}-{i:02d}-{kind.lower()}","enable":True,"flow":""}],"decryption":"none"},
   "streamSettings":{"network":"xhttp","security":"tls",
    "tlsSettings":{"minVersion":"1.3","alpn":alpn,"certificates":[{"certificateFile":cert,"keyFile":key}]},
    "xhttpSettings":{"path":p,"mode":"auto"}},
   "sniffing":{"enabled":True,"destOverride":["http","tls","quic"],"routeOnly":False}}
  with open(os.path.join(root,f"{i:02d}-{kind}.json"),"w") as f: json.dump(obj,f)
PY

if [[ "$MODE" == check ]]; then
 echo "Read-only preflight complete: no inbounds were created."
 exit 0
fi

BACKUP="/root/x-ui-before-xhttp-batch-$(date +%Y%m%d-%H%M%S).db"
python3 - "$DB" "$BACKUP" <<'PY'
import sqlite3,sys,os
src=sqlite3.connect(sys.argv[1]); dst=sqlite3.connect(sys.argv[2])
src.backup(dst); dst.close(); src.close(); os.chmod(sys.argv[2],0o600)
print("Database backup saved:",sys.argv[2])
PY

DONE=0
for f in "$TMP"/{01..05}-H3.json "$TMP"/{01..05}-H2.json; do
 [[ -f "$f" ]] || continue
 remark=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["remark"])' "$f")
 port=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["port"])' "$f")
 echo "Adding $remark on port $port ..."
 HTTP_STATUS="$("${CURL[@]}" -H 'Content-Type: application/json' --data-binary "@$f" -o "$RESP" -w '%{http_code}' "$BASE/panel/api/inbounds/add")" || die "API transport failed after $DONE creations. Check panel before retrying; backup: $BACKUP"
 if [[ "$HTTP_STATUS" != "200" ]]; then
   BODY="$(head -c 500 "$RESP" 2>/dev/null || true)"
   die "Inbound-add API returned HTTP $HTTP_STATUS after $DONE creations (response: ${BODY:-<empty>}). Backup: $BACKUP"
 fi
 [[ -s "$RESP" ]] || die "Inbound-add API returned HTTP 200 with an empty body after $DONE creations. Backup: $BACKUP"
 python3 - "$RESP" <<'PY' || die "Could not validate inbound-add response after $DONE creations. Backup: $BACKUP"
import json,sys
raw_bytes=open(sys.argv[1],"rb").read()
raw=raw_bytes.decode("utf-8","replace")
try:
    d=json.loads(raw)
except Exception as e:
    preview=raw[:1000]
    raise SystemExit(f"Inbound-add API returned non-JSON data: {e}; response preview={preview!r}")
if not isinstance(d,dict):
    raise SystemExit(f"Inbound-add API returned unexpected JSON type: {type(d).__name__}")
if not d.get("success"):
    raise SystemExit("Panel rejected inbound creation: "+str(d.get("msg","API returned failure")))
PY
 DONE=$((DONE+1))
done

echo "Submitted $DONE/10 inbounds. Backup: $BACKUP"
if [[ "$DONE" -ne 10 ]]; then die "Expected 10 successful creations, got $DONE."; fi
echo
echo "========== VLESS SHARE LINKS =========="
python3 - "$TMP" "$DOMAIN" <<'PYLINK'
import json,sys,glob,os
from urllib.parse import urlencode,quote
root,host=sys.argv[1:]
for f in sorted(glob.glob(os.path.join(root,"??-H?.json"))):
    d=json.load(open(f))
    uid=d["settings"]["clients"][0]["id"]
    ss=d["streamSettings"]
    kind="H3" if "H3" in d["remark"] else "H2"
    alpn=ss["tlsSettings"]["alpn"][0]
    path=ss["xhttpSettings"]["path"]
    params={"encryption":"none","security":"tls","sni":host,"alpn":alpn,
            "type":"xhttp","path":path,"mode":"auto","fp":"chrome"}
    link=f"vless://{uid}@{host}:{d['port']}?{urlencode(params,quote_via=quote)}#{quote(d['remark'])}"
    print(link)
PYLINK
echo "H3 UDP ports: $H3-$((H3+4)); H2 TCP ports: $H2-$((H2+4))."
echo "Allow these UDP/TCP port ranges in your VPS provider firewall."
echo "No Hiddify services or ports 80/443 were modified."
echo "If any creation fails partway, inspect 3x-ui inbound list before rerunning."
