#!/usr/bin/env bash
# 3x-ui: add five VLESS-XHTTP pairs (H2/TCP + H3/UDP), ten inbounds total.
# Default mode only checks prerequisites and API connectivity. Use --apply to create.
set -Eeuo pipefail
umask 077

DB="/etc/x-ui/x-ui.db"

die(){ echo "ERROR: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }
[[ $EUID -eq 0 ]] || die "Run as root."
for c in curl python3 openssl ss systemctl; do need "$c"; done
[[ -s "$DB" ]] || die "3x-ui database not found: $DB"
systemctl is-active --quiet x-ui || die "x-ui service is not active."
MODE=check
[[ "${1:-}" == "--apply" ]] && MODE=apply
[[ -z "${1:-}" || "${1:-}" == "--apply" ]] || die "Usage: $0 [--apply]"

echo "Each run creates five pairs (10 inbounds): H3/UDP and H2/TCP."

# Read the panel address directly from the 3x-ui settings database.
mapfile -t PANEL_SETTINGS < <(python3 - "$DB" <<'PY'
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
    raise SystemExit("Panel TLS is not configured in 3x-ui settings; cannot auto-build an HTTPS panel URL.")
if not domain:
    try:
        out = subprocess.check_output(["openssl", "x509", "-in", cert, "-noout", "-ext", "subjectAltName"], text=True, stderr=subprocess.DEVNULL)
        names = re.findall(r"DNS:([^,\\s]+)", out)
        if names:
            domain = names[0]
        else:
            ips = re.findall(r"IP Address:([^,\\s]+)", out)
            if ips:
                domain = ips[0]
    except Exception:
        pass
if not domain:
    raise SystemExit("Cannot determine panel hostname from webDomain or TLS certificate SAN.")
print("https")
print(domain)
print(port)
print(base)
PY
) || die "Failed to read panel URL from 3x-ui settings."
[[ "${#PANEL_SETTINGS[@]}" -eq 4 ]] || die "Unexpected panel settings response."
PANEL_SCHEME="${PANEL_SETTINGS[0]}"
PANEL_HOST="${PANEL_SETTINGS[1]}"
PANEL_PORT="${PANEL_SETTINGS[2]}"
PANEL_PATH="${PANEL_SETTINGS[3]}"
if [[ "$PANEL_HOST" == *:* && "$PANEL_HOST" != \\[*\\] ]]; then PANEL_HOST="[$PANEL_HOST]"; fi
BASE="${PANEL_SCHEME}://${PANEL_HOST}:${PANEL_PORT}${PANEL_PATH}"
echo "Panel URL auto-detected from 3x-ui database (URL path hidden)."

read -r -p "Server domain / TLS SNI (e.g. node.example.com): " DOMAIN
[[ -n "$DOMAIN" && "$DOMAIN" != *"/"* && "$DOMAIN" != *" "* ]] || die "Invalid TLS domain/SNI."
read -r -p "Full-chain certificate path: " CERT
read -r -p "Private-key path: " KEY
[[ -s "$CERT" && -s "$KEY" ]] || die "TLS certificate/key not found."
openssl x509 -in "$CERT" -noout -checkhost "$DOMAIN" >/dev/null || die "Certificate does not cover $DOMAIN."
openssl x509 -in "$CERT" -noout -checkend 86400 >/dev/null || die "Certificate expires within 24 hours."
openssl pkey -in "$KEY" -noout >/dev/null 2>&1 || die "Private key is unreadable."
read -r -p "Node name prefix: " PREFIX
[[ -n "$PREFIX" ]] || die "Name prefix is required."
read -r -p "H3 UDP starting port [8443]: " V; H3=${V:-8443}
read -r -p "H2 TCP starting port [9443]: " V; H2=${V:-9443}
for p in "$H3" "$H2"; do [[ "$p" =~ ^[0-9]+$ ]] && ((p>=1024 && p<=65531)) || die "Invalid starting port: $p"; done
(( H3+4 < H2 || H2+4 < H3 )) || die "H2 and H3 port ranges overlap."
read -r -p "XHTTP path prefix [/xhttp]: " V; PATH_PREFIX=${V:-/xhttp}
[[ "$PATH_PREFIX" == /* && "$PATH_PREFIX" != *" "* && "$PATH_PREFIX" != *"?"* && "$PATH_PREFIX" != *"#"* ]] || die "Invalid XHTTP path prefix."

TMP=$(mktemp -d /root/3xaddxhttp.XXXXXX)
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT
COOKIE="$TMP/cookie"
RESP="$TMP/response.json"
CURL=(curl -sS --connect-timeout 6 --max-time 30 -b "$COOKIE" -c "$COOKIE")

echo "Planned ports:"
for i in 0 1 2 3 4; do
  printf 'Pair %d: H3 UDP %d; H2 TCP %d; path %s/%02d\n' "$((i+1))" "$((H3+i))" "$((H2+i))" "$PATH_PREFIX" "$((i+1))"
done
echo "H2/H3 within each pair share one UUID. Each pair has a unique UUID."
read -r -p "3x-ui username: " USERNAME
read -r -s -p "3x-ui password: " PASSWORD; echo
read -r -p "2FA code (press Enter if disabled): " OTP
python3 - "$TMP/login.json" "$USERNAME" "$PASSWORD" "$OTP" <<'PY'
import json,sys,os
d={"username":sys.argv[2],"password":sys.argv[3]}
if sys.argv[4]: d["twoFactorCode"]=sys.argv[4]
with open(sys.argv[1],"w") as f: json.dump(d,f)
os.chmod(sys.argv[1],0o600)
PY
unset PASSWORD OTP

"${CURL[@]}" -H 'Content-Type: application/json' --data-binary "@$TMP/login.json" "$BASE/login" -o "$RESP" || die "Panel login request failed."
python3 - "$RESP" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
if not d.get("success"): raise SystemExit("Login failed: "+str(d.get("msg","unknown error")))
PY
rm -f "$TMP/login.json"

# Fetch current inbound list; this also validates that the configured API path works.
"${CURL[@]}" "$BASE/panel/api/inbounds/list" -o "$RESP" || die "Cannot read inbound list via API."
python3 - "$RESP" "$H3" "$H2" "$PREFIX" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
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
   "settings":{"clients":[{"id":uid,"email":f"xhttp-{i:02d}","enable":True,"flow":""}],"decryption":"none"},
   "streamSettings":{"network":"xhttp","security":"tls",
    "tlsSettings":{"minVersion":"1.3","alpn":alpn,"certificates":[{"certificateFile":cert,"keyFile":key}]},
    "xhttpSettings":{"path":p,"mode":"auto"}},
   "sniffing":{"enabled":True,"destOverride":["http","tls","quic"],"routeOnly":False}}
  with open(os.path.join(root,f"{i:02d}-{kind}.json"),"w") as f: json.dump(obj,f)
PY

if [[ "$MODE" == check ]]; then
 echo "Precheck only: no inbound has been created."
 echo "After reviewing the parameters, rerun with --apply."
 exit 0
fi

echo "This will add TEN inbounds. Existing inbounds are not deleted or replaced."
read -r -p "Type CREATE-10 to continue: " CONFIRM
[[ "$CONFIRM" == CREATE-10 ]] || die "Cancelled."

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
 "${CURL[@]}" -H 'Content-Type: application/json' --data-binary "@$f" "$BASE/panel/api/inbounds/add" -o "$RESP" || die "API request failed after $DONE creations. Check panel before retrying; backup: $BACKUP"
 python3 - "$RESP" <<'PY' || die "Panel rejected an inbound after $DONE creations. Check panel before retrying."
import json,sys
d=json.load(open(sys.argv[1]))
if not d.get("success"): raise SystemExit(str(d.get("msg","API returned failure")))
PY
 DONE=$((DONE+1))
done

echo "Submitted $DONE/10 inbounds. Backup: $BACKUP"
echo "H3 UDP ports: $H3-$((H3+4)); H2 TCP ports: $H2-$((H2+4))."
echo "Allow these UDP/TCP port ranges in your VPS provider firewall."
echo "No Hiddify services or ports 80/443 were modified."
echo "If any creation fails partway, inspect 3x-ui inbound list before rerunning."
