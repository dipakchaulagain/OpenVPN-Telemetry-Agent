#!/usr/bin/env bash
# setup_openvpn_telemetry.sh
#
# Non-blocking OpenVPN telemetry installer for Ubuntu/Debian/CentOS/RHEL:
# - OpenVPN client-connect/client-disconnect hooks append NDJSON events locally
# - A small agent ships queued events to an external telemetry server over HTTPS
# - If telemetry server is down, VPN still works (scripts always exit 0)
# - Queue rotates to chunks and deletes delivered chunks (no endless growth)
#
# Usage:
#   sudo bash setup_openvpn_telemetry.sh
#
# Optional config:
#   /etc/openvpn-telemetry/.env

set -euo pipefail

# ---------- Paths ----------
ENV_FILE="/etc/openvpn-telemetry/.env"
ENV_EXAMPLE_FILE="/etc/openvpn-telemetry/.env.example"
CONF_DIR="/etc/openvpn-telemetry"
CONF_FILE="$CONF_DIR/agent.env"

AGENT_BIN="/usr/local/sbin/openvpn-telemetry-agent"
WRITER_BIN="/usr/local/sbin/openvpn-telemetry-write-event"

OPENVPN_SCRIPTS_DIR="/etc/openvpn/scripts"
CONNECT_HOOK="$OPENVPN_SCRIPTS_DIR/telemetry-connect.sh"
DISCONNECT_HOOK="$OPENVPN_SCRIPTS_DIR/telemetry-disconnect.sh"

SYSTEMD_UNIT="/etc/systemd/system/openvpn-telemetry-agent.service"

SPOOL_DIR="/var/spool/openvpn-telemetry"
QUEUE_FILE="$SPOOL_DIR/queue.log"
PENDING_DIR="$SPOOL_DIR/pending"
SEQ_FILE="$SPOOL_DIR/seq"
LOCK_FILE="$SPOOL_DIR/writer.lock"

# ---------- Helpers ----------
need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: Run as root (sudo)."
    exit 1
  fi
}

log() { echo "[setup] $*"; }

get_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  else
    echo ""
  fi
}

install_package() {
  local pkg="$1"
  local pm
  pm="$(get_pkg_manager)"

  case "$pm" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
      ;;
    dnf)
      dnf install -y "$pkg"
      ;;
    yum)
      yum install -y "$pkg"
      ;;
    *)
      log "ERROR: No supported package manager found (apt, dnf, yum)."
      exit 1
      ;;
  esac
}

ensure_min_deps() {
  # Minimal deps: curl, util-linux (flock)
  if ! command -v curl >/dev/null 2>&1; then
    log "curl not found -> installing curl"
    install_package curl
  fi

  if ! command -v flock >/dev/null 2>&1; then
    log "flock not found -> installing util-linux"
    install_package util-linux
  fi
}

detect_openvpn_script_user_group() {
  # If OpenVPN is configured with user/group directives, you can set these in .env:
  #   OPENVPN_SCRIPT_USER=nobody
  #   OPENVPN_SCRIPT_GROUP=nogroup
  OPENVPN_SCRIPT_USER="${OPENVPN_SCRIPT_USER:-nobody}"
  OPENVPN_SCRIPT_GROUP="${OPENVPN_SCRIPT_GROUP:-nogroup}"

  # Some systems use nobody:nobody. If nogroup doesn't exist, fallback to nobody.
  if ! getent group "$OPENVPN_SCRIPT_GROUP" >/dev/null 2>&1; then
    if getent group nobody >/dev/null 2>&1; then
      OPENVPN_SCRIPT_GROUP="nobody"
    fi
  fi

  # Ensure user exists; if not, fallback to nobody.
  if ! id -u "$OPENVPN_SCRIPT_USER" >/dev/null 2>&1; then
    OPENVPN_SCRIPT_USER="nobody"
  fi

  log "OpenVPN hook execution user/group assumed: ${OPENVPN_SCRIPT_USER}:${OPENVPN_SCRIPT_GROUP}"
}

load_env_defaults() {
  SERVER_ID="${SERVER_ID:-$(hostname -f 2>/dev/null || hostname)}"

  ROTATE_INTERVAL_SECONDS="${ROTATE_INTERVAL_SECONDS:-5}"    # low latency
  ROTATE_MAX_BYTES="${ROTATE_MAX_BYTES:-131072}"             # 128 KB

  RETRY_SLEEP_SECONDS="${RETRY_SLEEP_SECONDS:-2}"
  MAX_PENDING_FILES="${MAX_PENDING_FILES:-5000}"

  AUTH_HEADER="${AUTH_HEADER:-}"                             # e.g. "Authorization: Bearer xxxx"

  # mTLS optional
  MTLS_ENABLED="${MTLS_ENABLED:-0}"
  CLIENT_CERT="${CLIENT_CERT:-/etc/openvpn-telemetry/client.crt}"
  CLIENT_KEY="${CLIENT_KEY:-/etc/openvpn-telemetry/client.key}"
  CA_CERT="${CA_CERT:-/etc/openvpn-telemetry/ca.crt}"

  # Optional autopatch of OpenVPN config:
  OPENVPN_SERVER_CONF="${OPENVPN_SERVER_CONF:-}"

  # OpenVPN hook user/group overrides
  OPENVPN_SCRIPT_USER="${OPENVPN_SCRIPT_USER:-nobody}"
  OPENVPN_SCRIPT_GROUP="${OPENVPN_SCRIPT_GROUP:-nogroup}"
}

write_env_example() {
  mkdir -p "$CONF_DIR"
  cat >"$ENV_EXAMPLE_FILE" <<EOF
# Required: telemetry ingestion endpoint
TELEMETRY_URL="https://telemetry.your-domain.tld/api/v1/events"

# Optional identity
# SERVER_ID="vpn-node-01"

# Optional: if OpenVPN hooks run as nobody:nobody
# OPENVPN_SCRIPT_USER="nobody"
# OPENVPN_SCRIPT_GROUP="nobody"

# Optional auto-patch OpenVPN config
# OPENVPN_SERVER_CONF="/etc/openvpn/server/server.conf"

# Rotation & retry
# ROTATE_INTERVAL_SECONDS=5
# ROTATE_MAX_BYTES=131072
# RETRY_SLEEP_SECONDS=2
# MAX_PENDING_FILES=5000

# Auth option A: HTTP header
# AUTH_HEADER="Authorization: Bearer YOURTOKEN"

# Auth option B: mTLS
# MTLS_ENABLED=1
# CLIENT_CERT="/etc/openvpn-telemetry/client.crt"
# CLIENT_KEY="/etc/openvpn-telemetry/client.key"
# CA_CERT="/etc/openvpn-telemetry/ca.crt"
EOF
  chmod 0640 "$ENV_EXAMPLE_FILE"
  chown root:root "$ENV_EXAMPLE_FILE"
}

read_env_file_if_present() {
  if [[ -r "$ENV_FILE" ]]; then
    log "Loading $ENV_FILE"
    # shellcheck disable=SC1090
    source "$ENV_FILE"
  else
    log "No $ENV_FILE found. Creating template: $ENV_EXAMPLE_FILE"
  fi

  load_env_defaults
  write_env_example

  TELEMETRY_URL="${TELEMETRY_URL:-}"
  if [[ -z "$TELEMETRY_URL" ]]; then
    log "ERROR: TELEMETRY_URL is required."
    log "Set TELEMETRY_URL in $ENV_FILE (copy from $ENV_EXAMPLE_FILE)."
    exit 1
  fi
}

write_agent_conf() {
  mkdir -p "$CONF_DIR"
  chmod 0750 "$CONF_DIR"

  cat >"$CONF_FILE" <<EOF
# Generated by setup_openvpn_telemetry.sh
TELEMETRY_URL="$TELEMETRY_URL"
SERVER_ID="$SERVER_ID"

QUEUE_FILE="$QUEUE_FILE"
PENDING_DIR="$PENDING_DIR"
SEQ_FILE="$SEQ_FILE"
LOCK_FILE="$LOCK_FILE"

ROTATE_INTERVAL_SECONDS=$ROTATE_INTERVAL_SECONDS
ROTATE_MAX_BYTES=$ROTATE_MAX_BYTES

RETRY_SLEEP_SECONDS=$RETRY_SLEEP_SECONDS
MAX_PENDING_FILES=$MAX_PENDING_FILES

AUTH_HEADER="$AUTH_HEADER"

MTLS_ENABLED=$MTLS_ENABLED
CLIENT_CERT="$CLIENT_CERT"
CLIENT_KEY="$CLIENT_KEY"
CA_CERT="$CA_CERT"
EOF

  chmod 0640 "$CONF_FILE"
  chown root:root "$CONF_FILE"

  log "Wrote agent config: $CONF_FILE"
}

setup_spool_permissions() {
  mkdir -p "$SPOOL_DIR" "$PENDING_DIR"
  touch "$QUEUE_FILE" "$SEQ_FILE" "$LOCK_FILE" || true

  # Critical: hooks may run as nobody:nogroup.
  chown -R root:"$OPENVPN_SCRIPT_GROUP" "$SPOOL_DIR"
  chmod 0770 "$SPOOL_DIR" "$PENDING_DIR"
  chmod 0660 "$QUEUE_FILE" "$SEQ_FILE" "$LOCK_FILE" || true

  if [[ ! -s "$SEQ_FILE" ]]; then
    echo "0" >"$SEQ_FILE" || true
    chmod 0660 "$SEQ_FILE" || true
  fi

  log "Prepared spool with group write for ${OPENVPN_SCRIPT_GROUP}: $SPOOL_DIR"
}

install_agent() {
  cat >"$AGENT_BIN" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF="/etc/openvpn-telemetry/agent.env"
[[ -r "$CONF" ]] || { echo "Missing $CONF" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONF"

mkdir -p "$PENDING_DIR"
touch "$QUEUE_FILE"

log() { echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") openvpn-telemetry-agent: $*" >&2; }

# Single instance lock
LOCK_FD=200
AGENT_LOCK_FILE="/run/openvpn-telemetry-agent.lock"
exec {LOCK_FD}>"$AGENT_LOCK_FILE"
flock -n "$LOCK_FD" || { log "Agent already running"; exit 0; }

LAST_ROTATE=0

rotate_queue_if_needed() {
  local now size
  now="$(date +%s)"
  size="$(stat -c%s "$QUEUE_FILE" 2>/dev/null || echo 0)"

  if (( now - LAST_ROTATE >= ROTATE_INTERVAL_SECONDS )) || (( size >= ROTATE_MAX_BYTES )); then
    if (( size > 0 )); then
      local chunk="$PENDING_DIR/chunk.$(date -u +%Y%m%dT%H%M%SZ).$$.log"
      # atomic rename
      mv "$QUEUE_FILE" "$chunk" || return 0
      : > "$QUEUE_FILE"
      chmod 0660 "$QUEUE_FILE" || true
      log "Rotated queue -> $(basename "$chunk") (size=$size)"
    fi
    LAST_ROTATE="$now"
  fi
}

post_file() {
  local file="$1"
  local tmp sent_at
  tmp="$(mktemp)"
  sent_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  # Batch JSON: {"server_id":"...","sent_at":"...","events":[...]}
  {
    printf '{"server_id":"%s","sent_at":"%s","events":[' \
      "${SERVER_ID//\"/\\\"}" "$sent_at"
    awk 'BEGIN{first=1} NF{ if(!first) printf ","; printf "%s",$0; first=0 }' "$file"
    printf ']}'
  } >"$tmp"

  local curl_args=(
    --silent --show-error --fail
    --connect-timeout 2
    --max-time 10
    -H "Content-Type: application/json"
  )

  if [[ -n "${AUTH_HEADER:-}" ]]; then
    curl_args+=(-H "$AUTH_HEADER")
  fi

  if [[ "${MTLS_ENABLED:-0}" == "1" ]]; then
    curl_args+=(--cert "$CLIENT_CERT" --key "$CLIENT_KEY" --cacert "$CA_CERT")
  fi

  if curl "${curl_args[@]}" -X POST "$TELEMETRY_URL" --data-binary @"$tmp" >/dev/null; then
    rm -f "$tmp"
    return 0
  fi

  rm -f "$tmp"
  return 1
}

send_pending() {
  local count
  count="$(find "$PENDING_DIR" -maxdepth 1 -type f -name 'chunk.*.log' | wc -l | tr -d ' ')"
  if (( count > MAX_PENDING_FILES )); then
    log "WARNING: pending chunk files=$count exceeds limit=$MAX_PENDING_FILES"
  fi

  local f
  while IFS= read -r f; do
    if post_file "$f"; then
      rm -f "$f"
      log "Delivered: $(basename "$f")"
    else
      log "Delivery failed: $(basename "$f")"
      return 1
    fi
  done < <(find "$PENDING_DIR" -maxdepth 1 -type f -name 'chunk.*.log' -printf '%T@ %p\n' | sort -n | awk '{print $2}')
}

log "Started. url=$TELEMETRY_URL server_id=$SERVER_ID"
while true; do
  rotate_queue_if_needed || true
  send_pending || sleep "$RETRY_SLEEP_SECONDS"
  sleep 1
done
EOF

  chmod 0755 "$AGENT_BIN"
  chown root:root "$AGENT_BIN"
  log "Installed agent: $AGENT_BIN"
}

install_writer() {
  cat >"$WRITER_BIN" <<'EOF'
#!/usr/bin/env bash
# Non-blocking event writer for OpenVPN hooks.
# ALWAYS exits 0 to never block VPN authentication/connect.

set -u

CONF="/etc/openvpn-telemetry/agent.env"
if [[ -r "$CONF" ]]; then
  # shellcheck disable=SC1090
  source "$CONF"
fi

QUEUE_FILE="${QUEUE_FILE:-/var/spool/openvpn-telemetry/queue.log}"
SEQ_FILE="${SEQ_FILE:-/var/spool/openvpn-telemetry/seq}"
LOCK_FILE="${LOCK_FILE:-/var/spool/openvpn-telemetry/writer.lock}"

EVENT_TYPE="${1:-UNKNOWN}"

# OpenVPN exports these env vars to scripts:
CN="${common_name:-unknown}"
REAL_IP="${trusted_ip:-}"
REAL_PORT="${trusted_port:-}"
VIRT_IP="${ifconfig_pool_remote_ip:-}"

EVENT_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
EVENT_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "$RANDOM-$RANDOM-$RANDOM")"

json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

append_event() {
  local seq line
  seq="0"

  # Non-blocking lock keeps hook fast and prevents seq corruption under concurrency.
  if exec 9>"$LOCK_FILE" 2>/dev/null; then
    if flock -w 0.05 9 2>/dev/null; then
      if [[ -r "$SEQ_FILE" ]]; then
        seq="$(cat "$SEQ_FILE" 2>/dev/null || echo 0)"
      fi
      case "$seq" in
        ''|*[!0-9]*) seq=0 ;;
      esac
      seq=$((seq + 1))
      echo "$seq" >"$SEQ_FILE" 2>/dev/null || true
    fi
  fi

  line='{"event_id":"'"$(json_escape "$EVENT_ID")"'","seq":'"$seq"',"type":"'"$(json_escape "$EVENT_TYPE")"'","common_name":"'"$(json_escape "$CN")"'","real_ip":"'"$(json_escape "$REAL_IP")"'","real_port":"'"$(json_escape "$REAL_PORT")"'","virtual_ip":"'"$(json_escape "$VIRT_IP")"'","event_time_vpn":"'"$(json_escape "$EVENT_TIME")"'"}'

  (
    umask 007
    echo "$line" >>"$QUEUE_FILE"
  ) >/dev/null 2>&1 || true
}

append_event || true
exit 0
EOF

  chmod 0755 "$WRITER_BIN"
  chown root:root "$WRITER_BIN"
  log "Installed writer: $WRITER_BIN"
}

install_hooks() {
  mkdir -p "$OPENVPN_SCRIPTS_DIR"
  chmod 0755 "$OPENVPN_SCRIPTS_DIR"

  cat >"$CONNECT_HOOK" <<EOF
#!/usr/bin/env bash
$WRITER_BIN SESSION_CONNECTED >/dev/null 2>&1 || true
exit 0
EOF

  cat >"$DISCONNECT_HOOK" <<EOF
#!/usr/bin/env bash
$WRITER_BIN SESSION_DISCONNECTED >/dev/null 2>&1 || true
exit 0
EOF

  chmod 0755 "$CONNECT_HOOK" "$DISCONNECT_HOOK"
  chown "$OPENVPN_SCRIPT_USER":"$OPENVPN_SCRIPT_GROUP" "$CONNECT_HOOK" "$DISCONNECT_HOOK" || true

  log "Installed OpenVPN hooks:"
  log "  $CONNECT_HOOK"
  log "  $DISCONNECT_HOOK"
}

install_systemd() {
  cat >"$SYSTEMD_UNIT" <<EOF
[Unit]
Description=OpenVPN Telemetry Agent (non-blocking)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_BIN
Restart=always
RestartSec=2
Nice=10

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$SPOOL_DIR /run
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now openvpn-telemetry-agent.service
  log "Enabled service: openvpn-telemetry-agent"
}

patch_openvpn_conf_if_requested() {
  if [[ -z "${OPENVPN_SERVER_CONF:-}" ]]; then
    log "OPENVPN_SERVER_CONF not set; not editing OpenVPN config."
    log "Add these lines to your OpenVPN server config manually:"
    echo "  script-security 2"
    echo "  client-connect $CONNECT_HOOK"
    echo "  client-disconnect $DISCONNECT_HOOK"
    return 0
  fi

  if [[ ! -f "$OPENVPN_SERVER_CONF" ]]; then
    log "WARNING: OPENVPN_SERVER_CONF '$OPENVPN_SERVER_CONF' not found; skipping patch."
    return 0
  fi

  log "Patching OpenVPN config: $OPENVPN_SERVER_CONF"
  grep -qE '^\s*script-security\s+2' "$OPENVPN_SERVER_CONF" || echo "script-security 2" >>"$OPENVPN_SERVER_CONF"
  grep -qF "client-connect $CONNECT_HOOK" "$OPENVPN_SERVER_CONF" || echo "client-connect $CONNECT_HOOK" >>"$OPENVPN_SERVER_CONF"
  grep -qF "client-disconnect $DISCONNECT_HOOK" "$OPENVPN_SERVER_CONF" || echo "client-disconnect $DISCONNECT_HOOK" >>"$OPENVPN_SERVER_CONF"

  log "Patched OpenVPN config. Restart OpenVPN to apply."
}

print_summary() {
  cat <<EOF

OpenVPN telemetry installed (non-blocking).

Agent config:
  $CONF_FILE

Environment template:
  $ENV_EXAMPLE_FILE

Queue/spool:
  $QUEUE_FILE
  $PENDING_DIR

Service:
  systemctl status openvpn-telemetry-agent --no-pager
  journalctl -u openvpn-telemetry-agent -f

OpenVPN directives needed:
  script-security 2
  client-connect $CONNECT_HOOK
  client-disconnect $DISCONNECT_HOOK

Test a local event append (no OpenVPN needed):
  sudo -u $OPENVPN_SCRIPT_USER common_name=testuser trusted_ip=1.2.3.4 trusted_port=5555 ifconfig_pool_remote_ip=10.8.0.99 \\
    $WRITER_BIN SESSION_CONNECTED
  tail -n 3 $QUEUE_FILE

EOF
}

main() {
  need_root
  ensure_min_deps
  read_env_file_if_present
  detect_openvpn_script_user_group
  write_agent_conf
  setup_spool_permissions
  install_agent
  install_writer
  install_hooks
  install_systemd
  patch_openvpn_conf_if_requested
  print_summary
}

main
