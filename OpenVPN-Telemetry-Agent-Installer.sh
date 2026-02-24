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
VALID_USERS_REF_FILE="$SPOOL_DIR/valid-users.ref"
CCD_STATE_DIR="$SPOOL_DIR/ccd-state"

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

  # Periodic metadata scanners
  OPENVPN_INDEX_FILE="${OPENVPN_INDEX_FILE:-/etc/openvpn/easy-rsa/pki/index.txt}"
  OPENVPN_CCD_DIR="${OPENVPN_CCD_DIR:-/etc/openvpn/ccd}"
  CCD_STATE_DIR="${CCD_STATE_DIR:-$SPOOL_DIR/ccd-state}"
  INDEX_SCAN_INTERVAL_SECONDS="${INDEX_SCAN_INTERVAL_SECONDS:-60}"
  CCD_SCAN_INTERVAL_SECONDS="${CCD_SCAN_INTERVAL_SECONDS:-60}"
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

# Optional user and CCD scanners
# OPENVPN_INDEX_FILE="/etc/openvpn/easy-rsa/pki/index.txt"
# OPENVPN_CCD_DIR="/etc/openvpn/ccd"
# CCD_STATE_DIR="/var/spool/openvpn-telemetry/ccd-state"
# INDEX_SCAN_INTERVAL_SECONDS=60
# CCD_SCAN_INTERVAL_SECONDS=60

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
VALID_USERS_REF_FILE="$VALID_USERS_REF_FILE"

ROTATE_INTERVAL_SECONDS=$ROTATE_INTERVAL_SECONDS
ROTATE_MAX_BYTES=$ROTATE_MAX_BYTES

RETRY_SLEEP_SECONDS=$RETRY_SLEEP_SECONDS
MAX_PENDING_FILES=$MAX_PENDING_FILES

OPENVPN_INDEX_FILE="$OPENVPN_INDEX_FILE"
OPENVPN_CCD_DIR="$OPENVPN_CCD_DIR"
CCD_STATE_DIR="$CCD_STATE_DIR"
INDEX_SCAN_INTERVAL_SECONDS=$INDEX_SCAN_INTERVAL_SECONDS
CCD_SCAN_INTERVAL_SECONDS=$CCD_SCAN_INTERVAL_SECONDS

AUTH_HEADER="$AUTH_HEADER"

MTLS_ENABLED=$MTLS_ENABLED
CLIENT_CERT="$CLIENT_CERT"
CLIENT_KEY="$CLIENT_KEY"
CA_CERT="$CA_CERT"

OPENVPN_SCRIPT_USER="$OPENVPN_SCRIPT_USER"
OPENVPN_SCRIPT_GROUP="$OPENVPN_SCRIPT_GROUP"
EOF

  chmod 0640 "$CONF_FILE"
  chown root:root "$CONF_FILE"

  log "Wrote agent config: $CONF_FILE"
}

setup_spool_permissions() {
  mkdir -p "$SPOOL_DIR" "$PENDING_DIR" "$CCD_STATE_DIR"
  touch "$QUEUE_FILE" "$SEQ_FILE" "$LOCK_FILE" || true

  # Critical: hooks may run as nobody:nogroup.
  chown -R root:"$OPENVPN_SCRIPT_GROUP" "$SPOOL_DIR"
  chmod 2770 "$SPOOL_DIR" "$PENDING_DIR" "$CCD_STATE_DIR"
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
mkdir -p "$CCD_STATE_DIR"

ensure_queue_permissions() {
  chmod 0660 "$QUEUE_FILE" 2>/dev/null || true
  if [[ -n "${OPENVPN_SCRIPT_GROUP:-}" ]]; then
    chgrp "$OPENVPN_SCRIPT_GROUP" "$QUEUE_FILE" 2>/dev/null || true
  fi
}

ensure_queue_permissions

log() { echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") openvpn-telemetry-agent: $*" >&2; }

json_escape() {
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

new_event_id() {
  cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null || echo "$RANDOM-$RANDOM-$RANDOM"
}

enqueue_json_line() {
  local line="$1"
  (
    umask 007
    echo "$line" >>"$QUEUE_FILE"
  ) >/dev/null 2>&1 || true
}

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
      ensure_queue_permissions
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

emit_users_update_event() {
  local cn="$1"
  local status="$2"
  local action="$3"
  local expires_at_index="${4:-}"
  local revoked_at_index="${5:-}"
  local ts eid line extras

  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  eid="$(new_event_id)"
  extras=""
  if [[ -n "$expires_at_index" ]]; then
    extras+=',"expires_at_index":"'"$(json_escape "$expires_at_index")"'"'
  fi
  if [[ -n "$revoked_at_index" ]]; then
    extras+=',"revoked_at_index":"'"$(json_escape "$revoked_at_index")"'"'
  fi
  line='{"event_id":"'"$(json_escape "$eid")"'","type":"USERS_UPDATE","common_name":"'"$(json_escape "$cn")"'","status":"'"$(json_escape "$status")"'","action":"'"$(json_escape "$action")"'"'"$extras"',"event_time_agent":"'"$(json_escape "$ts")"'"}'
  enqueue_json_line "$line"
}

emit_users_update_initial_bulk_event() {
  local users_file="$1"
  local ts eid line users_json cn st exp first

  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  eid="$(new_event_id)"
  users_json="["
  first=1

  while IFS=$'\t' read -r cn st exp; do
    [[ -n "$cn" ]] || continue
    if (( first == 0 )); then
      users_json+=","
    fi
    users_json+='{"common_name":"'"$(json_escape "$cn")"'","status":"'"$(json_escape "$st")"'","expires_at_index":"'"$(json_escape "$exp")"'"}'
    first=0
  done <"$users_file"

  users_json+="]"
  line='{"event_id":"'"$(json_escape "$eid")"'","type":"USERS_UPDATE","action":"INITIAL","source":"index.txt","event_time_agent":"'"$(json_escape "$ts")"'","users":'"$users_json"'}'
  enqueue_json_line "$line"
}

emit_users_update_added_bulk_event() {
  local added_cn_file="$1"
  local valid_users_file="$2"
  local ts eid line users_json cn exp first

  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  eid="$(new_event_id)"
  users_json="["
  first=1

  while IFS= read -r cn; do
    [[ -n "$cn" ]] || continue
    exp="$(awk -F '\t' -v k="$cn" '$1==k { print $2; exit }' "$valid_users_file")"
    if (( first == 0 )); then
      users_json+=","
    fi
    users_json+='{"common_name":"'"$(json_escape "$cn")"'","status":"VALID","expires_at_index":"'"$(json_escape "$exp")"'"}'
    first=0
  done <"$added_cn_file"

  users_json+="]"
  line='{"event_id":"'"$(json_escape "$eid")"'","type":"USERS_UPDATE","action":"ADDED","source":"index.txt","event_time_agent":"'"$(json_escape "$ts")"'","users":'"$users_json"'}'
  enqueue_json_line "$line"
}

build_index_snapshots() {
  local valid_out="$1"
  local status_out="$2"
  local active_out="$3"
  : >"$valid_out"
  : >"$status_out"
  : >"$active_out"
  [[ -r "$OPENVPN_INDEX_FILE" ]] || return 1

  awk -F '\t' -v valid_out="$valid_out" -v status_out="$status_out" -v active_out="$active_out" '
    {
      st = $1
      exp_at = $2
      rev = $3
      dn = $NF
      sub(/^.*\/CN=/, "", dn)
      cn = dn
      if (length(cn) == 0) {
        next
      }
      status[cn] = st
      expires[cn] = exp_at
      revoked[cn] = rev
    }
    END {
      for (cn in status) {
        printf "%s\t%s\t%s\t%s\n", cn, status[cn], expires[cn], revoked[cn] >> status_out
        if (status[cn] == "V") {
          printf "%s\t%s\n", cn, expires[cn] >> valid_out
        } else if (status[cn] == "E") {
          printf "%s\t%s\t%s\n", cn, status[cn], expires[cn] >> active_out
        }
        if (status[cn] == "V") {
          printf "%s\t%s\t%s\n", cn, status[cn], expires[cn] >> active_out
        }
      }
    }
  ' "$OPENVPN_INDEX_FILE"

  sort -u -o "$valid_out" "$valid_out"
  sort -u -o "$status_out" "$status_out"
  sort -u -o "$active_out" "$active_out"
}

scan_index_and_emit_user_updates() {
  local cur_valid cur_status cur_active tmp_add tmp_rem prev_cn cur_cn cn exp st rev
  cur_valid="$(mktemp)"
  cur_status="$(mktemp)"
  cur_active="$(mktemp)"
  tmp_add="$(mktemp)"
  tmp_rem="$(mktemp)"
  prev_cn="$(mktemp)"
  cur_cn="$(mktemp)"

  if ! build_index_snapshots "$cur_valid" "$cur_status" "$cur_active"; then
    log "WARNING: index file unreadable: $OPENVPN_INDEX_FILE"
    rm -f "$cur_valid" "$cur_status" "$cur_active" "$tmp_add" "$tmp_rem" "$prev_cn" "$cur_cn"
    return 1
  fi

  if [[ ! -f "$VALID_USERS_REF_FILE" ]]; then
    cp "$cur_valid" "$VALID_USERS_REF_FILE" 2>/dev/null || true
    emit_users_update_initial_bulk_event "$cur_valid"
    log "Users reference initialized from index file."
    rm -f "$cur_valid" "$cur_status" "$cur_active" "$tmp_add" "$tmp_rem" "$prev_cn" "$cur_cn"
    return 0
  fi

  cut -f1 "$VALID_USERS_REF_FILE" | sort -u >"$prev_cn"
  cut -f1 "$cur_valid" | sort -u >"$cur_cn"

  comm -13 "$prev_cn" "$cur_cn" >"$tmp_add" || true
  if [[ -s "$tmp_add" ]]; then
    emit_users_update_added_bulk_event "$tmp_add" "$cur_valid"
  fi

  comm -23 "$prev_cn" "$cur_cn" >"$tmp_rem" || true
  while IFS= read -r cn; do
    [[ -n "$cn" ]] || continue
    st="$(awk -F '\t' -v k="$cn" '$1==k { print $2; exit }' "$cur_status")"
    exp="$(awk -F '\t' -v k="$cn" '$1==k { print $3; exit }' "$cur_status")"
    rev="$(awk -F '\t' -v k="$cn" '$1==k { print $4; exit }' "$cur_status")"

    if [[ "$st" == "R" ]]; then
      emit_users_update_event "$cn" "REVOKED" "REVOKED" "" "$rev"
    elif [[ "$st" == "E" ]]; then
      emit_users_update_event "$cn" "EXPIRED" "EXPIRED" "$exp" ""
    else
      emit_users_update_event "$cn" "UNKNOWN" "REMOVED" "$exp" "$rev"
    fi
  done <"$tmp_rem"

  cp "$cur_valid" "$VALID_USERS_REF_FILE" 2>/dev/null || true
  rm -f "$cur_valid" "$cur_status" "$cur_active" "$tmp_add" "$tmp_rem" "$prev_cn" "$cur_cn"
}

emit_ccd_info_event() {
  local cn="$1"
  local ccd_file="$2"
  local content_b64 ts eid line

  content_b64="$(base64 "$ccd_file" 2>/dev/null | tr -d '\n')"
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  eid="$(new_event_id)"
  line='{"event_id":"'"$(json_escape "$eid")"'","type":"CCD_INFO","common_name":"'"$(json_escape "$cn")"'","ccd_path":"'"$(json_escape "$ccd_file")"'","ccd_content_b64":"'"$(json_escape "$content_b64")"'","event_time_agent":"'"$(json_escape "$ts")"'"}'
  enqueue_json_line "$line"
}

file_hash() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
    return 0
  fi
  cksum "$path" | awk '{print $1 ":" $2}'
}

ccd_state_file_for_cn() {
  local cn="$1"
  local key
  key="$(printf '%s' "$cn" | tr -c 'A-Za-z0-9._-' '_')"
  printf '%s/%s.hash' "$CCD_STATE_DIR" "$key"
}

ccd_should_emit() {
  local cn="$1"
  local ccd_file="$2"
  local state_file old_hash new_hash

  state_file="$(ccd_state_file_for_cn "$cn")"
  new_hash="$(file_hash "$ccd_file")"
  old_hash="$(cat "$state_file" 2>/dev/null || true)"

  if [[ "$new_hash" == "$old_hash" ]]; then
    return 1
  fi

  printf '%s\n' "$new_hash" >"$state_file"
  chmod 0660 "$state_file" 2>/dev/null || true
  if [[ -n "${OPENVPN_SCRIPT_GROUP:-}" ]]; then
    chgrp "$OPENVPN_SCRIPT_GROUP" "$state_file" 2>/dev/null || true
  fi
  return 0
}

scan_ccd_and_emit_info() {
  local f cn
  [[ -d "$OPENVPN_CCD_DIR" ]] || return 0
  [[ -r "$VALID_USERS_REF_FILE" ]] || return 0

  while IFS= read -r f; do
    cn="$(basename "$f")"
    [[ -n "$cn" ]] || continue
    if awk -F '\t' -v k="$cn" '$1==k { found=1; exit } END { exit !found }' "$VALID_USERS_REF_FILE"; then
      if ccd_should_emit "$cn" "$f"; then
        emit_ccd_info_event "$cn" "$f"
      fi
    fi
  done < <(find "$OPENVPN_CCD_DIR" -maxdepth 1 -type f | sort)
}

log "Started. url=$TELEMETRY_URL server_id=$SERVER_ID"
LAST_INDEX_SCAN=0
LAST_CCD_SCAN=0
while true; do
  now_epoch="$(date +%s)"
  if (( now_epoch - LAST_INDEX_SCAN >= INDEX_SCAN_INTERVAL_SECONDS )); then
    scan_index_and_emit_user_updates || true
    LAST_INDEX_SCAN="$now_epoch"
  fi
  if (( now_epoch - LAST_CCD_SCAN >= CCD_SCAN_INTERVAL_SECONDS )); then
    scan_ccd_and_emit_info || true
    LAST_CCD_SCAN="$now_epoch"
  fi

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
  local line extras
  extras=""
  if [[ -n "$REAL_IP" ]]; then
    extras+=',"real_ip":"'"$(json_escape "$REAL_IP")"'"'
  fi
  if [[ -n "$VIRT_IP" ]]; then
    extras+=',"virtual_ip":"'"$(json_escape "$VIRT_IP")"'"'
  fi

  line='{"event_id":"'"$(json_escape "$EVENT_ID")"'","type":"'"$(json_escape "$EVENT_TYPE")"'","common_name":"'"$(json_escape "$CN")"'","event_time_vpn":"'"$(json_escape "$EVENT_TIME")"'"'"$extras"'}'

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

is_already_installed() {
  [[ -f "$SYSTEMD_UNIT" ]] || [[ -x "$AGENT_BIN" ]] || [[ -x "$WRITER_BIN" ]] || [[ -f "$CONNECT_HOOK" ]] || [[ -f "$DISCONNECT_HOOK" ]] || [[ -d "$CONF_DIR" ]] || [[ -d "$SPOOL_DIR" ]]
}

remove_hook_lines_from_conf() {
  local conf="$1"
  [[ -f "$conf" ]] || return 0

  sed -i -E "\|^[[:space:]]*client-connect[[:space:]]+$CONNECT_HOOK[[:space:]]*$|d" "$conf" || true
  sed -i -E "\|^[[:space:]]*client-disconnect[[:space:]]+$DISCONNECT_HOOK[[:space:]]*$|d" "$conf" || true
}

uninstall_telemetry() {
  log "Uninstalling OpenVPN telemetry components..."

  systemctl disable --now openvpn-telemetry-agent.service >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_UNIT"
  systemctl daemon-reload || true

  rm -f "$AGENT_BIN" "$WRITER_BIN"
  rm -f "$CONNECT_HOOK" "$DISCONNECT_HOOK"
  rm -rf "$CONF_DIR" "$SPOOL_DIR"

  remove_hook_lines_from_conf "/etc/openvpn/server/server.conf"
  remove_hook_lines_from_conf "/etc/openvpn/server.conf"
  if [[ -n "${OPENVPN_SERVER_CONF:-}" ]]; then
    remove_hook_lines_from_conf "$OPENVPN_SERVER_CONF"
  fi

  log "Uninstall complete."
  log "Restart OpenVPN service if you removed client-connect/client-disconnect lines."
}

choose_install_action() {
  local choice

  if [[ ! -t 0 ]]; then
    echo "reinstall"
    return 0
  fi

  echo
  echo "OpenVPN telemetry is already installed."
  echo "Select action:"
  echo "  1) Uninstall"
  echo "  2) Reinstall"
  echo "  3) Exit"
  read -r -p "Enter choice [1-3]: " choice

  case "$choice" in
    1) echo "uninstall" ;;
    2) echo "reinstall" ;;
    *) echo "exit" ;;
  esac
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
  local action="install"
  need_root

  if is_already_installed; then
    action="$(choose_install_action)"
    case "$action" in
      uninstall)
        uninstall_telemetry
        exit 0
        ;;
      reinstall)
        log "Reinstall selected."
        ;;
      *)
        log "No action taken."
        exit 0
        ;;
    esac
  fi

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
