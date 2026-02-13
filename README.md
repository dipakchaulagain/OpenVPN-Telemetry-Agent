# OpenVPN Telemetry Installer (Non‑Blocking) – Ubuntu

This repository provides a **single setup script** that installs a **non-blocking** telemetry pipeline for an OpenVPN server.

The design goal is critical:

> **Telemetry must never break VPN authentication or client connectivity.**  
> If the telemetry server is unreachable, OpenVPN users should still connect and work normally.

---

## What this setup installs

Running `setup_openvpn_telemetry.sh` installs:

### 1) Local queue (spool)
- **Queue file:** `/var/spool/openvpn-telemetry/queue.log`
- **Pending chunks:** `/var/spool/openvpn-telemetry/pending/`
- **Sequence counter:** `/var/spool/openvpn-telemetry/seq`

OpenVPN hook scripts append events into the queue as **NDJSON** (one JSON object per line).

### 2) OpenVPN hook scripts (connect/disconnect)
- `/etc/openvpn/scripts/telemetry-connect.sh`
- `/etc/openvpn/scripts/telemetry-disconnect.sh`

These hooks:
- **only write locally**
- **do not call the external telemetry server**
- **always exit `0`** (never block OpenVPN)

Ownership/permissions are tuned for common OpenVPN deployments where scripts run as:
- `nobody:nogroup` (Ubuntu typical) or optionally `nobody:nobody`

### 3) Event writer helper
- `/usr/local/sbin/openvpn-telemetry-write-event`

This helper builds the event JSON from OpenVPN environment variables (e.g. `common_name`, `trusted_ip`, etc.) and appends it to the queue.

### 4) Telemetry agent (systemd service)
- Agent binary: `/usr/local/sbin/openvpn-telemetry-agent`
- systemd unit: `/etc/systemd/system/openvpn-telemetry-agent.service`
- Config: `/etc/openvpn-telemetry/agent.env`

The agent:
- rotates the queue file into **chunk files**
- sends chunk batches to your external telemetry server via **HTTPS POST**
- deletes chunks **only after successful delivery**
- retries automatically if the server is down

---

## Why this is “non-blocking” (safe for VPN)

OpenVPN can reject or delay client connections if a `client-connect` script:
- hangs
- runs long network calls
- exits non-zero

This setup avoids that completely:

✅ **Connect/disconnect scripts never perform network calls**  
✅ **They always exit 0**  
✅ **All network delivery happens asynchronously in the agent**  

So VPN continues normally even during telemetry outages.

---

## Minimum packages / dependencies

The installer uses only:
- `bash`
- `curl`
- `flock` (from `util-linux`)

If `curl` or `flock` are missing, the script installs them via `apt`.

---

## Telemetry payload format

The queue file uses **NDJSON** (one JSON object per line). The agent posts batches like:

```json
{
  "server_id": "vpn-ubuntu-01",
  "sent_at": "2026-02-13T12:10:10Z",
  "events": [
    {
      "event_id": "uuid",
      "seq": 123,
      "type": "SESSION_CONNECTED",
      "common_name": "alice",
      "real_ip": "1.2.3.4",
      "real_port": "5555",
      "virtual_ip": "10.8.0.6",
      "event_time_vpn": "2026-02-13T12:10:05Z"
    }
  ]
}
```

**Recommendation (server-side):**
- enforce **idempotency** using `event_id` as a unique key to ignore duplicates safely.

---

## Files created/managed by the installer

### Config / env
- Optional overrides: `/etc/openvpn-telemetry/.env`
- Generated agent config: `/etc/openvpn-telemetry/agent.env`

### Executables
- `/usr/local/sbin/openvpn-telemetry-agent`
- `/usr/local/sbin/openvpn-telemetry-write-event`

### OpenVPN hooks
- `/etc/openvpn/scripts/telemetry-connect.sh`
- `/etc/openvpn/scripts/telemetry-disconnect.sh`

### systemd
- `/etc/systemd/system/openvpn-telemetry-agent.service`

### Queue/spool
- `/var/spool/openvpn-telemetry/queue.log`
- `/var/spool/openvpn-telemetry/pending/`
- `/var/spool/openvpn-telemetry/seq`

---

## Installation

### 1) (Optional) Create override env file

Create `/etc/openvpn-telemetry/.env` **before** running the installer to override defaults:

```bash
sudo mkdir -p /etc/openvpn-telemetry
sudo tee /etc/openvpn-telemetry/.env >/dev/null <<'ENV'
TELEMETRY_URL="https://telemetry.example.com/api/v1/events"
SERVER_ID="vpn-ubuntu-01"

# If OpenVPN runs scripts under nobody:nobody (instead of nobody:nogroup)
# OPENVPN_SCRIPT_USER="nobody"
# OPENVPN_SCRIPT_GROUP="nobody"

# If you want the installer to patch your OpenVPN server config automatically:
# OPENVPN_SERVER_CONF="/etc/openvpn/server/server.conf"

# Rotation / retry tuning
ROTATE_INTERVAL_SECONDS=5
ROTATE_MAX_BYTES=131072
RETRY_SLEEP_SECONDS=2

# Optional auth (choose one):
# AUTH_HEADER="Authorization: Bearer YOURTOKEN"

# Optional mTLS (recommended):
# MTLS_ENABLED=1
# CLIENT_CERT="/etc/openvpn-telemetry/client.crt"
# CLIENT_KEY="/etc/openvpn-telemetry/client.key"
# CA_CERT="/etc/openvpn-telemetry/ca.crt"
ENV
```

### 2) Run the installer

```bash
sudo bash setup_openvpn_telemetry.sh
```

The script will:
- install minimal dependencies if missing
- write configs
- create spool directory & permissions
- install agent + writer
- install OpenVPN hooks
- install and start the systemd service

---

## OpenVPN configuration changes

If you **did not** set `OPENVPN_SERVER_CONF` in `.env`, you must add these lines to your OpenVPN server config manually:

```conf
script-security 2
client-connect /etc/openvpn/scripts/telemetry-connect.sh
client-disconnect /etc/openvpn/scripts/telemetry-disconnect.sh
```

Then restart OpenVPN.

> Common config paths:
> - `/etc/openvpn/server/server.conf`
> - `/etc/openvpn/server.conf`
> - systemd instances: `openvpn-server@server`

---

## Service management

Check agent status:

```bash
systemctl status openvpn-telemetry-agent --no-pager
```

Follow logs:

```bash
journalctl -u openvpn-telemetry-agent -f
```

Restart:

```bash
sudo systemctl restart openvpn-telemetry-agent
```

---

## Testing (without OpenVPN)

You can simulate an OpenVPN connect event by setting the same environment variables OpenVPN provides:

```bash
sudo -u nobody \
  common_name=testuser trusted_ip=1.2.3.4 trusted_port=5555 ifconfig_pool_remote_ip=10.8.0.99 \
  /usr/local/sbin/openvpn-telemetry-write-event SESSION_CONNECTED

tail -n 3 /var/spool/openvpn-telemetry/queue.log
```

If your script user is different (e.g., `nobody:nobody`), run as that user.

---

## Permissions model (important)

OpenVPN often runs with `user nobody` / `group nogroup`, causing hook scripts to execute as `nobody:nogroup`.

This installer ensures:
- `/var/spool/openvpn-telemetry` is **group-writable**
- queue and pending directories are writable by the OpenVPN script group

If your OpenVPN uses `nobody:nobody`, set in `.env`:

```bash
OPENVPN_SCRIPT_USER="nobody"
OPENVPN_SCRIPT_GROUP="nobody"
```

---

## Operational notes & best practices

### Time synchronization
To keep timestamp differences minimal, ensure both systems run NTP:
- On Ubuntu: `chrony` is recommended.

### Backpressure / disk safety
If the external telemetry server is down for a long time, chunk files will accumulate in:
- `/var/spool/openvpn-telemetry/pending/`

Tune:
- `MAX_PENDING_FILES`
- rotation settings

…and monitor disk usage.

### Idempotency
Because retries can cause duplicates, make `event_id` unique on the telemetry server.

---

## Troubleshooting

### 1) Agent is running but nothing arrives
- Check service logs:
  ```bash
  journalctl -u openvpn-telemetry-agent -n 200 --no-pager
  ```
- Verify URL is correct and reachable:
  ```bash
  curl -v https://telemetry.example.com/
  ```

### 2) Queue file is not writable
- Confirm OpenVPN script user/group and spool permissions:
  ```bash
  ls -ld /var/spool/openvpn-telemetry /var/spool/openvpn-telemetry/pending
  ls -l /var/spool/openvpn-telemetry/queue.log
  ```

### 3) VPN connections fail after enabling hooks
This should not happen with these scripts (they always exit 0), but if it does:
- verify OpenVPN has:
  ```conf
  script-security 2
  ```
- check OpenVPN logs for script errors
- ensure scripts are executable:
  ```bash
  ls -l /etc/openvpn/scripts/telemetry-*.sh
  ```

---

## Security options

### Bearer token header
Set:
```bash
AUTH_HEADER="Authorization: Bearer <token>"
```

### mTLS (recommended)
Set:
```bash
MTLS_ENABLED=1
CLIENT_CERT="/etc/openvpn-telemetry/client.crt"
CLIENT_KEY="/etc/openvpn-telemetry/client.key"
CA_CERT="/etc/openvpn-telemetry/ca.crt"
```

---

## What this does *not* include (yet)
This installer only covers **connect/disconnect** events.

Typical next additions:
- parsing `/var/log/openvpn/status.log` to emit periodic `SESSION_UPDATE` (bytes in/out)
- parsing Easy-RSA `index.txt` to track `valid/revoked/expired` status changes
- reconciliation snapshots

If you want, you can extend the same queue+agent pattern for those sources too.

