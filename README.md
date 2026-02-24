# OpenVPN Telemetry Agent Installer (Non-Blocking)

This repository provides one installer script:

- `OpenVPN-Telemetry-Agent-Installer.sh`

It deploys a telemetry pipeline for OpenVPN where telemetry failures never block VPN client connections.

## Design Goal

Telemetry must never break VPN authentication or client connectivity.

How this is enforced:

- OpenVPN hooks only append events locally.
- Hooks always exit `0`.
- Network delivery is done asynchronously by a background systemd service.

## Supported Platforms

The installer supports package installation via:

- `apt` (Ubuntu/Debian)
- `dnf` (RHEL/Fedora family)
- `yum` (CentOS 7)

Your CentOS 7 profile is supported:

- `ID="centos"`
- `VERSION_ID="7"`

## What Gets Installed

### Files and paths

- Optional env overrides: `/etc/openvpn-telemetry/.env`
- Generated env template: `/etc/openvpn-telemetry/.env.example`
- Generated runtime config: `/etc/openvpn-telemetry/agent.env`
- Writer binary: `/usr/local/sbin/openvpn-telemetry-write-event`
- Agent binary: `/usr/local/sbin/openvpn-telemetry-agent`
- OpenVPN connect hook: `/etc/openvpn/scripts/telemetry-connect.sh`
- OpenVPN disconnect hook: `/etc/openvpn/scripts/telemetry-disconnect.sh`
- systemd unit: `/etc/systemd/system/openvpn-telemetry-agent.service`
- Queue file: `/var/spool/openvpn-telemetry/queue.log`
- Pending chunks: `/var/spool/openvpn-telemetry/pending/`
- Sequence counter: `/var/spool/openvpn-telemetry/seq`
- Writer lock: `/var/spool/openvpn-telemetry/writer.lock`

### Runtime behavior

- Hooks write NDJSON events to `queue.log`.
- Agent periodically scans Easy-RSA index and emits `USERS_UPDATE` events.
- Agent scans CCD files for valid users and emits `CCD_INFO` only on first seen content and when content changes.
- Agent rotates queue into chunks.
- Agent posts batches to `TELEMETRY_URL` over HTTPS.
- Chunks are deleted only after successful delivery.
- On failure, chunks are retried.

## Required Configuration

`TELEMETRY_URL` is required.

Create `/etc/openvpn-telemetry/.env` before running installer:

```bash
sudo mkdir -p /etc/openvpn-telemetry
sudo tee /etc/openvpn-telemetry/.env >/dev/null <<'EOF'
TELEMETRY_URL="https://telemetry.example.com/api/v1/events"

# Optional
# SERVER_ID="vpn-centos7-01"
# OPENVPN_SCRIPT_USER="nobody"
# OPENVPN_SCRIPT_GROUP="nobody"
# OPENVPN_SERVER_CONF="/etc/openvpn/server/server.conf"

# Optional user and CCD scanners
# OPENVPN_INDEX_FILE="/etc/openvpn/easy-rsa/pki/index.txt"
# OPENVPN_CCD_DIR="/etc/openvpn/ccd"
# CCD_STATE_DIR="/var/spool/openvpn-telemetry/ccd-state"
# INDEX_SCAN_INTERVAL_SECONDS=60
# CCD_SCAN_INTERVAL_SECONDS=60

# Rotation and retry
# ROTATE_INTERVAL_SECONDS=5
# ROTATE_MAX_BYTES=131072
# RETRY_SLEEP_SECONDS=2
# MAX_PENDING_FILES=5000

# Auth option A
# AUTH_HEADER="Authorization: Bearer YOURTOKEN"

# Auth option B (mTLS)
# MTLS_ENABLED=1
# CLIENT_CERT="/etc/openvpn-telemetry/client.crt"
# CLIENT_KEY="/etc/openvpn-telemetry/client.key"
# CA_CERT="/etc/openvpn-telemetry/ca.crt"
EOF
```

If `.env` does not exist, installer will generate `.env.example` and exit until `TELEMETRY_URL` is provided.

## Installation

Run:

```bash
sudo bash OpenVPN-Telemetry-Agent-Installer.sh
```

If already installed, installer shows a menu:

- `1) Uninstall`
- `2) Reinstall`
- `3) Exit`

If run non-interactively (no TTY), it defaults to `Reinstall`.

Installer actions:

- installs missing dependencies (`curl`, `util-linux` for `flock`)
- writes config and spool permissions
- installs writer and agent
- installs hooks
- installs and starts systemd service
- optionally patches OpenVPN config if `OPENVPN_SERVER_CONF` is set

## Uninstall / Reinstall

Run the same installer:

```bash
sudo bash OpenVPN-Telemetry-Agent-Installer.sh
```

When prompted:

- Choose `1` to uninstall telemetry components
- Choose `2` to reinstall
- Choose `3` to exit without changes

Uninstall removes:

- `openvpn-telemetry-agent.service`
- `/usr/local/sbin/openvpn-telemetry-agent`
- `/usr/local/sbin/openvpn-telemetry-write-event`
- `/etc/openvpn/scripts/telemetry-connect.sh`
- `/etc/openvpn/scripts/telemetry-disconnect.sh`
- `/etc/openvpn-telemetry/`
- `/var/spool/openvpn-telemetry/`

Uninstall also removes `client-connect` and `client-disconnect` telemetry lines from:

- `/etc/openvpn/server/server.conf`
- `/etc/openvpn/server.conf`
- `OPENVPN_SERVER_CONF` (if set)

## OpenVPN Config

If `OPENVPN_SERVER_CONF` is not set, add manually to your OpenVPN server config:

```conf
script-security 2
client-connect /etc/openvpn/scripts/telemetry-connect.sh
client-disconnect /etc/openvpn/scripts/telemetry-disconnect.sh
```

Then restart OpenVPN.

Common paths:

- `/etc/openvpn/server/server.conf`
- `/etc/openvpn/server.conf`

Common services:

- `openvpn-server@server` (newer layouts)
- `openvpn@server` (older layouts)

## CentOS 7 Notes

For CentOS 7 with OpenVPN running hooks as `nobody:nobody`, set:

```bash
OPENVPN_SCRIPT_USER="nobody"
OPENVPN_SCRIPT_GROUP="nobody"
```

If SELinux is enforcing and blocks hook or spool access, review audit logs and apply appropriate policy adjustments.

## Validation

Check service status:

```bash
systemctl status openvpn-telemetry-agent --no-pager
```

Follow logs:

```bash
journalctl -u openvpn-telemetry-agent -f
```

Simulate one event:

```bash
sudo -u nobody \
  common_name=testuser trusted_ip=1.2.3.4 trusted_port=5555 ifconfig_pool_remote_ip=10.8.0.99 \
  /usr/local/sbin/openvpn-telemetry-write-event SESSION_CONNECTED

tail -n 3 /var/spool/openvpn-telemetry/queue.log
```

## Payload Shape

Events are queued as NDJSON and sent in batch:

```json
{
  "server_id": "vpn-node-01",
  "sent_at": "2026-02-13T12:10:10Z",
  "events": [
    {
      "event_id": "uuid-1",
      "type": "SESSION_CONNECTED",
      "common_name": "alice",
      "real_ip": "1.2.3.4",
      "virtual_ip": "10.8.0.6",
      "event_time_vpn": "2026-02-13T12:10:05Z"
    },
    {
      "event_id": "uuid-2",
      "type": "SESSION_DISCONNECTED",
      "common_name": "alice",
      "event_time_vpn": "2026-02-13T12:20:05Z"
    }
  ]
}
```

Server-side recommendation:

- enforce idempotency using `event_id`.

Event types emitted by this agent:

- `SESSION_CONNECTED` from OpenVPN `client-connect` hook.
- `SESSION_DISCONNECTED` from OpenVPN `client-disconnect` hook.
- `USERS_UPDATE` from periodic Easy-RSA `index.txt` scans.
- `CCD_INFO` from CCD scans for users currently valid in reference list (first seen and then only when CCD file content changes).

`USERS_UPDATE` example (periodic scan with newly added users, single bulk event):

```json
{
  "event_id": "b0ca3d8f-3f81-41cb-8e23-18cdbed4f5bb",
  "type": "USERS_UPDATE",
  "action": "ADDED",
  "source": "index.txt",
  "event_time_agent": "2026-02-13T12:10:05Z",
  "users": [
    {
      "common_name": "alice",
      "status": "VALID",
      "expires_at_index": "290124060904Z"
    },
    {
      "common_name": "bob",
      "status": "VALID",
      "expires_at_index": "290124092711Z"
    }
  ]
}
```

`USERS_UPDATE` example (first scan when reference list is created, single bulk event):

```json
{
  "event_id": "2f6123ea-31dc-4f2d-8704-a79f30dd2a81",
  "type": "USERS_UPDATE",
  "action": "INITIAL",
  "source": "index.txt",
  "event_time_agent": "2026-02-13T12:00:00Z",
  "users": [
    {
      "common_name": "alice",
      "status": "VALID",
      "expires_at_index": "290124060904Z"
    },
    {
      "common_name": "bob",
      "status": "VALID",
      "expires_at_index": "290124092711Z"
    }
  ]
}
```

`USERS_UPDATE` example (revoked user):

```json
{
  "event_id": "85715f85-45f7-441a-b7d8-a74f2066f8f8",
  "type": "USERS_UPDATE",
  "common_name": "subarnaISPcsr",
  "status": "REVOKED",
  "action": "REVOKED",
  "revoked_at_index": "221206054507Z",
  "event_time_agent": "2026-02-13T12:11:10Z"
}
```

`USERS_UPDATE` example (expired user):

```json
{
  "event_id": "9013f5a8-1d09-42ad-9a40-7fc4b51f8eb5",
  "type": "USERS_UPDATE",
  "common_name": "dineshButwalNOC",
  "status": "EXPIRED",
  "action": "EXPIRED",
  "expires_at_index": "241012065432Z",
  "event_time_agent": "2026-02-13T12:12:10Z"
}
```

`CCD_INFO` example:

```json
{
  "event_id": "0af8d2a7-6518-4aeb-b0d1-2ad6573a01d2",
  "type": "CCD_INFO",
  "common_name": "alice",
  "ccd_path": "/etc/openvpn/ccd/alice",
  "ccd_content_b64": "aWZjb25maWctcHVzaCAxMC44LjAuNiAyNTUuMjU1LjI1NS4w",
  "event_time_agent": "2026-02-13T12:10:10Z"
}
```

Important note about `ccd_content_b64`:

- It is Base64-encoded content for transport in JSON.
- It is not encrypted.
- No salt or key is required to decode it on backend.

## Troubleshooting

Agent running but no delivery:

```bash
journalctl -u openvpn-telemetry-agent -n 200 --no-pager
curl -v https://telemetry.example.com/
```

Queue permission issues:

```bash
ls -ld /var/spool/openvpn-telemetry /var/spool/openvpn-telemetry/pending
ls -l /var/spool/openvpn-telemetry/queue.log /var/spool/openvpn-telemetry/seq
```

Hook execution issues:

```bash
ls -l /etc/openvpn/scripts/telemetry-*.sh
```

## Security Options

Bearer token:

```bash
AUTH_HEADER="Authorization: Bearer <token>"
```

mTLS:

```bash
MTLS_ENABLED=1
CLIENT_CERT="/etc/openvpn-telemetry/client.crt"
CLIENT_KEY="/etc/openvpn-telemetry/client.key"
CA_CERT="/etc/openvpn-telemetry/ca.crt"
```
