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

Installer actions:

- installs missing dependencies (`curl`, `util-linux` for `flock`)
- writes config and spool permissions
- installs writer and agent
- installs hooks
- installs and starts systemd service
- optionally patches OpenVPN config if `OPENVPN_SERVER_CONF` is set

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

Server-side recommendation:

- enforce idempotency using `event_id`.

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
