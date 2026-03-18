# TheBox — Architecture & Codebase Context

> **Purpose:** This document is a fast-ingest reference for AI coding assistants (and human contributors)
> working on TheBox.  It captures everything needed to understand the design without re-reading all source
> files.  Keep it updated whenever a significant feature changes.

---

## Table of Contents

1. [High-Level Overview](#1-high-level-overview)
2. [Services](#2-services)
3. [Docker Networking & Compose Files](#3-docker-networking--compose-files)
4. [PostgreSQL Schema](#4-postgresql-schema)
5. [Redis Event Bus](#5-redis-event-bus)
6. [Environment Variables — Full Reference](#6-environment-variables--full-reference)
7. [Device Status State Machine](#7-device-status-state-machine)
8. [IoT Learning Pipeline](#8-iot-learning-pipeline)
9. [Discovery Service Internals](#9-discovery-service-internals)
10. [Guardian Service Internals](#10-guardian-service-internals)
11. [Honeypot Service Internals](#11-honeypot-service-internals)
12. [Dashboard API Reference](#12-dashboard-api-reference)
13. [Redirector Service Internals](#13-redirector-service-internals)
14. [Pi-hole v6 API Integration](#14-pi-hole-v6-api-integration)
15. [Platform Differences — Linux vs macOS](#15-platform-differences--linux-vs-macos)
16. [Code Conventions](#16-code-conventions)

---

## 1. High-Level Overview

TheBox is a self-hosted, Docker Compose-based home-network security and device-management platform.
It runs as eight containers that communicate over Redis pub/sub, share state in PostgreSQL, and
enforce network policy via Pi-hole (DNS) and Linux iptables/ipset.

```
┌───────────────────────────────────────────────────────────┐
│                        Docker Host                        │
│                                                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ discovery│  │ guardian │  │ honeypot │  │redirector│  │
│  │ (Python) │  │ (Python) │  │ (Python) │  │ (Python) │  │
│  └────┬─────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘  │
│       │              │             │              │       │
│  ┌────▼──────────────▼─────────────▼──────────────▼────┐  │
│  │              Redis  thebox:events  pub/sub          │  │
│  └──────────────────────────┬──────────────────────────┘  │
│                             │                             │
│  ┌──────────────────────────▼──────┐   ┌──────────────┐   │
│  │           PostgreSQL            │   │   Pi-hole v6 │   │
│  └─────────────────────────────────┘   │  (DNS + API) │   │
│                                        └──────────────┘   │
│  ┌────────────────────────────────────────────────────┐   │
│  │              Dashboard  (Flask + SSE)              │   │
│  └────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
```

---

## 2. Services

| Service | Source | Default Port(s) | Responsibilities |
|---------|--------|-----------------|-----------------|
| `discovery` | `services/discovery/app.py` | host network | ARP sweep, nmap, Pi-hole FTL API, DNS sniff, SSDP/UPnP, mDNS, NetBIOS, HTTP banners, IoT learning sessions |
| `guardian` | `services/guardian/app.py` | host network | iptables/ipset policy (quarantine / iot / blocked / trusted), sync every 10 min, event-driven policy updates |
| `honeypot` | `services/honeypot/app.py` | host network | 24-port fake-service listener, protocol simulation, severity/intent classification, Redis hit-counter |
| `redirector` | `services/redirector/app.py` | host network | passive monitoring, iptables DNAT, ARP spoof, DHCP inject/starvation, gateway takeover |
| `dashboard` | `services/dashboard/app.py` | 3000 | Flask REST API, Server-Sent Events, device/user/group CRUD, IoT allowlist feed, Pi-hole stats proxy |
| `pihole` | upstream image | 53 (DNS), 80 (API), 8080 (UI) | DNS filtering, ad-blocking, client tracking, groups/adlists for IoT |
| `postgres` | upstream image | 5432 (internal) | Persistent state |
| `redis` | upstream image | 6379 (internal) | Event bus + honeypot counters cache |

---

## 3. Docker Networking & Compose Files

### Networks

| Network | Type | Who Uses It | Notes |
|---------|------|-------------|-------|
| `thebox_internal` | bridge, `internal: true` | postgres, redis, pihole, discovery, guardian, honeypot, redirector, dashboard | No external route; containers resolve each other by name |
| `thebox_external` | bridge | pihole, dashboard | Accessible from host / LAN |

### Compose file layering

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Base — bridge networking, works everywhere |
| `docker-compose.linux.yml` | Linux overlay — adds `network_mode: host` to discovery, guardian, honeypot, redirector; overrides DATABASE_URL and REDIS_URL to `127.0.0.1` |
| `docker-compose.macos.yml` | macOS overlay — no host networking; honeypot ports added by `setup.sh` into `docker-compose.macos.ports.yml` |

**Linux overlay key points:**
- `network_mode: host` means container DNS won't resolve service names → DATABASE_URL/REDIS_URL use `127.0.0.1`
- postgres and redis are exposed on `127.0.0.1:5432` / `127.0.0.1:6379` for host-mode containers
- `PIHOLE_URL` is overridden to `http://127.0.0.1:${PIHOLE_WEB_PORT:-8080}`

---

## 4. PostgreSQL Schema

All tables defined in `config/postgres/init.sql`.  No SQL enum types — statuses are VARCHAR.

### `users`
```sql
id            SERIAL PRIMARY KEY
username      VARCHAR(64)  NOT NULL UNIQUE
display_name  VARCHAR(255)
email         VARCHAR(255)
created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
```

### `devices`
```sql
id            SERIAL PRIMARY KEY
mac_address   VARCHAR(17)  NOT NULL UNIQUE        -- colon-separated, lowercase
ip_address    VARCHAR(45)                          -- last-known IP
hostname      VARCHAR(255)
vendor        VARCHAR(255)                         -- from MAC OUI
device_type   VARCHAR(64)  DEFAULT 'unknown'       -- see state machine
os_guess      VARCHAR(255)                         -- nmap OS result
first_seen    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
last_seen     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
status        VARCHAR(32)  NOT NULL DEFAULT 'new'  -- new|quarantined|trusted|blocked|iot|iot_learning
notes         TEXT
open_ports    JSONB        DEFAULT '[]'            -- [{port, proto, service}, ...]
extra_info    JSONB        DEFAULT '{}'            -- vendor-enrichment bag
owner_id      INTEGER      REFERENCES users(id) ON DELETE SET NULL
```
Indexes: `mac_address`, `ip_address`, `status`, `owner_id`

### `iot_allowlist`
```sql
id         SERIAL PRIMARY KEY
device_id  INTEGER  REFERENCES devices(id) ON DELETE CASCADE  -- NULL = globally shared
fqdn       VARCHAR(255) NOT NULL
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
UNIQUE(device_id, fqdn)
-- Partial unique index: UNIQUE(fqdn) WHERE device_id IS NULL
```

### `iot_learning_sessions`
```sql
id                    SERIAL PRIMARY KEY
device_id             INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE  UNIQUE
pihole_group_name     VARCHAR(64) NOT NULL   -- e.g. "iot_192.168.1.42_learning"
learning_started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
learning_completed_at TIMESTAMPTZ
status                VARCHAR(32) NOT NULL DEFAULT 'active'  -- active|completed
```

### `honeypot_events`
```sql
id                SERIAL PRIMARY KEY
src_ip            VARCHAR(45) NOT NULL
src_port          INTEGER
dst_port          INTEGER     NOT NULL
protocol          VARCHAR(10) NOT NULL DEFAULT 'tcp'
payload_preview   TEXT
severity          VARCHAR(16) NOT NULL DEFAULT 'low'   -- low|high|critical
device_id         INTEGER REFERENCES devices(id)
interaction_level VARCHAR(32)   -- none|banner|data|credentials|commands
intent            VARCHAR(32)   -- scan|recon|probe|brute_force|exploit|sweep
is_sweep          BOOLEAN
ports_scanned     JSONB
created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
```
Indexes: `src_ip`, `created_at`

### `dns_events`
```sql
id          SERIAL PRIMARY KEY
device_id   INTEGER REFERENCES devices(id)
src_ip      VARCHAR(45) NOT NULL
query       VARCHAR(255) NOT NULL
query_type  VARCHAR(16)  NOT NULL DEFAULT 'A'
blocked     BOOLEAN      NOT NULL DEFAULT FALSE
created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
```

### `scan_runs`
```sql
id            SERIAL PRIMARY KEY
started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
finished_at   TIMESTAMPTZ
network_range VARCHAR(64) NOT NULL
devices_found INTEGER     NOT NULL DEFAULT 0
new_devices   INTEGER     NOT NULL DEFAULT 0
status        VARCHAR(32) NOT NULL DEFAULT 'running'
```

### `alerts`
```sql
id           SERIAL PRIMARY KEY
source       VARCHAR(64) NOT NULL          -- discovery|guardian|honeypot
level        VARCHAR(16) NOT NULL DEFAULT 'info'   -- info|warning|critical
title        VARCHAR(255) NOT NULL
detail       TEXT
device_id    INTEGER REFERENCES devices(id)
acknowledged BOOLEAN NOT NULL DEFAULT FALSE
created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
```
Indexes: `level`, `created_at`

### `groups`
```sql
id                SERIAL PRIMARY KEY
name              VARCHAR(64)  NOT NULL UNIQUE
description       TEXT
pihole_group_name VARCHAR(64)
created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

### `user_groups`
```sql
PRIMARY KEY (user_id, group_id)
user_id   INTEGER NOT NULL REFERENCES users(id)   ON DELETE CASCADE
group_id  INTEGER NOT NULL REFERENCES groups(id)  ON DELETE CASCADE
```

### `device_groups`
```sql
PRIMARY KEY (device_id, group_id)
device_id INTEGER NOT NULL REFERENCES devices(id)  ON DELETE CASCADE
group_id  INTEGER NOT NULL REFERENCES groups(id)   ON DELETE CASCADE
```

### `redirect_events`
```sql
id         SERIAL PRIMARY KEY
action     VARCHAR(64) NOT NULL
target_ip  VARCHAR(45) NOT NULL
target_mac VARCHAR(17)
mode       VARCHAR(64) NOT NULL    -- arp_spoof|redirect_dns|dhcp_advertise|...
detail     TEXT
device_id  INTEGER REFERENCES devices(id)
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```
Indexes: `target_ip`, `created_at`

### `schema_migrations`
```sql
version    VARCHAR(16) NOT NULL PRIMARY KEY
applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
```

---

## 5. Redis Event Bus

**Single channel:** `thebox:events`  
All services publish and subscribe to this one channel with JSON payloads.

### Published Events

| Event type | Publisher | Subscribers | Key payload fields | Guardian action |
|------------|-----------|-------------|-------------------|----------------|
| `new_device` | discovery | guardian, dashboard | device_id, mac, ip, vendor, device_type, ts | Quarantines if AUTO_QUARANTINE=true; creates alert |
| `iot_learning_started` | discovery | guardian, dashboard | device_id, ip, pihole_group, ts | Applies unrestricted policy so all DNS queries are visible |
| `iot_learning_completed` | discovery | dashboard | device_id, ip, domains_learned, ts | UI refresh only |
| `iot_learning_start_requested` | dashboard | discovery | device_id, ip, mac | Calls `start_iot_learning()` |
| `device_status_changed` | dashboard | guardian, dashboard | device_id, status | Immediately applies iptables policy for new status |
| `block_ip` | honeypot | *(none yet)* | ip, reason, ts | Not subscribed to currently |
| `quarantine_device` | *(none yet)* | redirector | ip, mac | Starts per-device ARP spoof loop |
| `unquarantine_device` | *(none yet)* | redirector | ip | Stops per-device ARP spoof loop |

> **Note:** `quarantine_device` / `unquarantine_device` are subscribed by redirector but not published by any service yet — reserved for future guardian integration.

### Dashboard SSE relay

`dashboard` subscribes to `thebox:events` and fans all messages to a list of per-client `Queue` objects
(`_sse_subscribers`).  The `/api/events` endpoint drains these queues and streams them as Server-Sent
Events.  Keep-alive `:\n\n` comments are sent every 30 s to prevent idle-connection timeouts.

### Redis cache keys (honeypot)

| Key pattern | Type | TTL | Purpose |
|-------------|------|-----|---------|
| `thebox:honeypot:hits:{src_ip}` | Integer (INCR) | `HONEYPOT_THRESHOLD_WINDOW` s | Hit-frequency counter for severity escalation |
| `thebox:honeypot:ports:{src_ip}` | Set (SADD) | `HONEYPOT_SWEEP_WINDOW` s | Distinct ports probed — sweep detection |
| `thebox:honeypot:creds:{src_ip}` | Integer (INCR) | `HONEYPOT_THRESHOLD_WINDOW × HONEYPOT_CREDENTIAL_WINDOW_MULTIPLIER` s | Credential-attempt count for brute-force detection |
| `thebox:honeypot:sweep_alerted:{src_ip}` | String "1" (SETEX) | `HONEYPOT_SWEEP_WINDOW` s | Deduplication flag to prevent duplicate sweep alerts |

---

## 6. Environment Variables — Full Reference

### General

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `TZ` | `America/New_York` | all | Container timezone |
| `LOG_LEVEL` | `INFO` | all | Log verbosity: DEBUG / INFO / WARNING / ERROR |

### PostgreSQL

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `POSTGRES_DB` | `thebox` | postgres | Database name |
| `POSTGRES_USER` | `thebox` | postgres, all via DATABASE_URL | DB username |
| `POSTGRES_PASSWORD` | `thebox_secret` | postgres, all via DATABASE_URL | DB password — **change in production** |
| `DATABASE_URL` | auto-built | discovery, guardian, honeypot, redirector, dashboard | Full psycopg2/SQLAlchemy URL |

### Redis

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `REDIS_URL` | `redis://redis:6379/0` | all Python services | Redis connection URL |

### Pi-hole

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `PIHOLE_PASSWORD` | `thebox_pihole` | pihole, discovery, dashboard | Pi-hole admin password — **change in production** |
| `PIHOLE_DNS_PORT` | `53` | pihole | Host port exposed for DNS |
| `PIHOLE_WEB_PORT` | `8080` | pihole | Host port for Pi-hole web UI |
| `PIHOLE_URL` | `http://pihole:80` | discovery, dashboard | Base URL for Pi-hole v6 API calls (NOT /admin/api — use /api) |

### Dashboard

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `DASHBOARD_PORT` | `3000` | dashboard | HTTP port for Flask |
| `SECRET_KEY` | `change_me_in_production` | dashboard | Flask session key — **change in production** |
| `PIHOLE_SID_TTL` | `240` | dashboard | Seconds to cache Pi-hole v6 session ID; Pi-hole sessions expire in ~300 s |
| `DASHBOARD_URL` | `http://dashboard:3000` | discovery | URL discovery passes to Pi-hole for registering the IoT adlist feed |

### Network Discovery

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `NETWORK_RANGES` | `192.168.1.0/24` | discovery, redirector | Comma-separated CIDR ranges |
| `SCAN_INTERVAL` | `300` | discovery | Seconds between ARP/nmap sweeps |
| `DNS_SNIFF_ENABLED` | `true` | discovery | Enable live DNS packet capture (requires NET_RAW) |
| `DNS_SNIFF_IFACE` | *(auto)* | discovery | Network interface to sniff; empty = auto-detect |
| `SSDP_ENABLED` | `true` | discovery | SSDP/UPnP multicast M-SEARCH probes |
| `SSDP_TIMEOUT` | `5` | discovery | Seconds to collect SSDP responses |
| `MDNS_ENABLED` | `true` | discovery | mDNS/Zeroconf DNS-SD browser (zeroconf==0.131.0) |
| `NETBIOS_ENABLED` | `true` | discovery | `nmap nbstat` scan for Windows/Samba hosts |
| `BANNER_GRAB_ENABLED` | `true` | discovery | HTTP/HTTPS banner + TLS cert extraction |
| `BANNER_GRAB_TIMEOUT` | `3` | discovery | Timeout per banner-grab connection |

### IoT Learning

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `IOT_LEARNING_HOURS` | `48` | discovery | Hours in learning window before finalising allow-list |
| `PIHOLE_IOT_GROUP` | `iot` | discovery | Pi-hole group for post-learning IoT devices |

### Device Guardian

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `AUTO_QUARANTINE` | `true` | guardian | Quarantine `status='new'` devices automatically |
| `QUARANTINE_VLAN` | `192.168.99.0/24` | guardian | CIDR for quarantine subnet annotation |
| `TRUSTED_NETWORKS` | `192.168.1.0/24` | guardian | Comma-separated trusted CIDRs |

### Honeypot

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `HONEYPOT_PORTS` | `21,22,23,25,53,80,110,135,143,389,443,445,1433,3306,3389,5432,5900,5985,6379,8080,8443,9200,11211,27017` | honeypot | TCP ports to listen on |
| `HONEYPOT_IGNORED_NETWORKS` | `172.16.0.0/12,127.0.0.0/8` | honeypot | CIDRs silently ignored (Docker bridges, loopback) |
| `HONEYPOT_THRESHOLD_COUNT` | `3` | honeypot | Hits within window before `low`→`high` escalation; ×3 → `critical` |
| `HONEYPOT_THRESHOLD_WINDOW` | `60` | honeypot | Rolling window (s) for hit counting |
| `HONEYPOT_SWEEP_THRESHOLD` | `4` | honeypot | Distinct ports within window to flag as sweep |
| `HONEYPOT_SWEEP_WINDOW` | `60` | honeypot | Rolling window (s) for sweep detection |
| `HONEYPOT_RECV_TIMEOUT` | `4` | honeypot | Seconds to wait for attacker data after banner |
| `HONEYPOT_MAX_PAYLOAD_LENGTH` | `2000` | honeypot | Max chars stored as `payload_preview` |
| `HONEYPOT_CREDENTIAL_WINDOW_MULTIPLIER` | `5` | honeypot | `THRESHOLD_WINDOW × multiplier` = credential-tracking TTL |

### Redirector

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `REDIRECT_MODE` | `passive` | redirector | Comma-separated modes (see §13) |
| `NETWORK_INTERFACE` | `eth0` | redirector | Interface for ARP/Scapy operations |
| `GATEWAY_IP` | *(auto)* | redirector | Default gateway; auto-detected if empty |
| `PIHOLE_IP` | *(auto → BOX_IP)* | redirector | Pi-hole IP for DNAT targets |
| `BOX_IP` | *(auto)* | redirector | TheBox's own IP (auto-detected from NETWORK_INTERFACE) |
| `BLACKHOLE_QUARANTINED` | `false` | redirector | Drop quarantined-device traffic except DNS/DHCP |
| `ARP_REFRESH_INTERVAL` | `10` | redirector | Seconds between gratuitous ARP refresh packets |

---

## 7. Device Status State Machine

Valid values for `devices.status`:

```
[new]
  │
  └── AUTO_QUARANTINE=true ──► [quarantined]   iptables: allow DNS(53) + DHCP(67/68) only
        │
        ├── dashboard: approve ──► [trusted]    iptables: no restrictions
        │
        ├── dashboard: mark IoT (first time) ──► [iot_learning]   iptables: unrestricted
        │                                              │            (Pi-hole captures all DNS)
        │                                  IOT_LEARNING_HOURS later
        │                                              │
        │                                              └──► [iot]  iptables: ipset thebox_iot
        │                                                          Pi-hole: PIHOLE_IOT_GROUP
        │
        └── dashboard: block ──► [blocked]      iptables: DROP everything (ipset thebox_blocked)
```

### Guardian ipset names (exact strings)

| ipset | type | Applies to |
|-------|------|-----------|
| `thebox_quarantine` | `hash:mac` | quarantined devices |
| `thebox_iot` | `hash:mac` | iot devices |
| `thebox_blocked` | `hash:mac` | blocked devices |

### Guardian iptables chain

`THEBOX_POLICY` — used as fallback when `hash:mac` ipsets are unavailable (e.g. macOS Docker kernel).
Rules in this chain match by source IP and apply accept/drop decisions.

---

## 8. IoT Learning Pipeline

**Trigger:** Dashboard receives `PUT /api/devices/<id>/status` with `{"status": "iot"}` for a device
with no prior `iot_learning_sessions` row.

1. **Dashboard** (`api_set_device_status`):
   - Sets `devices.status = 'iot_learning'`
   - Publishes `iot_learning_start_requested` → `{device_id, ip, mac}`

2. **Guardian** (on `iot_learning_started` event):
   - Calls `apply_device_policy(mac, ip, 'iot_learning')` → no ipset entry → unrestricted

3. **Discovery** (`_handle_iot_learning_start_requested` → `start_iot_learning`):
   - Creates Pi-hole group: `iot_<IP>_learning` (e.g. `iot_192.168.1.42_learning`)
   - Registers device IP as Pi-hole client in that group
   - Inserts row into `iot_learning_sessions` (status=`active`)
   - Publishes `iot_learning_started`

4. **Discovery** periodic check (`process_completed_learnings`, runs every scan cycle):
   - Finds `iot_learning_sessions` where `learning_started_at + IOT_LEARNING_HOURS <= now`
   - For each completed session:
     a. Queries Pi-hole FTL API for all domains resolved during the window
     b. Inserts unique FQDNs into `iot_allowlist` with `device_id=NULL` (globally shared)
     c. Calls `pihole_register_iot_allowlist(DASHBOARD_URL)` — registers `/iot-allowlist.txt` as
        Pi-hole adlist (type `allow`) for `PIHOLE_IOT_GROUP`
     d. Adds each domain to Pi-hole exact allowlist for `PIHOLE_IOT_GROUP`
     e. Calls `pihole_assign_client_to_groups(ip, [PIHOLE_IOT_GROUP])` — moves client from learning
        group to permanent IoT group
     f. Deletes the temporary Pi-hole learning group
     g. Updates `devices.status = 'iot'`, marks session `status='completed'`
     h. Publishes `iot_learning_completed`

5. **Guardian** (on `device_status_changed` with status=`iot`):
   - Calls `apply_device_policy(mac, ip, 'iot')` → adds MAC to `thebox_iot` ipset

**IoT allowlist feed URL:** `GET /iot-allowlist.txt` on the dashboard service.
- Returns all FQDNs from `iot_allowlist` (global + all per-device), deduplicated, sorted, one per line
- No authentication — must be reachable from Pi-hole container over `thebox_internal`
- Pi-hole polls this URL as an adlist every time it updates gravity

---

## 9. Discovery Service Internals

### Scan cycle (`run_scan`)

1. ARP sweep (`scapy` or nmap fallback) → list of `{ip, mac}` dicts
2. Pi-hole FTL API — fetch `/api/clients` → augment list
3. DNS sniff queue drain → augment list (if `DNS_SNIFF_ENABLED`)
4. SSDP discover → `dict[ip → enrichment]` (if `SSDP_ENABLED`)
5. mDNS queue drain → `dict[ip → enrichment]` (if `MDNS_ENABLED`)
6. NetBIOS scan (`nmap nbstat`) → `dict[ip → enrichment]` (if `NETBIOS_ENABLED`)
7. For each host:
   - Merge SSDP/mDNS/NetBIOS data
   - Reverse DNS lookup
   - MAC OUI vendor lookup
   - nmap port + OS scan → `open_ports`, `os_guess`
   - Banner grab → `http_server`, `tls_cn`, `tls_org` (if `BANNER_GRAB_ENABLED`)
   - `guess_device_type(vendor, open_ports, os_guess, extra_info, hostname)` → `device_type`
   - `upsert_device(conn, rdb, host)` → `True` if new device
8. If new device and `AUTO_QUARANTINE`: publish `new_device`
9. `process_completed_learnings()` — finalise any expired IoT learning sessions

### Enrichment function names

| Capability | Function | Returns |
|-----------|----------|---------|
| SSDP/UPnP | `ssdp_discover(timeout)` | `dict[ip → {upnp_location, upnp_friendly_name, upnp_manufacturer, upnp_model_name, upnp_device_type, upnp_udn, …}]` |
| mDNS | `process_mdns_queue()` | `dict[ip → {mdns_services: [...], mdns_hostname}]` |
| NetBIOS | `netbios_scan(network)` | `dict[ip → {netbios_name, workgroup}]` |
| Banner | `enrich_from_banners(ip, open_ports)` | `{http_server, tls_cn, tls_org, tls_issuer_cn, tls_sans}` |
| Port/OS | `nmap_scan(ip)` | `{open_ports: [{port, proto, service}], os_guess}` |

### IoT device-type heuristics (`guess_device_type`)

Detection priority (first match wins):

1. **mDNS service-type** (highest specificity)
   - `_googlecast._tcp`, `_cast._tcp` → `iot`
   - `_airplay._tcp`, `_raop._tcp`, `_companion-link._tcp` → `mobile`
   - `_homekit._tcp`, `_hap._tcp`, `_matter._tcp` → `iot`
   - `_printer._tcp`, `_ipp._tcp`, `_ipps._tcp` → `printer`
   - `_workstation._tcp`, `_smb._tcp`, `_afpovertcp._tcp` → `desktop`

2. **UPnP device-type**
   - `InternetGatewayDevice` → `network_device`
   - `MediaRenderer`, `MediaServer` → `iot`
   - `printer` → `printer`
   - `WLANAccessPoint`, `WANDevice` → `network_device`

3. **Vendor keywords** (`_IOT_VENDOR_KEYWORDS` frozenset — ~60 entries including espressif, tuya, shelly, sonos, ring, philips lighting, etc.)

4. **OS keywords** (`_IOT_OS_KEYWORDS` frozenset — embedded linux, openwrt, vxworks, freertos, etc.)

5. **Port signals** (`_IOT_PORT_SIGNALS` frozenset — MQTT 1883/8883, CoAP 5683, RTSP 554, BACnet 47808, Modbus 502, etc.)

6. **Hostname keywords** (`_IOT_HOSTNAME_KEYWORDS` frozenset — esp-, shelly, tasmota, hue-bridge, homeassistant, etc.)

7. **OS fallback** — windows→`desktop`, macos→`desktop`, linux+ssh→`server`

8. **Vendor fallback** — apple/ios→`mobile`, print in vendor→`printer`

9. **Port fallback** — 80/443/8080→`network_device`

10. **Default** → `unknown`

---

## 10. Guardian Service Internals

### Policy application (`apply_device_policy`)

When `_ipsets_available` (hash:mac supported by kernel):
- Remove MAC from all three ipsets unconditionally
- Add MAC to the correct ipset for the status:
  - `quarantined` → `thebox_quarantine`
  - `iot` → `thebox_iot`
  - `blocked` → `thebox_blocked`
  - `iot_learning`, `trusted`, `new` → no ipset entry (unrestricted)

When `_ipsets_available` is False (fallback, macOS Docker kernel):
- Clear existing per-IP rules from `THEBOX_POLICY` chain
- Insert IP-based rules:
  - `quarantined` or `iot`: accept DNS UDP/TCP 53, DHCP UDP 67/68, then DROP
  - `blocked`: DROP all
  - others: no rules

### Periodic sync (`sync_all_policies`)

Runs every 10 minutes.  Flushes all ipsets (or THEBOX_POLICY chain), then rebuilds by iterating all
devices in DB.  Devices with `status='new'` are treated as `quarantined` when `AUTO_QUARANTINE=true`.

### Subscribe loop

Subscribes to `thebox:events`.  Handles:
- `new_device` → `handle_new_device_event()` (quarantine if AUTO_QUARANTINE)
- `iot_learning_started` → `_apply_policy_from_db(device_id, status_override='iot_learning')`
- `device_status_changed` → `_apply_policy_from_db(device_id, status_override=new_status)`

---

## 11. Honeypot Service Internals

### Protocol simulation

Each port has a fake banner in `BANNERS` dict and an optional multi-turn handler in `_PROTOCOL_HANDLERS`:

| Port | Simulated banner / protocol |
|------|-----------------------------|
| 21 | `220 FTP server (vsftpd 3.0.5) ready.` then USER/PASS exchange |
| 22 | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` |
| 23 | Telnet IAC negotiation bytes |
| 25 | `220 mail.example.com ESMTP Postfix` then EHLO/MAIL/RCPT/AUTH/DATA |
| 80/8080 | HTTP 200 with Apache/Tomcat banner; full request parsing |
| 110 | POP3 OK; USER/PASS |
| 143 | IMAP OK with CAPABILITY; LOGIN/AUTHENTICATE |
| 389 | LDAP BindResponse bytes |
| 443/8443 | TLS Alert bytes |
| 445 | SMB negotiate bytes |
| 1433 | MSSQL pre-login packet |
| 3306 | MySQL handshake |
| 3389 | RDP connection confirm |
| 5432 | PostgreSQL MD5 auth request |
| 5900 | `RFB 003.008` |
| 5985 | HTTP 401 WinRM Negotiate |
| 6379 | `-NOAUTH Authentication required.` |
| 9200 | Elasticsearch JSON response |
| 11211 | `VERSION 1.6.21` |
| 27017 | MongoDB `isMaster` response bytes |

### `handle_connection` flow

1. Check `is_ignored(src_ip)` — drop silently if in `HONEYPOT_IGNORED_NETWORKS`
2. Send fake banner → set `interaction_level = 'banner'`
3. Call protocol handler (if any) → may elevate to `data`, `credentials`, or `commands`
4. `detect_sweep(src_ip, dst_port, rdb)` → `(is_sweep: bool, ports_scanned: list[int])`
5. `infer_intent(interaction_level, payload, is_sweep, src_ip, rdb)` → intent string
6. `classify_severity(src_ip, rdb, interaction_level, intent, is_sweep)` → severity string
7. `log_event(...)` — write to `honeypot_events`, create alert, publish `block_ip`

### Severity classification (`classify_severity`)

```
if intent == 'exploit'                         → 'critical'
if intent == 'brute_force' or
   (is_sweep and hits >= THRESHOLD_COUNT)       → 'critical'
if interaction_level in ('credentials','commands')
   or is_sweep                                  → 'high'
if hits >= THRESHOLD_COUNT * 3                 → 'critical'
if hits >= THRESHOLD_COUNT                     → 'high'
else                                           → 'low'
```

### Intent inference (`infer_intent`)

- `is_sweep` → `'sweep'`
- payload contains exploit-like patterns → `'exploit'`
- `interaction_level` in (`credentials`, `commands`) and cred-counter ≥ 3 → `'brute_force'`
- `interaction_level` == `'credentials'` → `'probe'`
- `interaction_level` == `'data'` → `'recon'`
- `interaction_level` == `'banner'` → `'scan'`
- default → `'scan'`

---

## 12. Dashboard API Reference

### Device endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/devices` | List all devices (includes owner, group membership) |
| GET | `/api/devices/<id>` | Single device |
| PUT | `/api/devices/<id>/status` | Change status: `trusted|quarantined|blocked|iot` — publishes `device_status_changed` |
| GET | `/api/devices/<id>/iot-allowlist` | Per-device FQDN allow-list entries |
| POST | `/api/devices/<id>/iot-allowlist` | Add FQDN — body `{"fqdn": "..."}` |
| DELETE | `/api/devices/<id>/iot-allowlist/<entry_id>` | Remove FQDN |
| PUT | `/api/devices/<id>/owner` | Assign owner — body `{"owner_id": N}` |

**`PUT /status` special case:** first-time `iot` assignment sets `iot_learning` and publishes
`iot_learning_start_requested`.  Subsequent `iot` assignments skip learning.

### User endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/users` | List users with device/group counts |
| GET | `/api/users/<id>` | Single user |
| POST | `/api/users` | Create — body `{"username": "...", "display_name": "...", "email": "..."}` |
| PUT | `/api/users/<id>` | Update display_name / email |
| DELETE | `/api/users/<id>` | Delete |

### Group endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/groups` | List groups with user/device counts |
| GET | `/api/groups/<id>` | Single group |
| POST | `/api/groups` | Create — body `{"name": "...", "pihole_group_name": "..."}` |
| PUT | `/api/groups/<id>` | Update description / pihole_group_name |
| DELETE | `/api/groups/<id>` | Delete |
| PUT | `/api/groups/<id>/users/<uid>` | Add user to group |
| DELETE | `/api/groups/<id>/users/<uid>` | Remove user |
| PUT | `/api/groups/<id>/devices/<did>` | Add device to group |
| DELETE | `/api/groups/<id>/devices/<did>` | Remove device |

### Other endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/alerts` | Last 200 alerts |
| PUT | `/api/alerts/<id>/acknowledge` | Mark acknowledged |
| GET | `/api/honeypot` | Last 200 honeypot events |
| GET | `/api/honeypot/<id>` | Single event |
| GET | `/api/pihole` | Pi-hole stats: queries_total, queries_blocked, percent_blocked, domains_blocked, clients_active, clients_total, status |
| GET | `/api/stats` | Summary: devices by status, honeypot_hits, unacked_alerts |
| GET | `/api/events` | SSE stream (text/event-stream) |
| GET | `/iot-allowlist.txt` | Plain-text IoT FQDN feed for Pi-hole adlist |

---

## 13. Redirector Service Internals

### Mode descriptions

| Mode | Behavior |
|------|----------|
| `passive` | No network manipulation; subscribes to events only |
| `redirect_dns` | iptables DNAT: `UDP/TCP 53 → PIHOLE_IP:53` on PREROUTING |
| `arp_spoof` | `scapy` sends ARP replies to all LAN hosts every `ARP_REFRESH_INTERVAL` s claiming TheBox MAC = gateway |
| `dhcp_advertise` | Sniffs UDP 67/68; injects DHCP Offer/ACK with Pi-hole as DNS; maintains in-memory lease table |
| `dhcp_starvation` | Floods upstream DHCP with Discovers (randomised MACs) to exhaust pool |
| `gateway_takeover` | ARP-spoofs every LAN host AND upstream router simultaneously |

### `arp_spoof(target_ip, spoof_ip, target_mac=None)`

Constructs Scapy `Ether/ARP` frame:
- ARP opcode 2 (is-at)
- `psrc=spoof_ip, hwsrc=own_mac`
- Sends unicast to `target_mac` or broadcast if None

### Per-device quarantine (from events)

On `quarantine_device` event:
- Starts background thread calling `arp_spoof(device_ip, GATEWAY_IP)` every `ARP_REFRESH_INTERVAL` s
- If `BLACKHOLE_QUARANTINED=true`: inserts iptables FORWARD rules — allow UDP/TCP 53, allow UDP 67, DROP all

On `unquarantine_device`:
- Stops ARP spoof thread
- Removes iptables FORWARD rules

---

## 14. Pi-hole v6 API Integration

### Important facts

- **API base path:** `/api` (e.g. `http://pihole:80/api`) — **NOT** `/admin/api`
- **Authentication:** `POST /api/auth` with `{"password": PIHOLE_PASSWORD}` → returns `session.sid`
- **Session caching:** cached for `PIHOLE_SID_TTL` seconds (default 240 s); Pi-hole sessions expire in ~300 s
- **Session invalidation:** any 401 response clears the SID cache and triggers re-auth
- **API response keys are always plural:** `"groups"`, `"clients"`, `"domains"`, `"lists"` — never singular

### Endpoints used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/auth` | POST | Authenticate; get SID |
| `/api/stats/summary` | GET | Query counts, blocking ratio, gravity size |
| `/api/clients` | GET | All clients Pi-hole has seen |
| `/api/groups` | GET | List all Pi-hole groups |
| `/api/groups` | POST | Create a group |
| `/api/groups/<name>` | DELETE | Delete a group |
| `/api/clients` | POST | Register a client (assign to groups) |
| `/api/clients/<ip>` | PATCH | Update client group membership |
| `/api/domains/allow/exact` | POST | Add domain to exact allowlist |
| `/api/lists` | POST | Register adlist URL (for IoT allowlist feed) |

### Key Pi-hole functions in discovery service

- `pihole_ensure_group(name)` — create group if not exists; reads from `response["groups"]`
- `pihole_assign_client_to_groups(ip, group_names)` — assign device to Pi-hole groups; reads `response["clients"]`
- `pihole_add_domain_to_allowlist(fqdn, group_name)` — exact allow; reads `response["domains"]`
- `pihole_register_iot_allowlist(dashboard_url)` — registers `{dashboard_url}/iot-allowlist.txt` as adlist; reads `response["lists"]`

---

## 15. Platform Differences — Linux vs macOS

| Capability | Linux (host networking) | macOS (Docker Desktop bridge) |
|-----------|------------------------|-------------------------------|
| ARP sweeps | Physical LAN | Docker VM network only |
| DNS packet sniffing | Physical LAN interface | Docker bridge interface only |
| iptables / ipset enforcement | Full — affects physical LAN | ipset may be unavailable; falls back to THEBOX_POLICY chain — does not affect physical LAN |
| ARP spoofing | Physical LAN | Docker VM stack only |
| DHCP injection | Physical LAN | Docker VM stack only |
| Service name DNS resolution | Broken in host-mode → use 127.0.0.1 | Works on bridge |
| DATABASE_URL / REDIS_URL | `127.0.0.1:5432` / `127.0.0.1:6379` (linux overlay) | `postgres:5432` / `redis:6379` |
| Honeypot ports | `network_mode: host` | Explicit port mappings in `docker-compose.macos.ports.yml` |
| Port 22 | Available | Excluded (macOS sshd) |

---

## 16. Code Conventions

- **Language:** Python 3.11+, all services
- **Logging:** `structlog` with JSON output; all log calls use keyword arguments
  (e.g. `log.info("scan_complete", devices_found=42)`)
- **Database access:** raw `psycopg2` connections; no ORM
- **Redis client:** `redis-py` (synchronous)
- **HTTP/Scapy:** `requests` for Pi-hole API; `scapy` for ARP/DHCP packet crafting
- **DNS sniffing:** `scapy` with `sniff(filter="udp port 53", store=0, prn=...)`
- **mDNS:** `zeroconf==0.131.0`
- **Environment variables:** read at module level via `os.environ.get(KEY, default)`;
  `int()` / `float()` cast inline; booleans via `.lower() == "true"`
- **Event channel constant:** `REDIS_CHANNEL = "thebox:events"` (string literal in each service)
- **Pi-hole API calls:** always include `sid` header as `{"sid": session_id}` in GET/DELETE,
  or `json={"sid": ..., ...}` body in POST/PATCH
- **iot_allowlist global entries:** `device_id=NULL` rows are globally shared across all IoT devices;
  per-device rows have `device_id` set; `/iot-allowlist.txt` serves the union of both
- **Device upsert:** `INSERT ... ON CONFLICT (mac_address) DO UPDATE` — MAC is the stable key;
  IP and enrichment fields are always overwritten with latest scan results
