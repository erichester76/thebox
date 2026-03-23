# STILL EARLY DEVELOPMENT - USE WITH CAUTION

# 🛡 TheBox — Container-Based Home Network Server

TheBox is a self-hosted, Docker Compose-based home network security and management platform.  It brings together capabilities inspired by Pi-hole, Firewalla, Bark, and UniFi into a single, easily deployable solution.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Auto-discovery** | ARP sweeps + nmap scan every N minutes to find every device on your network |
| **Pi-hole client discovery** | Queries the Pi-hole v6 FTL API to discover devices that have made DNS queries, even if they didn't respond to ARP |
| **DNS packet sniffing** | Captures DNS query packets (port 53) and mDNS responses (port 5353) to discover devices and extract hostnames in real-time |
| **DHCP hostname sniffing** | Extracts device hostnames directly from DHCP DISCOVER/REQUEST packets (option 12) — more reliable than reverse DNS, updated the moment a device connects |
| **ARP packet sniffing** | Detects devices the instant they send an ARP request, without waiting for the next periodic scan; includes ARP spoof detection |
| **SSDP / UPnP discovery** | Sends multicast M-SEARCH probes; fetches UPnP device description XML for manufacturer, model, and friendly name |
| **mDNS / Zeroconf discovery** | Browses DNS-SD service types (Bonjour/Avahi) to find Apple, Chromecast, printers, HomeKit, and other Zeroconf devices |
| **NetBIOS discovery** | Runs `nmap nbstat` across the subnet to retrieve NetBIOS hostnames and workgroup names for Windows/Samba hosts |
| **HTTP/HTTPS banner grabbing** | Extracts `Server` headers and TLS certificate subjects from open ports to enrich device vendor and hostname data |
| **Vendor / OS detection** | MAC OUI lookup, nmap OS fingerprinting, and heuristic device-type classification |
| **Auto-quarantine** | New unknown devices are immediately restricted to DNS + DHCP only via iptables |
| **IoT learning pipeline** | New IoT devices enter a 48-hour observation window; DNS queries are collected into a per-device allow-list and the device is then restricted to those FQDNs only |
| **IoT allow-list** | IoT devices can only reach FQDNs learned during the observation window or explicitly approved; served as a Pi-hole adlist feed |
| **Honeypot** | Listens on 24 common attack ports, simulates real service banners/conversations, detects port sweeps and brute-force attempts, and classifies each event by intent and severity |
| **DNS filtering** | Pi-hole v6 integration for ad/tracker blocking and custom DNS sinkholing |
| **Traffic redirection** | Intercept and redirect DNS/DHCP traffic to Pi-hole via passive monitoring, iptables DNAT, ARP spoofing, DHCP injection, or full gateway takeover |
| **Live dashboard** | Real-time web UI with Server-Sent Events — approve/block/trust/IoT devices in one click; manage users, groups, and Pi-hole stats |
| **Alerting** | Severity-ranked alerts for new devices, honeypot hits, and policy violations |

---

## 🏗 Architecture

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
│  │                    Redis pub/sub                    │  │
│  └──────────────────────────┬──────────────────────────┘  │
│                             │                             │
│  ┌──────────────────────────▼──────┐   ┌──────────────┐   │
│  │           PostgreSQL            │   │   Pi-hole    │   │
│  └─────────────────────────────────┘   │  (DNS + UI)  │   │
│                                        └──────────────┘   │
│  ┌────────────────────────────────────────────────────┐   │
│  │              Dashboard  (Flask + SSE)              │   │
│  └────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
```

### Services

| Service | Port(s) | Description |
|---------|---------|-------------|
| `dashboard` | 3000 | Web management UI (Flask + Server-Sent Events) |
| `pihole` | 53 (DNS), 80 (API), 8080 (UI) | Pi-hole v6 DNS filtering / ad-blocking |
| `postgres` | internal | Persistent state |
| `redis` | internal | Event bus & ephemeral cache |
| `discovery` | host network | Network scanner (ARP + nmap + Pi-hole + DNS sniff + DHCP sniff + ARP sniff + SSDP + mDNS + NetBIOS + banners) |
| `guardian` | host network | iptables/ipset policy enforcement |
| `honeypot` | host network | Multi-protocol fake-service attack catcher |
| `redirector` | host network | DNS/DHCP traffic interception and quarantine enforcement |

---

## 🚀 Quick Start

### Prerequisites

| | Linux | macOS |
|---|---|---|
| OS | Debian / Ubuntu / Fedora / etc. | macOS 12+ with [Docker Desktop](https://www.docker.com/products/docker-desktop/) |
| Docker | ≥ 24 with Compose v2 plugin | Docker Desktop (includes Compose v2) |
| Host networking | Automatic (required for full enforcement) | Not required — bridge networking is used |

### 1. Clone & configure

```bash
git clone https://github.com/erichester76/thebox.git
cd thebox
cp .env.example .env
# Edit .env — set strong passwords and your network range
nano .env
```

### 2. Run the setup script (recommended)

The setup script auto-detects Linux vs macOS and uses the appropriate settings.

On Ubuntu and other `systemd-resolved` hosts, the script also disables the
local DNS stub listener (`DNSStubListener=no`) and repoints `/etc/resolv.conf`
to the non-stub resolver file so Pi-hole can claim host port 53.

```bash
sudo bash scripts/setup.sh
```

Or start manually:

```bash
# Linux (full capabilities — ARP scanning + iptables enforcement)
# If systemd-resolved is active, disable its stub listener first:
#   sudo mkdir -p /etc/systemd/resolved.conf.d
#   printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/thebox.conf >/dev/null
#   if [ "$(readlink -f /etc/resolv.conf)" = "/run/systemd/resolve/stub-resolv.conf" ]; then
#     sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
#   fi
#   sudo systemctl restart systemd-resolved
docker compose -f docker-compose.yml -f docker-compose.linux.yml up -d

# macOS (Docker Desktop)
docker compose -f docker-compose.yml -f docker-compose.macos.yml up -d
```

### 3. Open the dashboard

```
http://<host-ip>:3000
```

### 4. Point your router's DNS to this host

Set your DHCP server's DNS option to the IP address of the Docker host so that
all devices use Pi-hole for DNS resolution.

---

## 🍎 macOS Notes

On macOS, Docker Desktop's `network_mode: host` does not expose Docker's
embedded DNS resolver to host-mode containers, which causes service-name
hostnames such as `postgres` and `redis` to fail to resolve.  The macOS
overlay therefore keeps all services on Docker's default **bridge** network
(where DNS works correctly) and exposes honeypot ports via explicit port
mappings.  No special Docker Desktop settings are required — simply use the
macOS overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.macos.yml up -d
```

The setup script (`scripts/setup.sh`) applies this overlay automatically when
it detects macOS.

**How the compose files fit together:**

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Base — bridge networking, works on all platforms |
| `docker-compose.linux.yml` | Linux overlay — adds `network_mode: host` to discovery, guardian, honeypot, and redirector for full ARP scanning and iptables enforcement |
| `docker-compose.macos.yml` | macOS overlay — uses bridge networking (Docker DNS works); exposes honeypot ports via port mappings |

**Feature availability on macOS:**

| Feature | Status | Notes |
|---------|--------|-------|
| Dashboard, Pi-hole, PostgreSQL, Redis | ✅ Full | Bridge networking |
| Honeypot (port listeners) | ✅ Full | Ports mapped to Mac host via explicit port bindings |
| Pi-hole client discovery | ✅ Full | Queries the Pi-hole FTL API via bridge network |
| DNS packet sniffing | ⚠️ Limited | Sniffs the Docker bridge interface; may not capture queries from physical LAN hosts |
| DHCP hostname sniffing | ⚠️ Limited | Sniffs the Docker bridge interface; DHCP packets from physical LAN hosts may not reach the container |
| ARP-based LAN scanning / ARP sniffing | ⚠️ Limited | Docker Desktop VM's network namespace is used, not the Mac's physical interface. Discovery starts without errors but may not reach all LAN devices. |
| iptables quarantine / IoT allow-lists | ⚠️ Limited | iptables/ipset are Linux kernel features. Guardian starts and manages database state normally but will not enforce rules on physical LAN traffic. |
| ARP spoofing / traffic redirection | ⚠️ Limited | Redirector starts and manages state normally but ARP/iptables operations target the Docker VM's stack, not physical LAN traffic. |

For full network enforcement capabilities, run TheBox on a dedicated Linux host
(Raspberry Pi, mini-PC, VM, etc.) on your LAN.

---

## ⚙️ Configuration

All configuration is done via environment variables in `.env`.  Copy `.env.example` to `.env` and adjust the values for your environment:

```bash
cp .env.example .env
nano .env
```

### General

| Variable | Default | Description |
|----------|---------|-------------|
| `TZ` | `America/New_York` | Container timezone |
| `LOG_LEVEL` | `INFO` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

### PostgreSQL

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | `thebox` | Database name |
| `POSTGRES_USER` | `thebox` | Database username |
| `POSTGRES_PASSWORD` | — | Database password (**change in production**) |

### Pi-hole

| Variable | Default | Description |
|----------|---------|-------------|
| `PIHOLE_PASSWORD` | — | Pi-hole admin UI password (**change in production**) |
| `PIHOLE_DNS_PORT` | `53` | Host port for Pi-hole DNS |
| `PIHOLE_WEB_PORT` | `8080` | Host port for Pi-hole web UI |
| `PIHOLE_URL` | *(auto)* | Base URL of the Pi-hole v6 API (e.g. `http://pihole:80`); auto-derived from the internal Docker network if left empty |

### Dashboard

| Variable | Default | Description |
|----------|---------|-------------|
| `DASHBOARD_PORT` | `3000` | Dashboard HTTP port |
| `SECRET_KEY` | — | Flask session secret key (**change in production**) |
| `PIHOLE_SID_TTL` | `240` | Seconds to cache a Pi-hole v6 session ID before re-authenticating; set lower if you see 401 errors |
| `DASHBOARD_URL` | `http://dashboard:3000` | Internal URL the discovery service uses to register the IoT allow-list feed with Pi-hole |

### Network Discovery

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_RANGES` | `192.168.1.0/24` | Comma-separated CIDR ranges to scan |
| `SCAN_INTERVAL` | `300` | Seconds between ARP/nmap discovery scans |
| `DNS_SNIFF_ENABLED` | `true` | Capture DNS query packets (port 53) and mDNS responses (port 5353) to discover devices and extract hostnames in real-time (requires `NET_RAW`; most effective with `network_mode: host` on Linux) |
| `DNS_SNIFF_IFACE` | *(auto)* | Network interface to sniff; leave empty for auto-detection |
| `DHCP_SNIFF_ENABLED` | `true` | Extract device hostnames from DHCP DISCOVER/REQUEST packets (option 12) in real-time — more reliable than reverse DNS (requires `NET_RAW`) |
| `ARP_SNIFF_ENABLED` | `true` | Detect new devices immediately from ARP traffic, rather than waiting for the next periodic sweep; includes ARP spoof detection (requires `NET_RAW`) |
| `SSDP_ENABLED` | `true` | Send SSDP/UPnP multicast M-SEARCH probes to discover routers, smart TVs, NAS, and other UPnP devices |
| `SSDP_TIMEOUT` | `5` | Seconds to wait for SSDP responses per scan cycle |
| `MDNS_ENABLED` | `true` | Browse mDNS/Zeroconf DNS-SD service types (Bonjour/Avahi) to find Apple, Chromecast, printers, and HomeKit devices |
| `NETBIOS_ENABLED` | `true` | Run `nmap nbstat` across the subnet to retrieve NetBIOS hostnames and workgroup names for Windows/Samba hosts |
| `BANNER_GRAB_ENABLED` | `true` | Grab HTTP `Server` headers and TLS certificate subjects from open ports to enrich device hostname and vendor data |
| `BANNER_GRAB_TIMEOUT` | `3` | Timeout in seconds for HTTP/HTTPS banner connections |

### IoT Learning

| Variable | Default | Description |
|----------|---------|-------------|
| `IOT_LEARNING_HOURS` | `48` | Hours a new IoT device spends in the observation (learning) group before its DNS queries are collected and it is moved to the permanent IoT policy |
| `PIHOLE_IOT_GROUP` | `iot` | Name of the Pi-hole group IoT devices are placed in after learning completes; this group should have the IoT allow-list adlist attached |

### Device Guardian

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTO_QUARANTINE` | `true` | Quarantine new/unknown devices automatically |
| `QUARANTINE_VLAN` | `192.168.99.0/24` | CIDR for quarantined devices |
| `TRUSTED_NETWORKS` | `192.168.1.0/24` | Comma-separated trusted network ranges |

### Honeypot

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEYPOT_PORTS` | `21,22,23,25,53,80,110,135,143,389,443,445,1433,3306,3389,5432,5900,5985,6379,8080,8443,9200,11211,27017` | Comma-separated list of TCP ports the honeypot listens on |
| `HONEYPOT_IGNORED_NETWORKS` | `172.16.0.0/12,127.0.0.0/8` | CIDR ranges whose connections are silently ignored (no logging or alerting); default covers Docker bridge gateways and loopback to avoid internal health-checks flooding the log |
| `HONEYPOT_THRESHOLD_COUNT` | `3` | Number of hits from a single IP within `HONEYPOT_THRESHOLD_WINDOW` seconds before severity is escalated (`low` → `high`; 3× → `critical`) |
| `HONEYPOT_THRESHOLD_WINDOW` | `60` | Rolling window in seconds for hit-count threshold |
| `HONEYPOT_SWEEP_THRESHOLD` | `4` | Number of distinct destination ports a single IP must probe within `HONEYPOT_SWEEP_WINDOW` seconds to be classified as a port sweep |
| `HONEYPOT_SWEEP_WINDOW` | `60` | Rolling window in seconds for port-sweep detection |
| `HONEYPOT_RECV_TIMEOUT` | `4` | Seconds to wait for the attacker to send data after the banner is sent |
| `HONEYPOT_MAX_PAYLOAD_LENGTH` | `2000` | Maximum characters stored as `payload_preview` in the database; increase to capture longer attacker conversations |
| `HONEYPOT_CREDENTIAL_WINDOW_MULTIPLIER` | `5` | Multiplier applied to `HONEYPOT_THRESHOLD_WINDOW` for the credential-tracking window, allowing slow brute-force detection across a wider time range |

### Redirector

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIRECT_MODE` | `passive` | Comma-separated list of active redirect modes (see [Redirector Modes](#-redirector-modes) below) |
| `NETWORK_INTERFACE` | `eth0` | Network interface used for ARP/packet operations (auto-detected on Linux) |
| `GATEWAY_IP` | *(auto)* | Default gateway IP; auto-detected from routing table if empty |
| `PIHOLE_IP` | *(auto)* | Pi-hole IP address; defaults to `BOX_IP` / TheBox's own address if empty |
| `BOX_IP` | *(auto)* | TheBox's own IP address; auto-detected from `NETWORK_INTERFACE` if empty |
| `BLACKHOLE_QUARANTINED` | `false` | Drop all traffic from quarantined devices except DHCP and DNS |
| `ARP_REFRESH_INTERVAL` | `10` | Seconds between ARP refresh packets for active spoof modes |

---

## 🔀 Redirector Modes

The `redirector` service supports multiple operating modes, set via the `REDIRECT_MODE` environment variable as a comma-separated list.  Modes are listed from least to most intrusive:

| Mode | Description |
|------|-------------|
| `passive` | Monitor only — no active redirection (default) |
| `redirect_dns` | Install iptables DNAT rules to forward all DNS traffic arriving on this host to Pi-hole.  Requires TheBox to already be in the traffic path (e.g. as the default gateway). |
| `arp_spoof` | Periodically send gratuitous ARP replies to LAN hosts advertising TheBox's MAC as the default gateway, enabling DNS traffic interception without device reconfiguration. |
| `dhcp_advertise` | Listen for DHCP discover/request packets and inject offers/acks advertising TheBox/Pi-hole as the DNS server.  Works alongside the upstream DHCP server. |
| `dhcp_starvation` | Exhaust the upstream DHCP pool with fabricated discover packets so devices fall back to TheBox as the DHCP server.  **⚠️ Highly disruptive** — use only when TheBox is intended to be the sole DHCP server. |
| `gateway_takeover` | ARP-spoof every active LAN host *and* the upstream router simultaneously so that all IP traffic flows through TheBox for inspection and filtering (most intrusive). |

The redirector also listens on the Redis event bus for `quarantine_device` / `unquarantine_device` events from the guardian service and ARP-spoofs the named device so its traffic is intercepted.  When `BLACKHOLE_QUARANTINED=true`, additional iptables rules drop all quarantined-device traffic except DHCP and DNS.

> **Note:** All modes beyond `passive` require `network_mode: host` on Linux and `NET_ADMIN` / `NET_RAW` capabilities.  On macOS, ARP and iptables operations target the Docker Desktop VM's network stack, not physical LAN traffic.

---

## 📋 Device Lifecycle

```
New device appears
      │
      ▼
  [quarantined]  ← DNS + DHCP only (iptables ipset)
      │
      ├─── Review in dashboard ──► [trusted]        ← full access
      │
      ├─── Mark as IoT         ──► [iot_learning]   ← unrestricted for IOT_LEARNING_HOURS
      │                                 │
      │                                 └──► [iot]  ← DNS-restricted to learned FQDNs
      │
      └─── Block               ──► [blocked]        ← DROP everything
```

---

## 🌱 IoT Learning Pipeline

When you mark a device as **IoT** in the dashboard for the first time, it enters an observation window whose length is set by `IOT_LEARNING_HOURS` (default: **48 hours**):

1. **Dashboard** sets the device status to `iot_learning` and publishes an `iot_learning_start_requested` event on Redis.
2. **Discovery** creates a temporary Pi-hole group named `iot_<IP>_learning` and registers the device as a Pi-hole client in that group — allowing it unrestricted internet access so all DNS queries are visible.
3. After `IOT_LEARNING_HOURS` hours, **Discovery** finalises the session:
   - Queries Pi-hole for every unique domain the device resolved during the window.
   - Inserts those FQDNs into the `iot_allowlist` table.
   - Registers the dashboard's `/iot-allowlist.txt` feed as a Pi-hole adlist for the permanent `PIHOLE_IOT_GROUP`.
   - Moves the device into that Pi-hole group and removes the temporary learning group.
4. **Guardian** detects the status change to `iot` and enforces the restricted ipset policy, dropping all DNS queries to FQDNs not in the allow-list.

The `/iot-allowlist.txt` endpoint served by the dashboard is a plain-text feed (one FQDN per line) containing both globally-shared entries and any per-device overrides added manually.

---

## 🕵️ Honeypot

The honeypot listens on up to 24 ports simultaneously and simulates real service banners and multi-turn protocol conversations to capture attacker behaviour:

| Ports | Simulated Service |
|-------|-------------------|
| 21 | FTP (USER/PASS exchange) |
| 22 | SSH (banner only) |
| 23 | Telnet |
| 25 | SMTP (EHLO/MAIL/RCPT/AUTH/DATA) |
| 53 | DNS stub |
| 80 / 8080 | HTTP (full request parsing) |
| 110 | POP3 (USER/PASS) |
| 135 | MS-RPC/DCOM |
| 143 | IMAP (LOGIN/AUTHENTICATE/CAPABILITY) |
| 389 | LDAP |
| 443 / 8443 | HTTPS (TLS banner) |
| 445 | SMB |
| 1433 | Microsoft SQL Server |
| 3306 | MySQL |
| 3389 | RDP |
| 5432 | PostgreSQL |
| 5900 | VNC |
| 5985 | WinRM |
| 6379 | Redis |
| 9200 | Elasticsearch |
| 11211 | Memcached |
| 27017 | MongoDB |

### Severity & Intent Classification

Each event is classified by **interaction level** (`none` → `banner` → `data` → `credentials` → `commands`) and **intent** (`scan`, `recon`, `probe`, `brute_force`, `exploit`, `sweep`), then mapped to a **severity** (`low`, `high`, `critical`):

- Hits crossing `HONEYPOT_THRESHOLD_COUNT` within `HONEYPOT_THRESHOLD_WINDOW` seconds escalate from `low` → `high`, and 3× the threshold → `critical`.
- A single IP probing `HONEYPOT_SWEEP_THRESHOLD` or more distinct ports within `HONEYPOT_SWEEP_WINDOW` seconds is flagged as a **port sweep** (`high`).
- Credential submissions (brute-force) are tracked over a wider window (`HONEYPOT_THRESHOLD_WINDOW × HONEYPOT_CREDENTIAL_WINDOW_MULTIPLIER`).
- Exploit-level interactions always generate a `critical` alert regardless of frequency.

---

## 🛠 Development

```bash
# Run just the infrastructure
docker compose up -d postgres redis

# Run a service locally for testing (discovery as example)
cd services/discovery
pip install -r requirements.txt
DATABASE_URL=postgresql://thebox:thebox_secret@localhost:5432/thebox \
REDIS_URL=redis://localhost:6379/0 \
NETWORK_RANGES=192.168.1.0/24 \
python app.py
```

---

## 📁 Project Structure

```
thebox/
├── docker-compose.yml           # Base orchestration (bridge networking)
├── docker-compose.linux.yml     # Linux overlay (host networking + iptables)
├── docker-compose.macos.yml     # macOS overlay (bridge networking + port mappings)
├── .env.example                 # Configuration template — copy to .env
├── config/
│   ├── pihole/                  # Pi-hole persistent config
│   ├── postgres/init.sql        # DB schema (devices, alerts, honeypot_events, iot_allowlist, …)
│   └── redis/redis.conf
├── services/
│   ├── discovery/               # Network scanner (ARP + nmap + Pi-hole + DNS/DHCP/ARP sniff + SSDP + mDNS + NetBIOS + banners)
│   ├── guardian/                # iptables/ipset policy enforcement
│   ├── honeypot/                # Multi-protocol fake-service attack catcher
│   ├── redirector/              # DNS/DHCP traffic redirector + quarantine enforcement
│   └── dashboard/               # Flask web UI (SSE, device/group/user management, IoT allowlist feed)
└── scripts/
    └── setup.sh                 # One-shot host setup (systemd-resolved, IP forwarding, compose launcher)
```

---

## 🔒 Security Notes

- Change all default passwords in `.env` before deploying.
- The `discovery`, `guardian`, `redirector`, and `honeypot` services run with `network_mode: host` on Linux and
  require `NET_ADMIN` / `NET_RAW` capabilities to perform ARP scans, manage
  iptables, and intercept/redirect network traffic.  This is intentional — they act as the network enforcement plane.
- The honeypot logs all data received from attackers.  Ensure your storage is
  not unbounded (PostgreSQL's `honeypot_events` table can be pruned on a
  schedule).
- Pi-hole's admin UI is exposed on port 8080.  Consider placing it behind a
  reverse proxy with authentication if your host is internet-facing.
- The `arp_spoof`, `dhcp_starvation`, and `gateway_takeover` redirector modes
  actively disrupt normal network operation.  Use them only in environments
  where TheBox is the intended network enforcement device and you understand the
  impact on other hosts on the LAN.

---

## 📜 License

[MIT](LICENSE)
