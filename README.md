# 🛡 TheBox — Container-Based Home Network Server

TheBox is a self-hosted, Docker Compose-based home network security and management platform.  It brings together capabilities inspired by Pi-hole, Firewalla, Bark, and UniFi into a single, easily deployable solution.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Auto-discovery** | ARP sweeps + nmap scan every N minutes to find every device on your network |
| **Pi-hole client discovery** | Queries the Pi-hole FTL API to discover devices that have made DNS queries, even if they didn't respond to ARP |
| **DNS packet sniffing** | Captures DNS query packets on the network interface to discover devices in real-time |
| **Vendor / OS detection** | MAC OUI lookup, nmap OS fingerprinting, and heuristic device-type classification |
| **Auto-quarantine** | New unknown devices are immediately restricted to DNS + DHCP only via iptables |
| **IoT allow-list** | IoT devices can only reach FQDNs you explicitly approve |
| **Honeypot** | Listens on 13 common attack ports, logs all connection attempts, auto-blocks repeat offenders |
| **DNS filtering** | Pi-hole integration for ad/tracker blocking and custom DNS sinkholing |
| **Traffic redirection** | Intercept and redirect DNS/DHCP traffic to Pi-hole via passive monitoring, iptables DNAT, ARP spoofing, DHCP injection, or full gateway takeover |
| **Live dashboard** | Real-time web UI with Server-Sent Events — approve/block/trust devices in one click |
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
| `dashboard` | 3000 | Web management UI |
| `pihole` | 53 (DNS), 8080 (UI) | DNS filtering / ad-blocking |
| `postgres` | internal | Persistent state |
| `redis` | internal | Event bus & ephemeral cache |
| `discovery` | host network | Network scanner (ARP + nmap + Pi-hole + DNS sniff) |
| `guardian` | host network | iptables policy enforcement |
| `honeypot` | host network | Fake-service attack catcher |
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
| ARP-based LAN scanning | ⚠️ Limited | Docker Desktop VM's network namespace is used, not the Mac's physical interface. Discovery starts without errors but may not reach all LAN devices. |
| iptables quarantine / IoT allow-lists | ⚠️ Limited | iptables/ipset are Linux kernel features. Guardian starts and manages database state normally but will not enforce rules on physical LAN traffic. |
| ARP spoofing / traffic redirection | ⚠️ Limited | Redirector starts and manages state normally but ARP/iptables operations target the Docker VM's stack, not physical LAN traffic. |

For full network enforcement capabilities, run TheBox on a dedicated Linux host
(Raspberry Pi, mini-PC, VM, etc.) on your LAN.

---

## ⚙️ Configuration

All configuration is done via environment variables in `.env`:

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

### Dashboard

| Variable | Default | Description |
|----------|---------|-------------|
| `DASHBOARD_PORT` | `3000` | Dashboard HTTP port |
| `SECRET_KEY` | — | Flask session secret key (**change in production**) |

### Network Discovery

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_RANGES` | `192.168.1.0/24` | Comma-separated CIDR ranges to scan |
| `SCAN_INTERVAL` | `300` | Seconds between ARP/nmap discovery scans |
| `DNS_SNIFF_ENABLED` | `true` | Capture DNS query packets to discover devices in real-time (requires `NET_RAW`; most effective with `network_mode: host` on Linux) |
| `DNS_SNIFF_IFACE` | *(auto)* | Network interface to sniff; leave empty for auto-detection |

### Device Guardian

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTO_QUARANTINE` | `true` | Quarantine new/unknown devices automatically |
| `QUARANTINE_VLAN` | `192.168.99.0/24` | CIDR for quarantined devices |
| `TRUSTED_NETWORKS` | `192.168.1.0/24` | Comma-separated trusted network ranges |

### Honeypot

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEYPOT_PORTS` | `21,22,23,25,80,110,143,443,445,3306,3389,8080` | Comma-separated list of ports the honeypot listens on |

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
  [quarantined]  ← DNS + DHCP only
      │
      ├─── Review in dashboard ──► [trusted]  ← full access
      │
      ├─── Mark as IoT         ──► [iot]      ← allow-list only
      │
      └─── Block               ──► [blocked]  ← DROP everything
```

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
├── docker-compose.yml       # Orchestration
├── .env.example             # Configuration template
├── config/
│   ├── pihole/              # Pi-hole persistent config
│   ├── postgres/init.sql    # DB schema
│   └── redis/redis.conf
├── services/
│   ├── discovery/           # Network scanner (ARP + nmap + Pi-hole + DNS sniff)
│   ├── guardian/            # iptables policy + quarantine
│   ├── honeypot/            # Fake-service attack catcher
│   ├── redirector/          # DNS/DHCP traffic redirector + quarantine enforcement
│   └── dashboard/           # Flask web UI
└── scripts/
    └── setup.sh             # One-shot host setup
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
