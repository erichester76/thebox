# 🛡 TheBox — Container-Based Home Network Server

TheBox is a self-hosted, Docker Compose-based home network security and management platform.  It brings together capabilities inspired by Pi-hole, Firewalla, Bark, and UniFi into a single, easily deployable solution.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Auto-discovery** | ARP sweeps + nmap scan every N minutes to find every device on your network |
| **Vendor / OS detection** | MAC OUI lookup, nmap OS fingerprinting, and heuristic device-type classification |
| **Auto-quarantine** | New unknown devices are immediately restricted to DNS + DHCP only via iptables |
| **IoT allow-list** | IoT devices can only reach FQDNs you explicitly approve |
| **Honeypot** | Listens on 13 common attack ports, logs all connection attempts, auto-blocks repeat offenders |
| **DNS filtering** | Pi-hole integration for ad/tracker blocking and custom DNS sinkholing |
| **Live dashboard** | Real-time web UI with Server-Sent Events — approve/block/trust devices in one click |
| **Alerting** | Severity-ranked alerts for new devices, honeypot hits, and policy violations |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────┐
│                      Docker Host                    │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ discovery│  │ guardian │  │     honeypot     │   │
│  │ (Python) │  │ (Python) │  │     (Python)     │   │
│  └────┬─────┘  └─────┬────┘  └─────────┬────────┘   │
│       │              │                 │            │
│  ┌────▼──────────────▼─────────────────▼──────────┐ │
│  │               Redis pub/sub                    │ │
│  └─────────────────────┬──────────────────────────┘ │
│                        │                            │
│  ┌─────────────────────▼───────┐   ┌─────────────┐  │
│  │          PostgreSQL         │   │   Pi-hole   │  │
│  └─────────────────────────────┘   │  (DNS + UI) │  │
│                                    └─────────────┘  │
│  ┌────────────────────────────────────────────────┐ │
│  │           Dashboard  (Flask + SSE)             │ │
│  └────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

### Services

| Service | Port(s) | Description |
|---------|---------|-------------|
| `dashboard` | 3000 | Web management UI |
| `pihole` | 53 (DNS), 8080 (UI) | DNS filtering / ad-blocking |
| `postgres` | internal | Persistent state |
| `redis` | internal | Event bus & ephemeral cache |
| `discovery` | host network | Network scanner (ARP + nmap) |
| `guardian` | host network | iptables policy enforcement |
| `honeypot` | host network | Fake-service attack catcher |

---

## 🚀 Quick Start

### Prerequisites

| | Linux | macOS |
|---|---|---|
| OS | Debian / Ubuntu / Fedora / etc. | macOS 12+ with [Docker Desktop ≥ 4.29](https://www.docker.com/products/docker-desktop/) |
| Docker | ≥ 24 with Compose v2 plugin | Docker Desktop ≥ 4.29 (includes Compose v2) |
| Host networking | Automatic | Must enable in Docker Desktop — see [macOS notes](#-macos-notes) below |

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

```bash
sudo bash scripts/setup.sh
```

Or start manually:

```bash
# Linux (full capabilities — ARP scanning + iptables enforcement)
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

### Enabling host networking in Docker Desktop

TheBox uses `network_mode: host` for the discovery, guardian, and honeypot
services.  Docker Desktop ≥ 4.29 supports this on macOS, but the feature must
be explicitly enabled before running the stack:

1. Open **Docker Desktop → Settings (⚙) → Resources → Network**
2. Turn on **"Enable host networking"**
3. Click **Apply & Restart**

Once enabled, the `docker-compose.macos.yml` overlay applies `network_mode: host`
to those services — identical to the Linux overlay — so ports are bound directly
on the Mac host's interfaces without any explicit port-mapping workarounds.
The setup script detects macOS and applies this overlay automatically.

**How the compose files fit together:**

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Base — bridge networking, works on all platforms without host networking |
| `docker-compose.linux.yml` | Linux overlay — adds `network_mode: host` to discovery, guardian, honeypot |
| `docker-compose.macos.yml` | macOS overlay — same as the Linux overlay; requires Docker Desktop ≥ 4.29 with host networking enabled |

**Feature availability on macOS (with host networking enabled):**

| Feature | Status | Notes |
|---------|--------|-------|
| Dashboard, Pi-hole, PostgreSQL, Redis | ✅ Full | Bridge networking; unaffected by host-networking setting |
| Honeypot (port listeners) | ✅ Full | Ports bound directly on Mac host via `network_mode: host` |
| ARP-based LAN scanning | ⚠️ Limited | `network_mode: host` attaches to the Docker Desktop Linux VM's network namespace. ARP sweeps may not reach all physical LAN devices depending on the VM's interface attachment. Discovery starts without errors. |
| iptables quarantine / IoT allow-lists | ⚠️ Limited | iptables/ipset are Linux kernel features that operate on the Linux VM's network stack, not the Mac host. Guardian starts and manages database state normally but will not enforce rules on physical LAN traffic. |

**Running without host networking (Docker Desktop < 4.29 or feature disabled):**

Use the base compose file only — all services start in bridge mode.
The honeypot is not accessible from outside Docker in this mode.

```bash
docker compose up -d
```

For full network enforcement capabilities, run TheBox on a dedicated Linux host
(Raspberry Pi, mini-PC, VM, etc.) on your LAN.

---

## ⚙️ Configuration

All configuration is done via environment variables in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_RANGES` | `192.168.1.0/24` | Comma-separated CIDR ranges to scan |
| `SCAN_INTERVAL` | `300` | Seconds between discovery scans |
| `AUTO_QUARANTINE` | `true` | Quarantine new devices automatically |
| `QUARANTINE_VLAN` | `192.168.99.0/24` | CIDR for quarantined devices |
| `HONEYPOT_PORTS` | `21,22,23,…` | Ports the honeypot listens on |
| `PIHOLE_PASSWORD` | — | Pi-hole admin password |
| `DASHBOARD_PORT` | `3000` | Dashboard HTTP port |

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
│   ├── discovery/           # Network scanner (ARP + nmap)
│   ├── guardian/            # iptables policy + quarantine
│   ├── honeypot/            # Fake-service attack catcher
│   └── dashboard/           # Flask web UI
└── scripts/
    └── setup.sh             # One-shot host setup
```

---

## 🔒 Security Notes

- Change all default passwords in `.env` before deploying.
- The `discovery` and `guardian` services run with `network_mode: host` and
  require `NET_ADMIN` / `NET_RAW` capabilities to perform ARP scans and manage
  iptables.  This is intentional — they act as the network enforcement plane.
- The honeypot logs all data received from attackers.  Ensure your storage is
  not unbounded (PostgreSQL's `honeypot_events` table can be pruned on a
  schedule).
- Pi-hole's admin UI is exposed on port 8080.  Consider placing it behind a
  reverse proxy with authentication if your host is internet-facing.

---

## 📜 License

[MIT](LICENSE)
