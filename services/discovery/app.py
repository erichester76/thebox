"""
TheBox — Network Discovery Service
===================================
Continuously scans the local network to discover devices, resolve hostnames,
identify vendors via MAC OUI lookup, and attempt OS fingerprinting.  New
devices are stored in PostgreSQL and a "new_device" event is published to
Redis so that the guardian and dashboard services can react in real-time.

Additional discovery methods:
  - Pi-hole API: queries the Pi-hole FTL API for known network clients
    (including MAC addresses when available).
  - DNS packet sniffing: captures DNS query packets on the network interface
    to discover devices that send queries to Pi-hole or the honeypot DNS
    listener.  Newly seen source IPs are ARP-resolved to obtain their MAC
    addresses and then upserted like any other discovered device.
  - SSDP/UPnP: sends multicast M-SEARCH probes and fetches UPnP device
    description XML to extract manufacturer, model, and friendly name.
  - mDNS/Zeroconf: browses common DNS-SD service types (Bonjour/Avahi) to
    discover Apple, Chromecast, printer, HomeKit, and other smart-home devices.
  - NetBIOS: runs nmap's nbstat NSE script across the subnet to retrieve
    NetBIOS hostnames and workgroup info for Windows/Samba hosts.
  - HTTP/HTTPS banners: grabs the Server header from open HTTP ports and
    reads TLS certificate subject/SAN fields from open HTTPS ports to derive
    hostnames, vendor, and model information.
"""

import csv
import io
import ipaddress
import json
import hashlib
import logging
import os
import queue
import re
import socket
import ssl
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.request import urlopen

import nmap
import psycopg2
import psycopg2.extras
import redis
import requests
import schedule
import structlog
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from scapy.all import ARP, BOOTP, DNSRR, DHCP, DNS, DNSQR, Ether, IP, TCP, UDP, srp, sniff  # noqa: F401
from zeroconf import ServiceBrowser, Zeroconf

# ─── Configuration ───────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
NETWORK_RANGES = [r.strip() for r in os.environ.get("NETWORK_RANGES", "192.168.1.0/24").split(",")]
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "300"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# Pi-hole integration
PIHOLE_URL = os.environ.get("PIHOLE_URL", "").rstrip("/")
PIHOLE_PASSWORD = os.environ.get("PIHOLE_PASSWORD", "")

# IoT learning period
IOT_LEARNING_HOURS = int(os.environ.get("IOT_LEARNING_HOURS", "48"))
PIHOLE_IOT_GROUP = os.environ.get("PIHOLE_IOT_GROUP", "iot")
# URL of the dashboard service as reachable from within the Docker network.
# Used to tell Pi-hole where to fetch the IoT allow-list as an adlist URL.
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "").rstrip("/")

# Maximum pages to fetch from Pi-hole's paginated queries API per learning
# session (1 000 pages × 1 000 results = up to 1 million queries).  Prevents
# an infinite loop when Pi-hole keeps returning a cursor on every page.
_PIHOLE_QUERY_MAX_PAGES = 1000
# Maximum domain-name length stored in iot_allowlist.fqdn (VARCHAR(255)).
_FQDN_MAX_LEN = 255

# DNS packet sniffing
DNS_SNIFF_ENABLED = os.environ.get("DNS_SNIFF_ENABLED", "true").lower() == "true"
DNS_SNIFF_IFACE = os.environ.get("DNS_SNIFF_IFACE") or None  # None → scapy auto-selects

# SSDP/UPnP discovery
SSDP_ENABLED = os.environ.get("SSDP_ENABLED", "true").lower() == "true"
SSDP_TIMEOUT = int(os.environ.get("SSDP_TIMEOUT", "5"))

# mDNS/Zeroconf discovery
MDNS_ENABLED = os.environ.get("MDNS_ENABLED", "true").lower() == "true"

# NetBIOS/NBNS discovery via nmap nbstat script
NETBIOS_ENABLED = os.environ.get("NETBIOS_ENABLED", "true").lower() == "true"

# HTTP/HTTPS banner grabbing
BANNER_GRAB_ENABLED = os.environ.get("BANNER_GRAB_ENABLED", "true").lower() == "true"
BANNER_GRAB_TIMEOUT = float(os.environ.get("BANNER_GRAB_TIMEOUT", "3"))

# DHCP packet sniffing — extracts device hostnames from DHCP option 12
DHCP_SNIFF_ENABLED = os.environ.get("DHCP_SNIFF_ENABLED", "true").lower() == "true"

# ARP packet sniffing — real-time device detection between scan cycles
ARP_SNIFF_ENABLED = os.environ.get("ARP_SNIFF_ENABLED", "true").lower() == "true"

# IEEE OUI vendor database — downloaded at startup and cached locally
_OUI_CSV_URL = os.environ.get(
    "OUI_CSV_URL", "https://standards-oui.ieee.org/oui/oui.csv"
)
_OUI_CSV_PATH = os.environ.get("OUI_CSV_PATH", "/tmp/oui.csv")

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, LOG_LEVEL, logging.INFO)),
)
log = structlog.get_logger()

# ─── MAC vendor lookup ───────────────────────────────────────────────────────

def _load_oui_table() -> dict[str, str]:
    """Download (or read from cache) the IEEE MA-L OUI CSV.

    Returns a dict mapping 6-hex-char OUI (e.g. ``"D8BB2C"``) to the
    registered organisation name (e.g. ``"Amazon Technologies Inc."``).

    On first call the file is fetched from *_OUI_CSV_URL* and written to
    *_OUI_CSV_PATH* for offline reuse.  If the download fails the cached
    copy is used.  Returns an empty dict when both sources are unavailable.
    """
    table: dict[str, str] = {}

    raw: str | None = None
    try:
        log.info("oui_download_start", url=_OUI_CSV_URL)
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) "
                "Gecko/20100101 Firefox/124.0"
            )
        }
        resp = requests.get(_OUI_CSV_URL, timeout=30, headers=headers)
        resp.raise_for_status()
        raw = resp.text
        try:
            with open(_OUI_CSV_PATH, "w", encoding="utf-8") as fh:
                fh.write(raw)
        except OSError as err:
            log.warning("oui_cache_write_failed", path=_OUI_CSV_PATH, error=str(err))
        log.info("oui_download_done", url=_OUI_CSV_URL)
    except Exception as exc:
        log.warning("oui_download_failed", error=str(exc))

    if raw is None:
        try:
            with open(_OUI_CSV_PATH, encoding="utf-8") as fh:
                raw = fh.read()
            log.info("oui_loaded_from_cache", path=_OUI_CSV_PATH)
        except OSError:
            log.warning("oui_cache_not_found", path=_OUI_CSV_PATH)
            return table

    skipped = 0
    reader = csv.reader(io.StringIO(raw))
    next(reader, None)  # skip header row
    for row in reader:
        if len(row) < 3:
            skipped += 1
            continue
        oui = row[1].strip().upper()
        name = row[2].strip()
        if oui and name:
            table[oui] = name

    if skipped:
        log.warning("oui_rows_skipped", skipped=skipped, reason="fewer than 3 columns")
    log.info("oui_table_loaded", entries=len(table))
    return table


mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()
except Exception:
    log.warning("mac_vendor_update_failed", msg="Using cached vendor list")

_oui_table: dict[str, str] = _load_oui_table()


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)


# ─── Schema bootstrap ────────────────────────────────────────────────────────

def ensure_schema():
    """Create tables this service reads from or writes to.

    Scoped to: ``users`` (FK dependency for devices), ``devices``,
    ``scan_runs``, ``iot_allowlist``, ``iot_learning_sessions``.
    All DDL uses ``IF NOT EXISTS`` so this is safe to call on every startup.
    """
    statements = [
        # users — FK dependency for devices.owner_id
        """CREATE TABLE IF NOT EXISTS users (
            id              SERIAL PRIMARY KEY,
            username        VARCHAR(64) NOT NULL UNIQUE,
            display_name    VARCHAR(255),
            email           VARCHAR(255),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        # devices — discovery inserts / updates every discovered host
        """CREATE TABLE IF NOT EXISTS devices (
            id              SERIAL PRIMARY KEY,
            mac_address     VARCHAR(17) NOT NULL UNIQUE,
            ip_address      VARCHAR(45),
            hostname        VARCHAR(255),
            vendor          VARCHAR(255),
            device_type     VARCHAR(64) DEFAULT 'unknown',
            os_guess        VARCHAR(255),
            first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            status          VARCHAR(32) NOT NULL DEFAULT 'new',
            notes           TEXT,
            open_ports      JSONB DEFAULT '[]',
            extra_info      JSONB DEFAULT '{}',
            owner_id        INTEGER REFERENCES users(id) ON DELETE SET NULL
        )""",
        # scan_runs — discovery records each scan cycle
        """CREATE TABLE IF NOT EXISTS scan_runs (
            id              SERIAL PRIMARY KEY,
            started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            finished_at     TIMESTAMPTZ,
            network_range   VARCHAR(64) NOT NULL,
            devices_found   INTEGER NOT NULL DEFAULT 0,
            new_devices     INTEGER NOT NULL DEFAULT 0,
            status          VARCHAR(32) NOT NULL DEFAULT 'running'
        )""",
        # iot_allowlist — FQDNs permitted for IoT devices.
        # device_id is nullable: NULL means the entry is global (shared across
        # all IoT devices); a non-NULL value ties the entry to a specific device.
        """CREATE TABLE IF NOT EXISTS iot_allowlist (
            id          SERIAL PRIMARY KEY,
            device_id   INTEGER REFERENCES devices(id) ON DELETE CASCADE,
            fqdn        VARCHAR(255) NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(device_id, fqdn)
        )""",
        # iot_learning_sessions — tracks the 48-hour observation window for
        # each newly-discovered IoT device.
        """CREATE TABLE IF NOT EXISTS iot_learning_sessions (
            id                    SERIAL PRIMARY KEY,
            device_id             INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            pihole_group_name     VARCHAR(64) NOT NULL,
            learning_started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            learning_completed_at TIMESTAMPTZ,
            status                VARCHAR(32) NOT NULL DEFAULT 'active',
            UNIQUE(device_id)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_devices_mac        ON devices(mac_address)",
        "CREATE INDEX IF NOT EXISTS idx_devices_ip         ON devices(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_devices_status     ON devices(status)",
        "CREATE INDEX IF NOT EXISTS idx_iot_learning_status  ON iot_learning_sessions(status)",
        "CREATE INDEX IF NOT EXISTS idx_iot_learning_started ON iot_learning_sessions(learning_started_at)",
        # Partial unique index: only one global entry (device_id IS NULL) per FQDN.
        # The UNIQUE(device_id, fqdn) constraint above allows multiple NULLs.
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_iot_allowlist_global_fqdn
            ON iot_allowlist(fqdn) WHERE device_id IS NULL""",
        # Migration: add ipv6_address column if the table already exists without it.
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS ipv6_address VARCHAR(45)",
        "CREATE INDEX IF NOT EXISTS idx_devices_ipv6       ON devices(ipv6_address)",
        # Migration tracking — ensure the table exists and record all versions
        # covered by this service's schema management.
        """CREATE TABLE IF NOT EXISTS schema_migrations (
            version     VARCHAR(16) NOT NULL PRIMARY KEY,
            applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        "INSERT INTO schema_migrations (version) VALUES ('0001') ON CONFLICT (version) DO NOTHING",
        "INSERT INTO schema_migrations (version) VALUES ('0002') ON CONFLICT (version) DO NOTHING",
        "INSERT INTO schema_migrations (version) VALUES ('0003') ON CONFLICT (version) DO NOTHING",
    ]
    conn = get_db()
    try:
        with conn.cursor() as cur:
            for stmt in statements:
                cur.execute(stmt)
        conn.commit()
    finally:
        conn.close()
    log.info("schema_ensured")


# ─── Settings helpers ────────────────────────────────────────────────────────

def get_setting(key: str, default: str = "") -> str:
    """Return the current value for *key* from the settings table.

    Falls back to *default* when the key is absent or when the database is
    unreachable (e.g. during very early startup before the schema exists).
    """
    try:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT value FROM settings WHERE key = %s", (key,))
                row = cur.fetchone()
                return row["value"] if row else default
        finally:
            conn.close()
    except Exception as exc:
        log.warning("get_setting_failed", key=key, error=str(exc))
        return default


def _load_settings() -> None:
    """Read all tuneable settings from the database and update module globals.

    Called once at startup *after* ``ensure_schema``.  Uses env-var values as
    the fallback so that existing deployments keep working unchanged.
    """
    global NETWORK_RANGES, SCAN_INTERVAL, PIHOLE_URL, PIHOLE_PASSWORD
    global IOT_LEARNING_HOURS, PIHOLE_IOT_GROUP, DASHBOARD_URL
    global DNS_SNIFF_ENABLED, DNS_SNIFF_IFACE
    global SSDP_ENABLED, SSDP_TIMEOUT
    global MDNS_ENABLED, NETBIOS_ENABLED
    global BANNER_GRAB_ENABLED, BANNER_GRAB_TIMEOUT
    global DHCP_SNIFF_ENABLED, ARP_SNIFF_ENABLED

    NETWORK_RANGES = [r.strip() for r in get_setting("NETWORK_RANGES", ",".join(NETWORK_RANGES)).split(",") if r.strip()]
    SCAN_INTERVAL  = int(get_setting("SCAN_INTERVAL", str(SCAN_INTERVAL)))
    PIHOLE_URL     = get_setting("PIHOLE_URL", PIHOLE_URL).rstrip("/")
    PIHOLE_PASSWORD = get_setting("PIHOLE_PASSWORD", PIHOLE_PASSWORD)
    IOT_LEARNING_HOURS = int(get_setting("IOT_LEARNING_HOURS", str(IOT_LEARNING_HOURS)))
    PIHOLE_IOT_GROUP   = get_setting("PIHOLE_IOT_GROUP", PIHOLE_IOT_GROUP)
    DASHBOARD_URL      = get_setting("DASHBOARD_URL", DASHBOARD_URL).rstrip("/")
    DNS_SNIFF_ENABLED  = get_setting("DNS_SNIFF_ENABLED", str(DNS_SNIFF_ENABLED).lower()).lower() == "true"
    dns_iface          = get_setting("DNS_SNIFF_IFACE", DNS_SNIFF_IFACE or "")
    DNS_SNIFF_IFACE    = dns_iface or None
    SSDP_ENABLED       = get_setting("SSDP_ENABLED", str(SSDP_ENABLED).lower()).lower() == "true"
    SSDP_TIMEOUT       = int(get_setting("SSDP_TIMEOUT", str(SSDP_TIMEOUT)))
    MDNS_ENABLED       = get_setting("MDNS_ENABLED", str(MDNS_ENABLED).lower()).lower() == "true"
    NETBIOS_ENABLED    = get_setting("NETBIOS_ENABLED", str(NETBIOS_ENABLED).lower()).lower() == "true"
    BANNER_GRAB_ENABLED  = get_setting("BANNER_GRAB_ENABLED", str(BANNER_GRAB_ENABLED).lower()).lower() == "true"
    BANNER_GRAB_TIMEOUT  = float(get_setting("BANNER_GRAB_TIMEOUT", str(BANNER_GRAB_TIMEOUT)))
    DHCP_SNIFF_ENABLED   = get_setting("DHCP_SNIFF_ENABLED", str(DHCP_SNIFF_ENABLED).lower()).lower() == "true"
    ARP_SNIFF_ENABLED    = get_setting("ARP_SNIFF_ENABLED", str(ARP_SNIFF_ENABLED).lower()).lower() == "true"
    log.info("settings_loaded", networks=NETWORK_RANGES, scan_interval=SCAN_INTERVAL)

def arp_sweep(network: str) -> list[dict]:
    """Send ARP requests for every host in *network* and collect replies."""
    log.info("arp_sweep_start", network=network)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=2, verbose=False)
    hosts = []
    for _, rcv in answered:
        hosts.append({"ip": rcv.psrc, "mac": rcv.hwsrc.upper()})
    log.info("arp_sweep_done", network=network, found=len(hosts))
    return hosts


def ndp_table() -> dict[str, str]:
    """Return a mapping of MAC address → globally-routable IPv6 address from the kernel NDP cache.

    Reads ``ip -6 neigh`` output.  Link-local addresses (``fe80::/10``) are
    excluded using the ``ipaddress`` module because they are not globally
    routable and are therefore not useful for guardian policy enforcement.

    Returns an empty dict when the command is unavailable or produces no output
    (e.g. inside a container without IPv6 or without the ``iproute2`` package).
    """
    result: dict[str, str] = {}
    try:
        out = subprocess.run(
            ["ip", "-6", "neigh"], capture_output=True, text=True, check=False
        )
        for line in out.stdout.splitlines():
            # Line format: <ipv6-addr> dev <iface> lladdr <mac> [router] <state>
            parts = line.split()
            if len(parts) >= 5 and parts[3] == "lladdr":
                ipv6_str = parts[0]
                mac = parts[4].upper()
                try:
                    addr = ipaddress.ip_address(ipv6_str)
                except ValueError:
                    continue
                # Exclude link-local (fe80::/10) — not globally routable
                if addr.is_link_local:
                    continue
                result[mac] = ipv6_str
    except Exception as exc:
        log.debug("ndp_table_error", error=str(exc))
    return result


def nmap_ping_sweep(network: str) -> list[dict]:
    """Discover live hosts in *network* using nmap's ping scan (``-sn``).

    Used as a fallback when ARP sweep returns no results (e.g. macOS Docker
    Desktop bridge networking where raw Ethernet frames cannot reach LAN
    devices).  Unlike ARP sweep, nmap uses ICMP/TCP/UDP probes that work
    across the container's default gateway.

    .. note::
        Requires the container to run with ``NET_RAW`` capability (or as
        root) so that nmap can send ICMP echo requests and raw TCP probes.
        On Linux the ``docker-compose.linux.yml`` overlay sets
        ``network_mode: host`` which provides this capability automatically.
        On macOS Docker Desktop the service runs without host networking;
        nmap falls back to TCP-based probes (``-PS/-PA``) which work without
        raw-socket access.

    Returns a list of dicts with ``ip`` and, when nmap was able to determine
    the MAC address via ARP (same broadcast domain), ``mac``.
    """
    log.info("nmap_ping_sweep_start", network=network)
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network, arguments="-sn -T4 --host-timeout 5s")
    except Exception as exc:
        log.warning("nmap_ping_sweep_error", network=network, error=str(exc))
        return []

    hosts = []
    for ip in nm.all_hosts():
        if nm[ip].state() != "up":
            continue
        host_data: dict[str, str] = {"ip": ip}
        mac = nm[ip].get("addresses", {}).get("mac", "").upper()
        if mac:
            host_data["mac"] = mac
        hosts.append(host_data)

    log.info("nmap_ping_sweep_done", network=network, found=len(hosts))
    return hosts


def _synthetic_mac_for_ip(ip: str) -> str:
    """Return a deterministic locally-administered MAC derived from *ip*.

    Uses the ``02:xx:…`` locally-administered unicast prefix so the address
    can never collide with a real OUI.  The remaining five octets are derived
    from a stable hash of the IP string so each address is unique and
    reproducible across scan cycles.

    This is used as a last-resort device identifier when a host is reachable
    but its real MAC cannot be obtained (e.g. macOS Docker Desktop bridge
    networking where raw ARP is unavailable).
    """
    h = hashlib.sha256(ip.encode()).hexdigest()
    return f"02:{h[0:2]}:{h[2:4]}:{h[4:6]}:{h[6:8]}:{h[8:10]}".upper()


def arp_resolve(ip: str) -> str | None:
    """Send a single ARP request to *ip* and return its MAC address, or None."""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(pkt, timeout=2, verbose=False)
        if answered:
            return answered[0][1].hwsrc.upper()
    except Exception as exc:
        log.debug("arp_resolve_error", ip=ip, error=str(exc))
    return None


# ─── Pi-hole API integration ─────────────────────────────────────────────────

def _get_pihole_sid(password: str) -> str | None:
    """Authenticate with the Pi-hole v6 API and return a session ID.

    POSTs the password to ``/api/auth`` and returns the ``sid`` from the
    response.  Returns ``None`` on failure.
    """
    url = f"{PIHOLE_URL}/api/auth"
    try:
        resp = requests.post(url, json={"password": password}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data.get("session", {}).get("sid") or None
    except Exception as exc:
        log.warning("pihole_auth_failed", error=str(exc))
        return None


def _delete_pihole_sid(sid: str) -> None:
    """Log out of the Pi-hole v6 API by deleting the session."""
    url = f"{PIHOLE_URL}/api/auth"
    try:
        requests.delete(url, params={"sid": sid}, timeout=10)
    except Exception:
        pass


def query_pihole_clients() -> list[dict]:
    """Query the Pi-hole v6 API for known network clients.

    Returns a list of dicts with keys ``ip``, ``mac``, and optionally
    ``hostname``.  Returns an empty list when Pi-hole is not configured or
    unreachable.
    """
    if not PIHOLE_URL:
        return []

    sid = _get_pihole_sid(PIHOLE_PASSWORD)
    if not sid:
        return []

    url = f"{PIHOLE_URL}/api/network/devices"
    data: dict = {}
    try:
        resp = requests.get(url, params={"sid": sid}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.warning("pihole_query_failed", error=str(exc))
    finally:
        _delete_pihole_sid(sid)

    clients: list[dict] = []
    for entry in data.get("devices", []):
        hwaddr = (entry.get("hwaddr") or "").upper()
        # Normalise invalid/placeholder MACs to empty string so the IPs are
        # still added to the discovery pipeline and will receive proper ARP /
        # nmap enrichment later.
        #   - "00:00:00:00:00:00"  → unknown MAC (no DHCP lease)
        #   - "IP-x.x.x.x"        → Pi-hole placeholder for DNS-only devices
        if hwaddr in ("", "00:00:00:00:00:00") or hwaddr.startswith("IP-"):
            hwaddr = ""
        # Pi-hole v6: each IP entry carries its own name (hostname is per-IP)
        for ip_entry in entry.get("ips", []):
            ip_addr = ip_entry.get("ip") if isinstance(ip_entry, dict) else ip_entry
            hostname = (
                ip_entry.get("name") if isinstance(ip_entry, dict) else None
            ) or None
            if ip_addr:
                client: dict = {"ip": ip_addr, "hostname": hostname}
                if hwaddr:
                    client["mac"] = hwaddr
                clients.append(client)

    log.info("pihole_clients_fetched", count=len(clients))
    return clients


# ─── Pi-hole group / client / domain management ──────────────────────────────

def _pihole_request(method: str, path: str, sid: str, **kwargs) -> dict:
    """Make an authenticated request to the Pi-hole v6 API.

    Returns the parsed JSON response body on success, or an empty dict on
    any error (network failure, non-2xx status, etc.).  All errors are logged
    at WARNING level so callers can react without crashing.
    """
    url = f"{PIHOLE_URL}/api{path}"
    params = dict(kwargs.pop("params", {}))
    params["sid"] = sid
    try:
        resp = requests.request(method, url, params=params, timeout=10, **kwargs)
        resp.raise_for_status()
        return resp.json() if resp.content else {}
    except Exception as exc:
        log.warning("pihole_api_error", method=method, path=path, error=str(exc))
        return {}


def _pihole_get_group_id(sid: str, name: str) -> int | None:
    """Return the Pi-hole group ID for *name*, or None if the group doesn't exist."""
    data = _pihole_request("GET", "/groups", sid)
    for group in data.get("groups", []):
        if group.get("name") == name:
            return group.get("id")
    return None


def pihole_ensure_group(sid: str, name: str, comment: str = "") -> int | None:
    """Ensure a Pi-hole group named *name* exists, creating it when absent.

    Returns the integer group ID on success, or None on failure.
    """
    gid = _pihole_get_group_id(sid, name)
    if gid is not None:
        return gid

    data = _pihole_request(
        "POST", "/groups", sid,
        json={"name": name, "comment": comment, "enabled": True},
    )
    groups = data.get("groups") or []
    gid = groups[0].get("id") if groups else None
    if gid is None:
        log.warning("pihole_group_create_failed", name=name)
    else:
        log.info("pihole_group_created", name=name, id=gid)
    return gid


def pihole_delete_group(sid: str, name: str) -> None:
    """Delete a Pi-hole group by name (best-effort; errors are logged only).

    Pi-hole v6 DELETE /api/groups/{id} requires an integer ID, so we look
    up the ID first and skip the delete if the group no longer exists.
    """
    gid = _pihole_get_group_id(sid, name)
    if gid is None:
        return
    _pihole_request("DELETE", f"/groups/{gid}", sid)
    log.info("pihole_group_deleted", name=name, id=gid)


def pihole_assign_client_to_groups(sid: str, client_ip: str, group_ids: list[int]) -> bool:
    """Assign a Pi-hole client (by IP address) to a set of groups.

    Tries to update an existing client first; creates a new client record if
    the update returns no ``clients`` key (which Pi-hole does for unknown IPs).
    Returns True when the assignment succeeded.
    """
    body = {"groups": group_ids, "comment": "IoT device managed by TheBox"}
    data = _pihole_request("PUT", f"/clients/{client_ip}", sid, json=body)
    if "clients" in data:
        return True

    # Client doesn't exist yet — create it
    create_body = {"client": client_ip, "comment": "IoT device managed by TheBox", "groups": group_ids}
    data = _pihole_request("POST", "/clients", sid, json=create_body)
    if "clients" not in data:
        log.warning("pihole_client_assign_failed", ip=client_ip, groups=group_ids)
        return False
    return True


def pihole_get_queries_for_client(
    sid: str, client_ip: str, from_ts: float, until_ts: float
) -> list[str]:
    """Return all unique DNS query domains recorded for *client_ip* in the given time window.

    Iterates through paginated results using the ``cursor`` field returned by
    the Pi-hole v6 queries API.  Stops when Pi-hole returns an empty page or
    no cursor.  A hard cap of 1 000 pages (~1 million queries) prevents an
    infinite loop should Pi-hole always return a cursor on the final page.
    """
    domains: set[str] = set()
    cursor: str | None = None

    for _page_num in range(_PIHOLE_QUERY_MAX_PAGES):
        params: dict = {
            "client": client_ip,
            "from": int(from_ts),
            "until": int(until_ts),
            "length": 1000,
        }
        if cursor:
            params["cursor"] = cursor

        data = _pihole_request("GET", "/queries", sid, params=params)
        page = data.get("queries", [])
        if not isinstance(page, list):
            log.warning("pihole_queries_unexpected_format", client=client_ip, type=type(page).__name__)
            break
        for q in page:
            if not isinstance(q, dict):
                continue
            domain = q.get("domain")
            if domain and isinstance(domain, str):
                domains.add(domain)

        cursor = data.get("cursor")
        if not cursor or not page:
            break
    else:
        log.warning("pihole_queries_page_limit_reached", client=client_ip, pages=_PIHOLE_QUERY_MAX_PAGES)

    log.info("pihole_queries_fetched", client=client_ip, count=len(domains))
    return list(domains)


def pihole_add_domain_to_allowlist(sid: str, domain: str, group_ids: list[int]) -> bool:
    """Add *domain* to the Pi-hole exact allow-list and assign it to *group_ids*.

    If the domain already exists on the allow-list the call is a no-op
    (Pi-hole returns the existing entry).  Returns True on success.
    """
    body = {"domain": domain, "comment": "IoT learned domain", "groups": group_ids, "enabled": True}
    data = _pihole_request("POST", "/domains/allow/exact", sid, json=body)
    return "domains" in data


def pihole_register_iot_allowlist(sid: str, url: str, group_ids: list[int]) -> bool:
    """Register the IoT allow-list URL as a Pi-hole ``allow`` type adlist.

    Idempotent: if the URL already exists as an adlist it is updated in-place
    (groups, enabled state) rather than creating a duplicate.  Pi-hole will
    fetch the URL on the next gravity update and apply the domains as an
    exact allow-list for the assigned groups.

    Returns True when the adlist was successfully created or updated.
    """
    # Check for an existing adlist with the same address
    data = _pihole_request("GET", "/lists", sid, params={"type": "allow"})
    existing_id: int | None = None
    for lst in data.get("lists", []):
        if lst.get("address") == url:
            existing_id = lst.get("id")
            break

    if existing_id is not None:
        result = _pihole_request(
            "PUT", f"/lists/{existing_id}", sid,
            json={"groups": group_ids, "enabled": True},
        )
        ok = "lists" in result
    else:
        result = _pihole_request(
            "POST", "/lists", sid,
            json={
                "address": url,
                "comment": "IoT allow-list managed by TheBox",
                "type": "allow",
                "enabled": True,
                "groups": group_ids,
            },
        )
        ok = "lists" in result

    if ok:
        log.info("pihole_iot_allowlist_registered", url=url, groups=group_ids)
    else:
        log.warning("pihole_iot_allowlist_register_failed", url=url)
    return ok


# ─── IoT learning session management ────────────────────────────────────────

def start_iot_learning(conn, rdb, device_id: int, ip: str) -> bool:
    """Begin the 48-hour learning period for a newly discovered IoT device.

    Steps:
    1. Create an ``iot_<ip>_learning`` group in Pi-hole.
    2. Register the device's IP as a Pi-hole client assigned to that group.
    3. Record the session in ``iot_learning_sessions``.
    4. Update the device status to ``iot_learning``.
    5. Publish an ``iot_learning_started`` event on Redis.

    When Pi-hole is not configured the function skips steps 1–2 but still
    updates the DB so the device is marked as ``iot_learning`` and the
    periodic completion check will collect Pi-hole queries once Pi-hole
    becomes available.

    Returns True when the learning session was successfully recorded.
    """
    # Sanitise IP for use in Pi-hole group name (replace dots with underscores)
    group_name = f"iot_{ip.replace('.', '_')}_learning"

    if PIHOLE_URL:
        sid = _get_pihole_sid(PIHOLE_PASSWORD)
        if sid:
            try:
                group_id = pihole_ensure_group(
                    sid, group_name, f"IoT learning session for {ip}"
                )
                if group_id is not None:
                    pihole_assign_client_to_groups(sid, ip, [group_id])
                else:
                    log.warning("iot_learning_group_unavailable", device_id=device_id, ip=ip)
            finally:
                _delete_pihole_sid(sid)
        else:
            log.warning("iot_learning_pihole_auth_failed", device_id=device_id, ip=ip)

    # Record the session and update device status regardless of Pi-hole outcome
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO iot_learning_sessions (device_id, pihole_group_name, status)
            VALUES (%s, %s, 'active')
            ON CONFLICT (device_id) DO UPDATE
                SET pihole_group_name     = EXCLUDED.pihole_group_name,
                    learning_started_at   = NOW(),
                    learning_completed_at = NULL,
                    status                = 'active'
            """,
            (device_id, group_name),
        )
        cur.execute(
            "UPDATE devices SET status = 'iot_learning' WHERE id = %s",
            (device_id,),
        )
    conn.commit()

    log.info("iot_learning_started", device_id=device_id, ip=ip, group=group_name)

    rdb.publish(
        "thebox:events",
        json.dumps({
            "type": "iot_learning_started",
            "device_id": device_id,
            "ip": ip,
            "pihole_group": group_name,
            "ts": datetime.now(timezone.utc).isoformat(),
        }),
    )
    return True


def process_completed_learnings(conn, rdb) -> int:
    """Finalise IoT learning sessions whose observation window has elapsed.

    For each active session whose ``learning_started_at`` is older than
    ``IOT_LEARNING_HOURS`` hours:

    1. Query Pi-hole for every DNS domain the device resolved during the
       learning period.
    2. Insert those FQDNs into ``iot_allowlist`` as globally-shared entries
       (``device_id = NULL``) so all IoT devices in the ``iot`` Pi-hole group
       benefit from the learned allow-list.
    3. Add each domain to Pi-hole's exact allow-list for the ``iot`` group.
    4. Reassign the Pi-hole client from the learning group to the ``iot`` group.
    5. Delete the temporary learning group from Pi-hole.
    6. Update the device status to ``iot`` and mark the session as completed.

    Returns the number of sessions finalised in this invocation.
    """
    threshold = datetime.now(timezone.utc) - timedelta(hours=IOT_LEARNING_HOURS)

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT s.id, s.device_id, s.pihole_group_name, s.learning_started_at,
                   d.ip_address
            FROM iot_learning_sessions s
            JOIN devices d ON d.id = s.device_id
            WHERE s.status = 'active'
              AND s.learning_started_at <= %s
            """,
            (threshold,),
        )
        sessions = cur.fetchall()

    if not sessions:
        return 0

    log.info("iot_learning_sessions_due", count=len(sessions))

    # Authenticate with Pi-hole once for the whole batch (if configured)
    sid: str | None = None
    iot_group_id: int | None = None
    if PIHOLE_URL:
        sid = _get_pihole_sid(PIHOLE_PASSWORD)
        if sid:
            iot_group_id = pihole_ensure_group(
                sid, PIHOLE_IOT_GROUP, "IoT devices — post-learning allow-list"
            )
        else:
            log.warning("iot_learning_complete_pihole_auth_failed")

    completed = 0
    try:
        for session in sessions:
            device_id: int = session["device_id"]
            ip: str | None = session["ip_address"]
            group_name: str = session["pihole_group_name"]
            started_at = session["learning_started_at"]

            if not ip:
                log.warning("iot_learning_no_ip", device_id=device_id, session_id=session["id"])
                continue

            log.info("iot_learning_completing", device_id=device_id, ip=ip, group=group_name)

            try:
                # ── 1. Collect DNS queries from Pi-hole ──────────────────────────
                domains: list[str] = []
                if sid:
                    from_ts = started_at.timestamp()
                    until_ts = datetime.now(timezone.utc).timestamp()
                    domains = pihole_get_queries_for_client(sid, ip, from_ts, until_ts)
                    log.info("iot_learning_domains_found", device_id=device_id, ip=ip, count=len(domains))

                # ── 2. Store FQDNs in iot_allowlist as global entries ────────────
                if domains:
                    # Clamp domain names to the VARCHAR(255) column limit.
                    safe_domains = [d[:_FQDN_MAX_LEN] for d in domains if d]
                    with conn.cursor() as cur:
                        for fqdn in safe_domains:
                            cur.execute(
                                """
                                INSERT INTO iot_allowlist (device_id, fqdn)
                                VALUES (NULL, %s)
                                ON CONFLICT (fqdn) WHERE device_id IS NULL DO NOTHING
                                """,
                                (fqdn,),
                            )
                    conn.commit()

                    # ── 3. Register the allow-list URL with Pi-hole and add domains ──
                    if sid and iot_group_id is not None:
                        # Register the dashboard URL as a Pi-hole adlist (idempotent).
                        # Pi-hole will fetch it on the next gravity update so it serves
                        # as the durable, URL-based source of truth for the allow-list.
                        if DASHBOARD_URL:
                            allowlist_url = f"{DASHBOARD_URL}/iot-allowlist.txt"
                            pihole_register_iot_allowlist(sid, allowlist_url, [iot_group_id])

                        # Also insert domains individually for immediate effect
                        # (adlist requires a gravity update before it takes effect).
                        for fqdn in safe_domains:
                            pihole_add_domain_to_allowlist(sid, fqdn, [iot_group_id])

                # ── 4. Move Pi-hole client to the iot group ──────────────────────
                if sid and iot_group_id is not None:
                    pihole_assign_client_to_groups(sid, ip, [iot_group_id])

                # ── 5. Delete the temporary learning group ───────────────────────
                if sid:
                    pihole_delete_group(sid, group_name)

                # ── 6. Update device status and mark session complete ────────────
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE devices SET status = 'iot' WHERE id = %s",
                        (device_id,),
                    )
                    cur.execute(
                        """
                        UPDATE iot_learning_sessions
                        SET status = 'completed', learning_completed_at = NOW()
                        WHERE id = %s
                        """,
                        (session["id"],),
                    )
                conn.commit()

                log.info(
                    "iot_learning_completed",
                    device_id=device_id,
                    ip=ip,
                    domains_learned=len(domains),
                )

                rdb.publish(
                    "thebox:events",
                    json.dumps({
                        "type": "iot_learning_completed",
                        "device_id": device_id,
                        "ip": ip,
                        "domains_learned": len(domains),
                        "ts": datetime.now(timezone.utc).isoformat(),
                    }),
                )

                completed += 1

            except Exception as exc:
                log.error(
                    "iot_learning_complete_error",
                    device_id=device_id,
                    ip=ip,
                    error=str(exc),
                )
                # Roll back any partial DB writes so subsequent sessions can
                # still use the connection without hitting an aborted-transaction
                # error.
                try:
                    conn.rollback()
                except Exception:
                    pass

    finally:
        if sid:
            _delete_pihole_sid(sid)

    return completed


# ─── DNS packet sniffer ──────────────────────────────────────────────────────

# Background thread posts newly-seen source IPs into this queue so that the
# main scan loop can enrich and upsert them without racing with the sniffer.
# Queue is thread-safe: the sniffer thread calls put() and the main thread
# calls get_nowait() in process_dns_sniff_queue().  maxsize caps memory use
# in high-traffic environments; excess items are dropped silently.
_dns_sniff_queue: queue.Queue = queue.Queue(maxsize=10_000)

# Hostname hints extracted from mDNS A/AAAA responses (port 5353).
# Each entry is a dict with keys: ip, hostname, device_type (optional).
_mdns_hostname_queue: queue.Queue = queue.Queue(maxsize=10_000)


def _dns_packet_handler(pkt) -> None:
    """Scapy packet callback — enqueue source IPs of DNS queries and extract
    hostname hints from mDNS A/AAAA responses (inspired by netsleuth).

    For regular DNS (port 53): enqueues the source IP of every outbound query
    so that the device can be discovered and enriched in the next scan cycle.

    For mDNS (port 5353): inspects DNS response records to extract:
    - Hostnames from A (type 1) and AAAA (type 28) records.
    - Printer device type from TXT records containing 'ipp'.
    - Apple/mobile device type from TXT records containing 'rdlink'.
    """
    try:
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return

        sport = pkt[UDP].sport
        src_ip = pkt[IP].src

        # Regular DNS queries (port 53) — enqueue for device discovery
        if sport != 5353 and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
            try:
                _dns_sniff_queue.put_nowait(src_ip)
            except queue.Full:
                pass
            return

        # mDNS responses (port 5353) — extract hostname and device-type hints
        if sport == 5353 and pkt[DNS].qr == 1 and pkt[DNS].ancount >= 1:
            try:
                ans = pkt[DNS].an
                while ans and hasattr(ans, "type"):
                    rtype = ans.type
                    rname = b""
                    if hasattr(ans, "rrname"):
                        rname = ans.rrname if isinstance(ans.rrname, bytes) else ans.rrname.encode()

                    if rtype in (1, 28):
                        # A / AAAA record: rrname is the hostname for this IP
                        hostname_full = rname.decode("utf-8", errors="replace").rstrip(".")
                        hostname_short = hostname_full.split(".")[0]
                        if hostname_short:
                            entry: dict = {"ip": src_ip, "hostname": hostname_short}
                            try:
                                _mdns_hostname_queue.put_nowait(entry)
                            except queue.Full:
                                pass

                    elif rtype == 16:
                        # TXT record: check for service-type hints
                        name_str = rname.decode("utf-8", errors="replace").lower()
                        device_type: str | None = None
                        if "._ipp._tcp" in name_str or "._ipps._tcp" in name_str:
                            device_type = "printer"
                        elif "rdlink" in name_str:
                            # Apple Private Relay / Continuity — indicates an Apple mobile device
                            device_type = "mobile"
                        if device_type:
                            hint: dict = {"ip": src_ip, "device_type": device_type}
                            try:
                                _mdns_hostname_queue.put_nowait(hint)
                            except queue.Full:
                                pass

                    # Advance to next answer record
                    if hasattr(ans, "payload") and isinstance(ans.payload, DNSRR):
                        ans = ans.payload
                    else:
                        break
            except Exception as exc:
                log.debug("mdns_packet_parse_error", ip=src_ip, error=str(exc))

    except Exception as exc:
        log.debug("dns_packet_handler_error", error=str(exc))


def start_dns_sniffer() -> threading.Thread:
    """Start a daemon thread that sniffs DNS query packets and mDNS responses.

    The thread runs ``scapy.sniff()`` capturing both regular DNS (port 53)
    and mDNS (port 5353) traffic.  Every DNS query triggers device discovery;
    mDNS A/AAAA/TXT responses provide real-time hostname and device-type hints
    without waiting for a Zeroconf service advertisement.

    The thread is a daemon so it is automatically cleaned up when the main
    process exits.

    Returns the :class:`threading.Thread` object (already started).
    """
    def _loop() -> None:
        log.info("dns_sniffer_start", iface=DNS_SNIFF_IFACE or "auto")
        try:
            sniff(
                filter="udp port 53 or udp port 5353",
                prn=_dns_packet_handler,
                store=False,
                iface=DNS_SNIFF_IFACE,
            )
        except Exception as exc:
            log.error("dns_sniffer_error", error=str(exc))

    t = threading.Thread(target=_loop, name="dns-sniffer", daemon=True)
    t.start()
    return t


def process_dns_sniff_queue(conn, rdb) -> int:
    """Drain the DNS sniffer queue and upsert any newly discovered devices.

    For each unique source IP found in the queue:

    1. Skip if the IP is already recorded in the database.
    2. Attempt to resolve the MAC address via a targeted ARP request.
    3. Skip if no MAC can be resolved (device may be off-network or
       the container lacks raw-socket access).
    4. Enrich with vendor/hostname/nmap data and upsert.

    Returns the number of new devices added.
    """
    # Drain the queue into a local set to deduplicate
    pending: set[str] = set()
    while True:
        try:
            pending.add(_dns_sniff_queue.get_nowait())
        except queue.Empty:
            break

    if not pending:
        return 0

    log.info("dns_sniff_queue_drain", candidates=len(pending))
    new_count = 0

    # Only query the DB for the IPs we actually need to check.
    with conn.cursor() as cur:
        cur.execute(
            "SELECT ip_address FROM devices WHERE ip_address = ANY(%s)",
            (list(pending),),
        )
        known_ips: set[str] = {row["ip_address"] for row in cur.fetchall() if row["ip_address"]}

    for ip in pending:
        if ip in known_ips:
            continue

        mac = arp_resolve(ip)
        if not mac:
            log.debug("dns_sniff_no_mac", ip=ip)
            continue

        host: dict = {"ip": ip, "mac": mac}
        host["hostname"] = resolve_hostname(ip)
        host["vendor"] = vendor_lookup(mac)
        scan_data = nmap_scan(ip)
        host.update(scan_data)
        extra_info: dict = enrich_from_banners(ip, host.get("open_ports", []))
        if extra_info.get("tls_cn") and not host.get("hostname"):
            host["hostname"] = extra_info["tls_cn"]
        host["extra_info"] = extra_info
        host["device_type"] = guess_device_type(
            host.get("vendor"), host.get("open_ports", []), host.get("os_guess"), extra_info,
            host.get("hostname"),
        )

        is_new = upsert_device(conn, rdb, host)
        if is_new:
            new_count += 1
            log.info("dns_sniff_new_device", ip=ip, mac=mac, vendor=host.get("vendor"))

    return new_count


def process_mdns_sniff_queue(conn) -> int:
    """Drain the mDNS hostname queue and update device records in the DB.

    Processes hostname and device-type hints extracted from mDNS A/AAAA/TXT
    responses by the DNS sniffer thread.  For each hint:

    - Updates the ``hostname`` column when the device exists but currently has
      no hostname (NULL or empty string).
    - Updates the ``device_type`` column when the current value is ``unknown``
      and the mDNS hint provides a more specific classification (e.g. printer,
      mobile).

    Returns the number of device rows touched.
    """
    # Collect all hints; keyed by IP so later entries override earlier ones
    # per-IP (last hostname/type hint wins within a single drain).
    hints: dict[str, dict] = {}
    while True:
        try:
            entry = _mdns_hostname_queue.get_nowait()
        except queue.Empty:
            break
        ip = entry.get("ip")
        if not ip:
            continue
        if ip not in hints:
            hints[ip] = {}
        if entry.get("hostname"):
            hints[ip]["hostname"] = entry["hostname"]
        if entry.get("device_type"):
            hints[ip]["device_type"] = entry["device_type"]

    if not hints:
        return 0

    log.info("mdns_sniff_queue_drain", candidates=len(hints))
    updated = 0

    for ip, hint in hints.items():
        hostname = hint.get("hostname")
        device_type = hint.get("device_type")
        if not hostname and not device_type:
            continue

        with conn.cursor() as cur:
            if hostname and device_type:
                cur.execute(
                    """
                    UPDATE devices
                    SET hostname = COALESCE(NULLIF(hostname, ''), %s),
                        device_type = CASE WHEN device_type = 'unknown' THEN %s ELSE device_type END,
                        last_seen = NOW()
                    WHERE ip_address = %s
                      AND (hostname IS NULL OR hostname = '' OR device_type = 'unknown')
                    """,
                    (hostname, device_type, ip),
                )
            elif hostname:
                cur.execute(
                    """
                    UPDATE devices
                    SET hostname = COALESCE(NULLIF(hostname, ''), %s),
                        last_seen = NOW()
                    WHERE ip_address = %s
                      AND (hostname IS NULL OR hostname = '')
                    """,
                    (hostname, ip),
                )
            else:
                cur.execute(
                    """
                    UPDATE devices
                    SET device_type = %s,
                        last_seen = NOW()
                    WHERE ip_address = %s
                      AND device_type = 'unknown'
                    """,
                    (device_type, ip),
                )
        if cur.rowcount > 0:
            updated += 1
            log.info("mdns_sniff_hint_applied", ip=ip, hostname=hostname, device_type=device_type)
        conn.commit()

    return updated


# ─── DHCP packet sniffer ─────────────────────────────────────────────────────

# Background thread pushes (mac, hostname, ip) hints here so that the
# main scan loop can update device records without blocking the sniffer.
_dhcp_hostname_queue: queue.Queue = queue.Queue(maxsize=10_000)


def _dhcp_packet_handler(pkt) -> None:
    """Scapy packet callback — extract device hostnames from DHCP packets.

    Watches for DHCPDISCOVER (type 1) and DHCPREQUEST (type 3) packets,
    which are sent by clients and carry the client hostname in DHCP option 12.
    This mirrors the DHCP hostname extraction in netsleuth, providing
    authoritative, near-real-time hostnames without relying on reverse DNS.

    Enqueues dicts with ``mac``, ``hostname``, and optionally ``ip`` for
    processing by :func:`process_dhcp_sniff_queue`.
    """
    try:
        if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
            return
        if not pkt.haslayer(Ether):
            return

        msg_type: int | None = None
        hostname: str | None = None
        req_ip: str | None = None

        for option in pkt[DHCP].options:
            if not isinstance(option, tuple):
                continue
            code, value = option[0], option[1]
            if code == "message-type":
                msg_type = value
            elif code == "hostname":
                hostname = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
            elif code == "requested_addr":
                req_ip = value

        # Only process DHCPDISCOVER (1) and DHCPREQUEST (3) which are sent by
        # clients and typically include the hostname option.
        if msg_type not in (1, 3):
            return
        if not hostname:
            return

        src_mac = pkt[Ether].src.upper()
        if src_mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            return

        # Determine the client IP: DHCPREQUEST usually puts it in ciaddr;
        # DHCPDISCOVER has 0.0.0.0 there so we fall back to the requested-addr
        # option, then the IP layer source address.
        src_ip: str | None = None
        if pkt[BOOTP].ciaddr and pkt[BOOTP].ciaddr not in ("0.0.0.0", ""):
            src_ip = pkt[BOOTP].ciaddr
        elif req_ip:
            src_ip = req_ip
        elif pkt.haslayer(IP) and pkt[IP].src not in ("0.0.0.0", ""):
            src_ip = pkt[IP].src

        entry: dict = {"mac": src_mac, "hostname": hostname}
        if src_ip:
            entry["ip"] = src_ip
        try:
            _dhcp_hostname_queue.put_nowait(entry)
        except queue.Full:
            pass
    except Exception as exc:
        log.debug("dhcp_packet_handler_error", error=str(exc))


def start_dhcp_sniffer() -> threading.Thread:
    """Start a daemon thread that sniffs DHCP packets for hostname extraction.

    Captures DHCP client messages (DHCPDISCOVER and DHCPREQUEST) on ports 67
    and 68.  Hostname hints from DHCP option 12 are enqueued for DB update via
    :func:`process_dhcp_sniff_queue`.  This provides near-real-time, vendor-
    authoritative hostnames that are far more reliable than reverse DNS — the
    same technique used in netsleuth for host identification.

    Returns the :class:`threading.Thread` object (already started).
    """
    def _loop() -> None:
        log.info("dhcp_sniffer_start", iface=DNS_SNIFF_IFACE or "auto")
        try:
            sniff(
                filter="udp and (port 67 or port 68)",
                prn=_dhcp_packet_handler,
                store=False,
                iface=DNS_SNIFF_IFACE,
            )
        except Exception as exc:
            log.error("dhcp_sniffer_error", error=str(exc))

    t = threading.Thread(target=_loop, name="dhcp-sniffer", daemon=True)
    t.start()
    return t


def process_dhcp_sniff_queue(conn) -> int:
    """Drain the DHCP sniffer queue and update device hostnames in the DB.

    For each enqueued (mac, hostname, ip) entry:

    - If the device is already known (matched by MAC): update its hostname when
      currently absent and back-fill a missing IP address.
    - If the device is not yet known: the main scan loop will discover it in
      the next ARP sweep; the hint is applied after that via MAC match.

    Returns the number of device rows updated.
    """
    pending: list[dict] = []
    while True:
        try:
            pending.append(_dhcp_hostname_queue.get_nowait())
        except queue.Empty:
            break

    if not pending:
        return 0

    log.info("dhcp_sniff_queue_drain", candidates=len(pending))
    updated = 0

    for entry in pending:
        mac = entry.get("mac")
        hostname = entry.get("hostname")
        ip = entry.get("ip")
        if not mac or not hostname:
            continue

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE devices
                SET hostname    = COALESCE(NULLIF(hostname, ''), %s),
                    ip_address  = COALESCE(ip_address, %s),
                    last_seen   = NOW()
                WHERE mac_address = %s
                  AND (hostname IS NULL OR hostname = '')
                """,
                (hostname, ip, mac),
            )
            if cur.rowcount > 0:
                updated += 1
                log.info("dhcp_hostname_updated", mac=mac, hostname=hostname, ip=ip)
        conn.commit()

    return updated


# ─── ARP packet sniffer ───────────────────────────────────────────────────────

# Background thread pushes newly-seen IP/MAC pairs here for real-time
# device detection between periodic scan cycles.
_arp_sniff_queue: queue.Queue = queue.Queue(maxsize=10_000)


def _arp_packet_handler(pkt) -> None:
    """Scapy packet callback — enqueue hosts seen in ARP traffic.

    Inspired by netsleuth's ARP-based host discovery, this captures both
    ARP requests (op=1, who-has) and ARP replies (op=2, is-at) to detect
    devices the moment they join or communicate on the network — without
    waiting for the next periodic scan cycle.

    Packets where the Ethernet source MAC does not match the ARP sender MAC
    (a sign of ARP spoofing) are skipped so that forged MACs are never stored.
    """
    try:
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        src_mac = arp.hwsrc
        src_ip = arp.psrc

        if not src_mac or src_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return
        if not src_ip or src_ip == "0.0.0.0":
            return

        # Discard packets where Ethernet src ≠ ARP hwsrc — indicates spoofing
        if pkt.haslayer(Ether) and pkt[Ether].src.lower() != src_mac.lower():
            log.debug("arp_spoof_skipped", ip=src_ip, ether_src=pkt[Ether].src, arp_hwsrc=src_mac)
            return

        entry: dict = {"ip": src_ip, "mac": src_mac.upper()}
        try:
            _arp_sniff_queue.put_nowait(entry)
        except queue.Full:
            pass
    except Exception as exc:
        log.debug("arp_packet_handler_error", error=str(exc))


def start_arp_sniffer() -> threading.Thread:
    """Start a daemon thread that sniffs ARP traffic for real-time host detection.

    Captures all ARP packets on the network interface and enqueues each
    sender's IP/MAC pair.  This detects newly-powered devices the moment they
    broadcast an ARP request — a technique taken directly from netsleuth —
    rather than waiting for the next periodic ARP sweep.

    Returns the :class:`threading.Thread` object (already started).
    """
    def _loop() -> None:
        log.info("arp_sniffer_start", iface=DNS_SNIFF_IFACE or "auto")
        try:
            sniff(
                filter="arp",
                prn=_arp_packet_handler,
                store=False,
                iface=DNS_SNIFF_IFACE,
            )
        except Exception as exc:
            log.error("arp_sniffer_error", error=str(exc))

    t = threading.Thread(target=_loop, name="arp-sniffer", daemon=True)
    t.start()
    return t


def process_arp_sniff_queue(conn, rdb) -> int:
    """Drain the ARP sniffer queue and upsert any newly discovered devices.

    For each unique MAC address seen in the queue:

    1. If the device is already in the database: update its IP and last_seen
       without running a full enrichment scan (keeps the hot path cheap).
    2. If the device is new: run full enrichment (hostname, vendor, nmap,
       banner grab) and upsert — identical to the main scan loop behaviour.

    Returns the number of new devices added.
    """
    # Deduplicate by MAC; keep the most recently seen IP for each.
    pending: dict[str, dict] = {}
    while True:
        try:
            entry = _arp_sniff_queue.get_nowait()
            pending[entry["mac"]] = entry
        except queue.Empty:
            break

    if not pending:
        return 0

    log.info("arp_sniff_queue_drain", candidates=len(pending))
    new_count = 0

    macs = list(pending.keys())
    with conn.cursor() as cur:
        cur.execute(
            "SELECT mac_address FROM devices WHERE mac_address = ANY(%s)",
            (macs,),
        )
        known_macs: set[str] = {row["mac_address"] for row in cur.fetchall()}

    for mac, host in pending.items():
        if mac in known_macs:
            # Already known — just refresh the IP and timestamp cheaply.
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE devices SET ip_address = %s, last_seen = NOW() WHERE mac_address = %s",
                    (host["ip"], mac),
                )
            conn.commit()
            continue

        # New device — run full enrichment then upsert
        host["hostname"] = resolve_hostname(host["ip"])
        host["vendor"] = vendor_lookup(mac)
        scan_data = nmap_scan(host["ip"])
        host.update(scan_data)
        extra_info: dict = enrich_from_banners(host["ip"], host.get("open_ports", []))
        if extra_info.get("tls_cn") and not host.get("hostname"):
            host["hostname"] = extra_info["tls_cn"]
        host["extra_info"] = extra_info
        host["device_type"] = guess_device_type(
            host.get("vendor"), host.get("open_ports", []), host.get("os_guess"), extra_info,
            host.get("hostname"),
        )

        is_new = upsert_device(conn, rdb, host)
        if is_new:
            new_count += 1
            log.info("arp_sniff_new_device", ip=host["ip"], mac=mac, vendor=host.get("vendor"))

    return new_count


# ─── SSDP / UPnP discovery ───────────────────────────────────────────────────
_SSDP_MULTICAST_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_SSDP_MX = 3


def _xml_text(element, tag: str, ns: dict) -> str | None:
    """Return the text of a child XML element, or None if absent."""
    child = element.find(tag, ns)
    return child.text.strip() if child is not None and child.text else None


_SSDP_LOCATION_RE = re.compile(r"^https?://", re.IGNORECASE)


def _validate_ssdp_location(location: str, responding_ip: str) -> bool:
    """Return True only when *location* is safe to fetch.

    Accepts only ``http://`` and ``https://`` URLs whose host component is an
    IP address that matches the device's responding IP.  This prevents an
    attacker on the LAN from injecting SSDP responses that point to cloud
    metadata endpoints (e.g. ``169.254.169.254``) or internal services.
    """
    if not _SSDP_LOCATION_RE.match(location):
        return False
    try:
        from urllib.parse import urlparse  # stdlib — no extra dep
        parsed = urlparse(location)
        host = parsed.hostname or ""
        # Reject any non-IP host (hostnames could resolve to unexpected addresses)
        # and reject mismatches with the responding IP.
        socket.inet_aton(host)  # raises OSError if not a valid IPv4 address
        return host == responding_ip
    except OSError:
        return False
    except Exception:
        return False


def ssdp_discover(timeout: int = 5) -> dict[str, dict]:
    """Discover UPnP/SSDP devices on the LAN via multicast M-SEARCH.

    Sends an ``ssdp:all`` M-SEARCH request to the UPnP multicast group
    (239.255.255.250:1900) and waits *timeout* seconds for responses.
    For each unique responding IP the LOCATION header URL is fetched and
    the UPnP device description XML is parsed to extract manufacturer,
    model name, friendly name, and device type.

    Returns a dict mapping IP address → enrichment dict.  Runs silently
    on error so that a missing or blocked multicast path doesn't abort the
    scan cycle.
    """
    if not SSDP_ENABLED:
        return {}

    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {_SSDP_MULTICAST_ADDR}:{_SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {_SSDP_MX}\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    responses: dict[str, dict] = {}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(msg, (_SSDP_MULTICAST_ADDR, _SSDP_PORT))
    except Exception as exc:
        log.warning("ssdp_send_error", error=str(exc))
        return {}

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(65507)
            ip = addr[0]
            if ip in responses:
                continue
            response_text = data.decode("utf-8", errors="replace")
            location: str | None = None
            for line in response_text.split("\r\n"):
                if line.upper().startswith("LOCATION:"):
                    location = line.split(":", 1)[1].strip()
                    break
            entry: dict = {}
            if location and _validate_ssdp_location(location, ip):
                entry["upnp_location"] = location
                try:
                    with urlopen(location, timeout=3) as resp:  # noqa: S310
                        xml_data = resp.read()
                    root = ET.fromstring(xml_data)
                    ns = {"d": "urn:schemas-upnp-org:device-1-0"}
                    device_el = root.find(".//d:device", ns)
                    if device_el is not None:
                        for attr, tag in (
                            ("upnp_friendly_name", "d:friendlyName"),
                            ("upnp_manufacturer", "d:manufacturer"),
                            ("upnp_manufacturer_url", "d:manufacturerURL"),
                            ("upnp_model_name", "d:modelName"),
                            ("upnp_model_number", "d:modelNumber"),
                            ("upnp_model_description", "d:modelDescription"),
                            ("upnp_serial_number", "d:serialNumber"),
                            ("upnp_device_type", "d:deviceType"),
                            ("upnp_udn", "d:UDN"),
                        ):
                            val = _xml_text(device_el, tag, ns)
                            if val:
                                entry[attr] = val
                except ET.ParseError as exc:
                    log.debug("ssdp_xml_parse_error", ip=ip, error=str(exc))
                except Exception as exc:
                    log.debug("ssdp_description_fetch_error", ip=ip, location=location, error=str(exc))
            if entry:
                responses[ip] = entry
        except TimeoutError:
            break
        except OSError:
            break
        except Exception as exc:
            log.debug("ssdp_recv_error", error=str(exc))
            break

    sock.close()
    log.info("ssdp_discover_done", found=len(responses))
    return responses


# ─── mDNS / Zeroconf discovery ───────────────────────────────────────────────

# Common DNS-SD service types that reveal useful device information.
_MDNS_SERVICE_TYPES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_sftp-ssh._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_nfs._tcp.local.",
    "_ftp._tcp.local.",
    "_telnet._tcp.local.",
    "_workstation._tcp.local.",
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_companion-link._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_matter._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_scanner._tcp.local.",
    "_device-info._tcp.local.",
    "_daap._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_spotify-connect._tcp.local.",
]

# Background thread pushes raw service entries here; main thread drains it.
_mdns_queue: queue.Queue = queue.Queue(maxsize=10_000)


class _MdnsListener:
    """Minimal zeroconf ServiceBrowser listener that enqueues service info."""

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        try:
            info = zc.get_service_info(type_, name, timeout=3000)
            if not info:
                return
            for addr in info.parsed_addresses():
                entry = {
                    "ip": addr,
                    "service_type": type_.rstrip("."),
                    "service_name": name,
                    "hostname": info.server.rstrip(".") if info.server else None,
                    "port": info.port,
                    "properties": {
                        (k.decode() if isinstance(k, bytes) else k): (
                            v.decode("utf-8", errors="replace") if isinstance(v, bytes) else (v or "")
                        )
                        for k, v in (info.properties or {}).items()
                    },
                }
                try:
                    _mdns_queue.put_nowait(entry)
                except queue.Full:
                    pass
        except Exception as exc:
            log.debug("mdns_service_info_error", name=name, error=str(exc))

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.add_service(zc, type_, name)


def start_mdns_discovery() -> threading.Thread:
    """Start a background daemon thread that browses mDNS/DNS-SD services.

    Creates a :class:`zeroconf.Zeroconf` instance and registers a
    :class:`ServiceBrowser` for each service type in ``_MDNS_SERVICE_TYPES``.
    The browser runs indefinitely; discovered service entries are pushed into
    ``_mdns_queue`` and consumed by :func:`process_mdns_queue` during each
    scan cycle.

    Returns the :class:`threading.Thread` object (already started).
    """
    def _loop() -> None:
        log.info("mdns_discovery_start", service_types=len(_MDNS_SERVICE_TYPES))
        try:
            zc = Zeroconf()
            listener = _MdnsListener()
            # Keep a reference to the browsers so they are not garbage-collected;
            # each ServiceBrowser runs background threads that stay alive as long
            # as the object is referenced.
            _active_browsers = [ServiceBrowser(zc, stype, listener) for stype in _MDNS_SERVICE_TYPES]
            while True:
                time.sleep(60)
        except Exception as exc:
            log.error("mdns_discovery_error", error=str(exc))

    t = threading.Thread(target=_loop, name="mdns-discovery", daemon=True)
    t.start()
    return t


def process_mdns_queue() -> dict[str, dict]:
    """Drain the mDNS queue and return per-IP enrichment data.

    Returns a dict mapping IP address → enrichment dict with keys:

    - ``mdns_services``: list of service entry dicts
    - ``mdns_hostname``: the ``.local`` hostname from the first entry that
      provides one
    """
    enrichment: dict[str, dict] = {}
    while True:
        try:
            entry = _mdns_queue.get_nowait()
        except queue.Empty:
            break
        ip = entry["ip"]
        if ip not in enrichment:
            enrichment[ip] = {"mdns_services": [], "mdns_hostname": None}
        enrichment[ip]["mdns_services"].append(
            {
                "service_type": entry["service_type"],
                "service_name": entry["service_name"],
                "port": entry.get("port"),
                "properties": entry.get("properties", {}),
            }
        )
        if entry.get("hostname") and not enrichment[ip]["mdns_hostname"]:
            enrichment[ip]["mdns_hostname"] = entry["hostname"]
    return enrichment


# ─── NetBIOS / NBNS discovery ────────────────────────────────────────────────

def netbios_scan(network: str) -> dict[str, dict]:
    """Run nmap's ``nbstat`` NSE script to collect NetBIOS names for a subnet.

    Scans UDP port 137 across *network* and parses the ``nbstat`` script
    output to extract each host's NetBIOS computer name and workgroup.
    Returns a dict mapping IP address → ``{"netbios_name": ..., "workgroup": ...}``.
    Falls back silently to an empty dict if nmap is unavailable or the scan
    fails (e.g. the container lacks raw-socket access).
    """
    if not NETBIOS_ENABLED:
        return {}

    log.info("netbios_scan_start", network=network)
    nm = nmap.PortScanner()
    try:
        nm.scan(
            hosts=network,
            arguments="-p 137 -sU --script nbstat.nse -T4 --host-timeout 5s",
        )
    except Exception as exc:
        log.warning("netbios_scan_error", error=str(exc))
        return {}

    results: dict[str, dict] = {}
    for ip in nm.all_hosts():
        host = nm[ip]
        for script in host.get("hostscript", []):
            if script.get("id") != "nbstat":
                continue
            output = script.get("output", "")
            name_match = re.search(r"NetBIOS name:\s*([^\s,]+)", output)
            wg_match = re.search(r"(?:workgroup|domain):\s*([^\s,<]+)", output, re.IGNORECASE)
            entry: dict = {}
            if name_match:
                entry["netbios_name"] = name_match.group(1)
            if wg_match:
                entry["workgroup"] = wg_match.group(1)
            if entry:
                results[ip] = entry

    log.info("netbios_scan_done", network=network, found=len(results))
    return results


# ─── HTTP / HTTPS banner grabbing ────────────────────────────────────────────

def http_banner(ip: str, port: int = 80, timeout: float = 3.0) -> str | None:
    """Return the ``Server`` header value from an HTTP service, or ``None``.

    Sends a minimal ``HEAD /`` request over a plain TCP socket so that the
    probe works against any HTTP/1.x server regardless of hostname.  The
    server banner (e.g. ``"Apache/2.4.54 (Debian)"``) is extracted from the
    ``Server:`` response header.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            response = b""
            while True:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
        for line in response.decode("utf-8", errors="replace").split("\r\n"):
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def tls_cert_info(ip: str, port: int = 443, timeout: float = 3.0) -> dict:
    """Extract subject and SAN info from the TLS certificate at *ip*:*port*.

    Establishes a TLS connection with hostname verification and certificate
    chain validation **disabled** (``ssl.CERT_NONE``).  This is intentional:
    the vast majority of home-network devices (NAS boxes, IP cameras, routers,
    smart-home hubs) use self-signed certificates that would cause a verified
    connection to fail.

    **Security note**: Because the certificate is not verified, the data
    returned reflects what the device *claims* rather than what a trusted CA
    has vouched for.  The extracted fields are stored as discovery metadata
    only and must not be used for authentication or access-control decisions.

    Returns a dict that may contain:

    - ``tls_cn``: certificate subject Common Name
    - ``tls_org``: certificate subject Organisation
    - ``tls_issuer_cn``: issuer Common Name
    - ``tls_sans``: list of DNS Subject Alternative Names
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Explicitly require TLS 1.2 or above even though certificate verification
    # is disabled.  This prevents negotiation of deprecated TLSv1/TLSv1.1
    # ciphers that would be flagged as insecure.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                cert = tls.getpeercert()
                if not cert:
                    return {}
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                result: dict = {}
                if subject.get("commonName"):
                    result["tls_cn"] = subject["commonName"]
                if subject.get("organizationName"):
                    result["tls_org"] = subject["organizationName"]
                if issuer.get("commonName"):
                    result["tls_issuer_cn"] = issuer["commonName"]
                if sans:
                    result["tls_sans"] = sans
                return result
    except Exception:
        pass
    return {}


def enrich_from_banners(ip: str, open_ports: list[dict]) -> dict:
    """Grab HTTP server banners and TLS certificate info for *ip*.

    Iterates over *open_ports* and:
    - Calls :func:`http_banner` for any port with service ``http`` or common
      HTTP port numbers (80, 8080, 8443).
    - Calls :func:`tls_cert_info` for any port with service ``https`` or
      common HTTPS port numbers (443, 8443).

    Returns a (possibly empty) dict of banner/cert enrichment fields.
    """
    if not BANNER_GRAB_ENABLED or not open_ports:
        return {}

    result: dict = {}
    http_ports = {p["port"] for p in open_ports if p.get("service") in ("http",) or p["port"] in (80, 8080)}
    https_ports = {p["port"] for p in open_ports if p.get("service") in ("https", "ssl") or p["port"] in (443, 8443)}

    for port in http_ports:
        banner = http_banner(ip, port, timeout=BANNER_GRAB_TIMEOUT)
        if banner:
            result["http_server"] = banner
            break  # first successful banner is sufficient

    for port in https_ports:
        cert = tls_cert_info(ip, port, timeout=BANNER_GRAB_TIMEOUT)
        if cert:
            result.update(cert)
            if not result.get("http_server"):
                banner = http_banner(ip, port, timeout=BANNER_GRAB_TIMEOUT)
                if banner:
                    result["http_server"] = banner
            break

    return result


# ─── nmap port/OS scan ───────────────────────────────────────────────────────

def nmap_scan(ip: str) -> dict:
    """Run a quick nmap scan on *ip* and return port list + OS guess."""
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments="-O -sV --osscan-guess -T4 --host-timeout 10s --open")
    except Exception as exc:
        log.warning("nmap_scan_error", ip=ip, error=str(exc))
        return {"open_ports": [], "os_guess": None}

    if ip not in nm.all_hosts():
        return {"open_ports": [], "os_guess": None}

    host = nm[ip]
    open_ports = []
    for proto in host.all_protocols():
        for port, info in host[proto].items():
            if info.get("state") == "open":
                open_ports.append(
                    {
                        "port": port,
                        "protocol": proto,
                        "service": info.get("name", ""),
                        "version": info.get("version", ""),
                    }
                )

    os_guess = None
    if "osmatch" in host and host["osmatch"]:
        os_guess = host["osmatch"][0].get("name")

    return {"open_ports": open_ports, "os_guess": os_guess}


# ─── Vendor + hostname helpers ───────────────────────────────────────────────

def resolve_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def vendor_lookup(mac: str) -> str | None:
    """Return the vendor/organisation name for *mac*.

    Consults two sources in priority order:

    1. The ``mac-vendor-lookup`` library (updated at startup from an online
       source; covers MA-L, MA-M, and MA-S ranges).
    2. The locally cached IEEE MA-L OUI table downloaded at startup.

    Returns *None* when neither source recognises the OUI.
    """
    try:
        result = mac_lookup.lookup(mac)
        if result:
            return result
    except VendorNotFoundError:
        pass
    except Exception as exc:
        log.debug("mac_lookup_unexpected_error", mac=mac, error=str(exc))

    # Fall back to the IEEE OUI table built at startup.
    try:
        oui = mac.replace(":", "").replace("-", "").upper()[:6]
        return _oui_table.get(oui)
    except Exception:
        return None


# ─── Device-type classification signal tables ────────────────────────────────
# All sets below are used as case-insensitive substring matches against the
# relevant field (vendor OUI string, OS fingerprint, hostname, etc.).  A broad
# prefix like "espressif" therefore matches "Espressif Systems", "ESPRESSIF
# INC.", and any future variant reported by MAC-vendor databases.

# OUI vendor strings that reliably identify IoT hardware.
_IOT_VENDOR_KEYWORDS: frozenset[str] = frozenset({
    # Microcontroller / embedded-SoC manufacturers
    "espressif", "espressif systems", "raspberry pi", "raspberrypi",
    "microchip technology", "nordic semiconductor", "silicon labs", "silabs",
    "texas instruments", "stmicroelectronics", "nxp semiconductors",
    # Smart-home protocols / hubs
    "z-wave", "zigbee", "insteon", "lutron", "leviton", "ge lighting",
    "smartthings", "samsung smarthings", "hubitat",
    # Smart lighting
    "signify", "philips lighting", "lifx", "osram", "sylvania", "sengled",
    "innr", "yeelight", "milight", "nanoleaf",
    # Smart plugs / switches / automation
    "tuya", "ewelink", "shelly", "sonoff", "tasmota", "esphome", "meross",
    "wemo", "belkin", "kasa", "tp-link", "tp link", "tplink",
    # Thermostats / HVAC
    "nest", "ecobee", "honeywell", "tado", "thermosmart",
    # IP cameras / doorbells / security
    "ring", "arlo", "blink", "eufy", "amcrest", "foscam", "reolink",
    "hikvision", "dahua", "axis communications", "hanwha", "vivotek",
    "pelco", "mobotix",
    # Smart speakers / streaming
    "sonos", "roku", "chromecast",
    # Consumer IoT / misc
    "wyze", "anker innovations", "xiaomi", "aqara", "miio",
    "d-link", "dlink", "vizio", "tcl", "hisense",
})

# OS / firmware fingerprint substrings that indicate embedded systems.
_IOT_OS_KEYWORDS: frozenset[str] = frozenset({
    "embedded linux", "uclinux", "openwrt", "lede", "dd-wrt", "buildroot",
    "vxworks", "freertos", "threadx", "nucleus rtos", "contiki", "tinyos",
    "busybox", "yocto", "openwrt", "ddwrt",
})

# TCP/UDP port numbers whose presence strongly hints at an IoT device.
_IOT_PORT_SIGNALS: frozenset[int] = frozenset({
    1883,   # MQTT
    8883,   # MQTT over TLS
    5683,   # CoAP
    5684,   # CoAP over DTLS
    554,    # RTSP (IP cameras / NVR)
    8554,   # RTSP alternate
    47808,  # BACnet/IP (building automation)
    502,    # Modbus TCP (industrial sensors)
    44818,  # EtherNet/IP (industrial)
    4840,   # OPC-UA (industrial IoT)
    9293,   # Zigbee TCP gateway (some hubs)
})

# Hostname substrings that indicate IoT devices.
_IOT_HOSTNAME_KEYWORDS: frozenset[str] = frozenset({
    "esp-", "esp8266", "esp32", "shelly", "tasmota", "sonoff",
    "tuya-", "wemos", "lifx", "miio-", "ring-", "arlo-", "wyze-",
    "cam-", "nvr-", "dvr-", "ipcam", "hue-bridge", "philips-hue",
    "ecobee", "nest-", "tado-", "octoprint", "homebridge",
    "hassio", "homeassistant", "ha-",
})

def guess_device_type(
    vendor: str | None,
    open_ports: list[dict],
    os_guess: str | None,
    extra_info: str | None = None,
    hostname: str | None = None,
) -> str:
    """Heuristic device-type classifier.

    Uses MAC vendor string, nmap OS fingerprint, open port set, mDNS service
    types, and UPnP device type to produce a best-effort device category.
    
    Returns one of: ``iot``, ``desktop``, ``server``, ``mobile``,
    ``printer``, ``network_device``, or ``unknown``.
    """
    
    vendor_l = (vendor or "").lower()
    os_l = (os_guess or "").lower()
    hostname_l = (hostname or "").lower()
    ports = {p["port"] for p in open_ports}
    extra = extra_info or {}

    # ── mDNS service-type hints (highest specificity) ─────────────────────────
    for svc in extra.get("mdns_services", []):
        stype = svc.get("service_type", "")
        if "_googlecast._tcp" in stype or "_cast._tcp" in stype:
            return "iot"
        if "_airplay._tcp" in stype or "_raop._tcp" in stype or "_companion-link._tcp" in stype:
            return "mobile"
        if "_homekit._tcp" in stype or "_hap._tcp" in stype or "_matter._tcp" in stype:
            return "iot"
        if "_printer._tcp" in stype or "_ipp._tcp" in stype or "_ipps._tcp" in stype:
            return "printer"
        if "_workstation._tcp" in stype:
            return "desktop"
        if "_smb._tcp" in stype or "_afpovertcp._tcp" in stype:
            return "desktop"

    # ── UPnP device-type hints ────────────────────────────────────────────────
    upnp_type = extra.get("upnp_device_type", "")
    upnp_mfr = extra.get("upnp_manufacturer", "").lower()
    if "InternetGatewayDevice" in upnp_type:
        return "network_device"
    if "MediaRenderer" in upnp_type or "MediaServer" in upnp_type:
        return "iot"
    if "printer" in upnp_type.lower():
        return "printer"
    if "WLANAccessPoint" in upnp_type or "WANDevice" in upnp_type:
        return "network_device"
    _iot_upnp_mfrs = {"tuya", "espressif", "shelly", "philips", "sonos", "ring", "nest", "ecobee"}
    if any(v in upnp_mfr for v in _iot_upnp_mfrs):
        return "iot"

    # ── IoT signals — checked first; most specific ────────────────────────────
    if any(kw in vendor_l for kw in _IOT_VENDOR_KEYWORDS):
        return "iot"
    if any(kw in os_l for kw in _IOT_OS_KEYWORDS):
        return "iot"
    if ports & _IOT_PORT_SIGNALS:
        return "iot"
    if any(kw in hostname_l for kw in _IOT_HOSTNAME_KEYWORDS):
        return "iot"

    # ── Desktop / workstation ─────────────────────────────────────────────────
    if "windows" in os_l:
        return "desktop"
    if "macos" in os_l or "mac os" in os_l:
        return "desktop"

    # ── Server ────────────────────────────────────────────────────────────────
    if "linux" in os_l and 22 in ports:
        return "server"

    # ── Mobile ───────────────────────────────────────────────────────────────
    if "android" in os_l or "apple" in vendor_l or "ios" in os_l:
        return "mobile"

    # ── Open-port heuristics ──────────────────────────────────────────────────
    if 9100 in ports or "print" in vendor_l:
        return "printer"

    # ── Network device ────────────────────────────────────────────────────────
    if 80 in ports or 443 in ports or 8080 in ports:
        return "network_device"

    return "unknown"


# ─── Persistence ─────────────────────────────────────────────────────────────

def upsert_device(conn, rdb, device: dict) -> bool:
    """Insert or update a device record.  Returns True if the device is new.

    For brand-new IoT devices the function also calls :func:`start_iot_learning`
    to create a Pi-hole learning group and record the 48-hour observation
    session.  The ``iot_learning_started`` event published by that function
    replaces the standard ``new_device`` event for IoT devices so that the
    guardian service does not attempt to quarantine them.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT id, status FROM devices WHERE mac_address = %s", (device["mac"],))
        row = cur.fetchone()

        if row is None:
            cur.execute(
                """
                INSERT INTO devices
                    (mac_address, ip_address, ipv6_address, hostname, vendor, device_type, os_guess,
                     open_ports, extra_info, status, first_seen, last_seen)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'new',NOW(),NOW())
                RETURNING id
                """,
                (
                    device["mac"],
                    device["ip"],
                    device.get("ipv6") or None,
                    device.get("hostname"),
                    device.get("vendor"),
                    device.get("device_type", "unknown"),
                    device.get("os_guess"),
                    json.dumps(device.get("open_ports", [])),
                    json.dumps(device.get("extra_info", {})),
                ),
            )
            device_id = cur.fetchone()["id"]
            conn.commit()
            log.info("new_device", mac=device["mac"], ip=device["ip"], vendor=device.get("vendor"))

            device_type = device.get("device_type", "unknown")
            if device_type == "iot":
                # For IoT devices start the learning period.  start_iot_learning
                # updates the device status to 'iot_learning' and publishes its
                # own event, so we do NOT publish a generic 'new_device' event.
                start_iot_learning(conn, rdb, device_id, device["ip"])
            else:
                # Publish event so guardian / dashboard react immediately
                rdb.publish(
                    "thebox:events",
                    json.dumps(
                        {
                            "type": "new_device",
                            "device_id": device_id,
                            "mac": device["mac"],
                            "ip": device["ip"],
                            "ipv6": device.get("ipv6") or "",
                            "vendor": device.get("vendor"),
                            "device_type": device_type,
                            "ts": datetime.now(timezone.utc).isoformat(),
                        }
                    ),
                )
            return True
        else:
            cur.execute(
                """
                UPDATE devices
                SET ip_address=%s, ipv6_address=COALESCE(%s, ipv6_address),
                    hostname=%s, vendor=%s, device_type=%s,
                    os_guess=%s, open_ports=%s, extra_info=%s, last_seen=NOW()
                WHERE mac_address=%s
                """,
                (
                    device["ip"],
                    device.get("ipv6") or None,
                    device.get("hostname"),
                    device.get("vendor"),
                    device.get("device_type", "unknown"),
                    device.get("os_guess"),
                    json.dumps(device.get("open_ports", [])),
                    json.dumps(device.get("extra_info", {})),
                    device["mac"],
                ),
            )
            conn.commit()
            return False


# ─── Main scan loop ──────────────────────────────────────────────────────────

def run_scan():
    log.info("scan_cycle_start", networks=NETWORK_RANGES)
    conn = get_db()
    rdb = get_redis()

    # ── Cycle-level enrichment passes (run once per scan, not per host) ───────
    # SSDP/UPnP — send M-SEARCH multicast and fetch device descriptions.
    ssdp_data: dict[str, dict] = ssdp_discover(timeout=SSDP_TIMEOUT) if SSDP_ENABLED else {}

    # mDNS — drain whatever announcements arrived since the last scan.
    mdns_data: dict[str, dict] = process_mdns_queue() if MDNS_ENABLED else {}

    for network in NETWORK_RANGES:
        # Record scan start
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scan_runs (network_range) VALUES (%s) RETURNING id",
                (network,),
            )
            scan_id = cur.fetchone()["id"]
        conn.commit()

        # ── Step 1: Layer-3 discovery — nmap ping sweep ───────────────────────
        # Works across Docker NAT, macOS bridge, and host networking alike.
        # Discovers hosts via ICMP/TCP/UDP probes without needing direct LAN
        # (layer-2) access.
        hosts = nmap_ping_sweep(network)
        host_by_ip: dict[str, dict] = {h["ip"]: h for h in hosts}
        log.info("nmap_sweep_done", network=network, found=len(hosts))

        # ── Step 2: Pi-hole client list (also layer 3) ────────────────────────
        # Pi-hole records every device that has queried DNS, and often includes
        # the MAC address from DHCP lease data.  Merge in any IPs not already
        # found by nmap and back-fill missing MACs/hostnames.
        pihole_clients = query_pihole_clients()
        if pihole_clients:
            for client in pihole_clients:
                ip = client["ip"]
                if ip not in host_by_ip:
                    hosts.append(client)
                    host_by_ip[ip] = client
                else:
                    if client.get("mac") and not host_by_ip[ip].get("mac"):
                        host_by_ip[ip]["mac"] = client["mac"]
                    if client.get("hostname") and not host_by_ip[ip].get("hostname"):
                        host_by_ip[ip]["hostname"] = client["hostname"]
            log.info("pihole_merge_done", total_after_merge=len(hosts))

        # ── Step 3: ARP sweep (layer 2) — augment with authoritative MACs ────
        # ARP provides the ground-truth MAC address for every host on the same
        # broadcast domain.  When the container runs with network_mode: host on
        # Linux (see docker-compose.linux.yml) the sweep reaches all LAN devices
        # directly.  When behind Docker NAT it may only see the gateway; we
        # still merge in whatever ARP replies we do receive to back-fill MACs
        # and pick up any hosts that nmap/Pi-hole missed.
        arp_hosts = arp_sweep(network)
        if arp_hosts:
            for arp_host in arp_hosts:
                ip = arp_host["ip"]
                if ip in host_by_ip:
                    # ARP gives us the authoritative MAC; always overwrite.
                    host_by_ip[ip]["mac"] = arp_host["mac"]
                else:
                    hosts.append(arp_host)
                    host_by_ip[ip] = arp_host
            log.info("arp_augment_done", arp_found=len(arp_hosts), total_after_augment=len(hosts))
        else:
            log.info("arp_sweep_empty", network=network, note="continuing with layer3 results only")

        # ── Step 4: SSDP/UPnP — add any IPs only found via SSDP ─────────────
        for ip, ssdp_entry in ssdp_data.items():
            if ip not in host_by_ip:
                host: dict = {"ip": ip}
                hosts.append(host)
                host_by_ip[ip] = host

        # ── Step 5: NetBIOS/NBNS subnet scan ─────────────────────────────────
        netbios_data: dict[str, dict] = netbios_scan(network) if NETBIOS_ENABLED else {}

        # ── Step 6: NDP table — back-fill IPv6 addresses ─────────────────────
        # Read the kernel Neighbour Discovery Protocol (NDP) cache to obtain
        # the globally-routable IPv6 address for each device we have already
        # resolved to a MAC address.  This is a best-effort step; devices
        # without IPv6 connectivity (or behind NAT64) will simply have no entry.
        ndp_cache: dict[str, str] = ndp_table()  # MAC (upper) → IPv6 address

        new_count = 0

        for host in hosts:
            # Ensure every host has a MAC address.  nmap ping-sweep hosts may
            # arrive without one; try ARP resolution first, then fall back to
            # a synthetic locally-administered MAC derived from the IP so that
            # every reachable device can still be tracked and stored.
            if not host.get("mac"):
                mac = arp_resolve(host["ip"])
                if mac:
                    host["mac"] = mac
                else:
                    host["mac"] = _synthetic_mac_for_ip(host["ip"])
                    log.debug(
                        "synthetic_mac_assigned",
                        ip=host["ip"],
                        mac=host["mac"],
                        reason="arp_unavailable",
                    )

            # Back-fill IPv6 address from NDP cache (keyed by upper-cased MAC).
            if not host.get("ipv6"):
                host["ipv6"] = ndp_cache.get(host["mac"].upper(), "")

            # ── Per-host enrichment ───────────────────────────────────────────
            # Build the extra_info dict from all enrichment sources.
            extra_info: dict = host.get("extra_info") or {}

            # Merge SSDP/UPnP data for this host's IP.
            if host["ip"] in ssdp_data:
                extra_info.update(ssdp_data[host["ip"]])

            # Merge mDNS data for this host's IP.
            if host["ip"] in mdns_data:
                mdns_entry = mdns_data[host["ip"]]
                extra_info["mdns_services"] = mdns_entry.get("mdns_services", [])
                # Prefer mDNS .local hostname over reverse-DNS if not already set.
                if mdns_entry.get("mdns_hostname") and not host.get("hostname"):
                    host["hostname"] = mdns_entry["mdns_hostname"]
                    extra_info["mdns_hostname"] = mdns_entry["mdns_hostname"]

            # Merge NetBIOS data for this host's IP.
            if host["ip"] in netbios_data:
                nb_entry = netbios_data[host["ip"]]
                extra_info.update(nb_entry)
                # Use NetBIOS name as hostname if nothing better is available.
                if nb_entry.get("netbios_name") and not host.get("hostname"):
                    host["hostname"] = nb_entry["netbios_name"]

            host["hostname"] = host.get("hostname") or resolve_hostname(host["ip"])
            host["vendor"] = host.get("vendor") or vendor_lookup(host["mac"])

            # nmap port/OS scan
            scan_data = nmap_scan(host["ip"])
            host.update(scan_data)

            # HTTP/HTTPS banner grabbing
            banner_data = enrich_from_banners(host["ip"], host.get("open_ports", []))
            if banner_data:
                extra_info.update(banner_data)
                # TLS cert CN can serve as a more accurate hostname.
                if banner_data.get("tls_cn") and not host.get("hostname"):
                    host["hostname"] = banner_data["tls_cn"]

            host["extra_info"] = extra_info
            host["device_type"] = guess_device_type(
                host.get("vendor"), host.get("open_ports", []), host.get("os_guess"), extra_info,
                host.get("hostname"),
            )

            is_new = upsert_device(conn, rdb, host)
            if is_new:
                new_count += 1

        # Process any devices discovered via DNS packet sniffing since the
        # last scan cycle.
        if DNS_SNIFF_ENABLED:
            new_count += process_dns_sniff_queue(conn, rdb)
            # Apply mDNS hostname/device-type hints extracted by the DNS sniffer.
            process_mdns_sniff_queue(conn)

        # Process real-time ARP-sniffed devices (netsleuth-style live detection).
        if ARP_SNIFF_ENABLED:
            new_count += process_arp_sniff_queue(conn, rdb)

        # Apply DHCP-sniffed hostnames to existing device records.
        if DHCP_SNIFF_ENABLED:
            process_dhcp_sniff_queue(conn)

        # Check for IoT learning sessions that have passed the observation window.
        process_completed_learnings(conn, rdb)

        # Update scan record
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_runs
                SET finished_at=NOW(), devices_found=%s, new_devices=%s, status='completed'
                WHERE id=%s
                """,
                (len(hosts), new_count, scan_id),
            )
        conn.commit()
        log.info("scan_cycle_done", network=network, total=len(hosts), new=new_count)

    conn.close()


# ─── Redis subscriber (dashboard-triggered events) ───────────────────────────

def _handle_iot_learning_start_requested(event: dict) -> None:
    """React to a user manually assigning a device to IoT status for the first time.

    The dashboard sets the device status to ``iot_learning`` and publishes
    this event.  Discovery handles it here by calling :func:`start_iot_learning`
    to create the Pi-hole learning group and record the session.

    The handler is intentionally conservative: if anything goes wrong the
    error is logged and the session the dashboard already wrote to the DB
    remains intact so that the learning window still runs.
    """
    device_id = event.get("device_id")
    ip = event.get("ip")

    if not device_id or not ip:
        log.warning("iot_learning_start_requested_missing_fields", event=event)
        return

    log.info("iot_learning_start_requested", device_id=device_id, ip=ip)
    conn = get_db()
    rdb = get_redis()
    try:
        start_iot_learning(conn, rdb, device_id, ip)
    except Exception as exc:
        log.error("iot_learning_start_failed", device_id=device_id, ip=ip, error=str(exc))
    finally:
        conn.close()


def _discovery_subscribe_loop() -> None:
    """Subscribe to ``thebox:events`` and dispatch dashboard-triggered events.

    Runs as a daemon thread so the process exits cleanly when the main thread
    finishes.  Only ``iot_learning_start_requested`` events are handled here;
    all other event types are ignored.
    """
    rdb = get_redis()
    pubsub = rdb.pubsub()
    pubsub.subscribe("thebox:events")
    log.info("discovery_subscribed_to_events")

    for message in pubsub.listen():
        if message["type"] != "message":
            continue
        try:
            event = json.loads(message["data"])
            if event.get("type") == "iot_learning_start_requested":
                _handle_iot_learning_start_requested(event)
        except Exception as exc:
            log.error("discovery_event_handling_error", error=str(exc))


def main():
    ensure_schema()
    _load_settings()

    log.info(
        "discovery_service_start",
        networks=NETWORK_RANGES,
        interval=SCAN_INTERVAL,
        iot_learning_hours=IOT_LEARNING_HOURS,
        pihole_iot_group=PIHOLE_IOT_GROUP,
    )

    # Start the background DNS-packet sniffer (requires NET_RAW capability).
    # Also handles mDNS (port 5353) hostname extraction when DNS_SNIFF_ENABLED.
    if DNS_SNIFF_ENABLED:
        start_dns_sniffer()
    else:
        log.info("dns_sniffer_disabled")

    # Start the DHCP packet sniffer for real-time hostname extraction.
    if DHCP_SNIFF_ENABLED:
        start_dhcp_sniffer()
    else:
        log.info("dhcp_sniffer_disabled")

    # Start the ARP packet sniffer for real-time device detection.
    if ARP_SNIFF_ENABLED:
        start_arp_sniffer()
    else:
        log.info("arp_sniffer_disabled")

    # Subscribe to Redis events so we can react to dashboard-triggered actions
    # (e.g. a user manually assigning a device to IoT status for the first time).
    threading.Thread(target=_discovery_subscribe_loop, name="discovery-redis-sub", daemon=True).start()

    # Start the background mDNS/Zeroconf service browser.
    if MDNS_ENABLED:
        start_mdns_discovery()
    else:
        log.info("mdns_discovery_disabled")

    # Run once immediately, then on schedule
    run_scan()
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)

    while True:
        schedule.run_pending()
        time.sleep(10)


if __name__ == "__main__":
    main()
