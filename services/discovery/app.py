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
  - WSD/WS-Discovery: sends a WS-Discovery Probe to 239.255.255.250:3702 to
    discover Windows PCs, network printers, and ONVIF-compliant IP cameras
    that do not respond to SSDP.
  - mDNS/Zeroconf: browses common DNS-SD service types (Bonjour/Avahi) to
    discover Apple, Chromecast, printer, HomeKit, and other smart-home devices.
    TXT record key/value pairs (md, am, model, ty, fn) are extracted to surface
    exact model names and device-type hints.
  - NetBIOS: runs nmap's nbstat NSE script across the subnet to retrieve
    NetBIOS hostnames and workgroup info for Windows/Samba hosts.
  - HTTP/HTTPS banners: grabs the Server header from open HTTP ports and
    reads TLS certificate subject/SAN fields from open HTTPS ports to derive
    hostnames, vendor, and model information.
  - DHCP fingerprinting: captures DHCP option 55 (Parameter Request List) from
    client DISCOVER/REQUEST packets and submits the fingerprint to the
    fingerbank.org API for device-name/type classification.  This is the most
    accurate passive classification source — the option-55 sequence is unique
    to the DHCP client stack compiled into a device's firmware.
  - MAC randomization detection: locally-administered (private/random) MACs
    are flagged as mobile devices when no vendor OUI match is found.
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
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from urllib.request import urlopen
import xml.etree.ElementTree as ET

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

# RF device-type classifier — optional, gracefully absent before first build.
try:
    import device_classifier as _dc
except ImportError:
    _dc = None  # type: ignore[assignment]

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

# WSD/WS-Discovery active probe (Windows PCs, printers, ONVIF cameras)
WSD_ENABLED = os.environ.get("WSD_ENABLED", "true").lower() == "true"
WSD_TIMEOUT = int(os.environ.get("WSD_TIMEOUT", "5"))

# DHCP fingerprint classification via fingerbank.org
# Enabled by default; set FINGERBANK_ENABLED=false to skip API calls.
# FINGERBANK_API_KEY is optional — unauthenticated requests work but are
# rate-limited to 100/day.  Get a free key at https://fingerbank.org/users/register
FINGERBANK_ENABLED = os.environ.get("FINGERBANK_ENABLED", "true").lower() == "true"
FINGERBANK_API_KEY = os.environ.get("FINGERBANK_API_KEY", "")

# How often (seconds) to drain the passive sniff queues and run SSDP/mDNS
# discovery between full scan cycles.  Defaults to 30 s so that newly-seen
# devices appear in the database within half a minute rather than waiting for
# the next SCAN_INTERVAL window.
SNIFF_PROCESS_INTERVAL = int(os.environ.get("SNIFF_PROCESS_INTERVAL", "30"))

# IEEE OUI vendor database — downloaded at startup and cached locally
_OUI_CSV_URL = os.environ.get(
    "OUI_CSV_URL", "https://standards-oui.ieee.org/oui/oui.csv"
)
_OUI_CSV_PATH = os.environ.get("OUI_CSV_PATH", "/tmp/oui.csv")

# ─── Logging ─────────────────────────────────────────────────────────────────
# force=True ensures the level is applied even when a dependency has already
# installed root-logger handlers before this module is first imported.
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), force=True)
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


# ─── MAC randomization helper ────────────────────────────────────────────────

def _is_locally_administered_mac(mac: str) -> bool:
    """Return True if *mac* has the locally-administered (LA) bit set.

    Modern iOS and Android devices rotate their MAC addresses using
    locally-administered (private/random) MACs.  The LA bit is the
    second-least-significant bit of the first octet.  A locally-administered
    *unicast* MAC has first-octet bit1=1, bit0=0 — e.g. 02:xx, 0A:xx, etc.

    When no OUI vendor match exists for such a MAC it is almost certainly a
    mobile device using MAC address randomization, so :func:`guess_device_type`
    uses this flag to classify it as ``mobile`` rather than ``unknown``.
    """
    try:
        first_octet = int(mac.replace(":", "").replace("-", "")[:2], 16)
        # bit1=1 (locally administered) AND bit0=0 (unicast)
        return bool(first_octet & 0x02) and not bool(first_octet & 0x01)
    except Exception:
        return False


# ─── Fingerbank DHCP-fingerprint classification ───────────────────────────────

_FINGERBANK_API_URL = "https://api.fingerbank.org/api/v2/combinations/interrogate"

# In-process cache: key = "fp|vci" → result dict (or empty dict for 404).
# Persists for the lifetime of the process; typical home-lab networks have
# only a handful of unique DHCP fingerprints so memory cost is negligible.
_fingerbank_cache: dict[str, dict] = {}
# Monotonic timestamp of the last API call — used to enforce a minimum
# interval between calls to avoid exceeding the unauthenticated rate limit.
_fingerbank_last_call: float = 0.0
_FINGERBANK_MIN_INTERVAL = 1.1  # seconds between API calls
# Lock protecting both the cache dict and the rate-limit timestamp so that
# concurrent calls from the sniff-processor and scan threads cannot race.
_fingerbank_lock = threading.Lock()

# Map fingerbank top-level parent category names to our device_type strings.
_FINGERBANK_CATEGORY_MAP: dict[str, str] = {
    "mobile":         "mobile",
    "smartphone":     "mobile",
    "tablet":         "mobile",
    "ios device":     "mobile",
    "android":        "mobile",
    "iot":            "iot",
    "smart tv":       "iot",
    "streaming":      "iot",
    "printer":        "printer",
    "network device": "network_device",
    "router":         "network_device",
    "switch":         "network_device",
    "access point":   "network_device",
    "nas":            "server",
    "workstation":    "desktop",
    "desktop":        "desktop",
    "laptop":         "desktop",
    "computer":       "desktop",
    "server":         "server",
    "virtual machine":"server",
}


def fingerbank_lookup(
    dhcp_fingerprint: str,
    vendor_class: str = "",
    hostname: str = "",
) -> dict | None:
    """Query fingerbank.org to classify a device by its DHCP option-55 fingerprint.

    The DHCP Parameter Request List (option 55) is a comma-separated list of
    DHCP option codes that a client requests from the server.  The exact
    sequence is unique to the TCP/IP stack compiled into the device's firmware
    and is one of the most reliable passive classification signals.

    Results are cached in-process by (fingerprint, vci) key so that repeated
    DHCP renewals from the same device type do not trigger additional API calls.

    Returns a dict with keys ``device_name``, ``device_type`` (one of our
    canonical types), and ``score`` (0–100) on success, or ``None`` on API
    failure or when fingerprinting is disabled.
    """
    if not FINGERBANK_ENABLED or not dhcp_fingerprint:
        return None

    cache_key = f"{dhcp_fingerprint}|{vendor_class}"

    with _fingerbank_lock:
        if cache_key in _fingerbank_cache:
            cached = _fingerbank_cache[cache_key]
            log.debug(
                "fingerbank_cache_hit",
                fingerprint=dhcp_fingerprint,
                vendor_class=vendor_class,
                result=cached or None,
            )
            return cached or None

        # Rate-limit: enforce minimum interval between calls atomically so
        # concurrent threads cannot both slip through at the same time.
        global _fingerbank_last_call
        elapsed = time.monotonic() - _fingerbank_last_call
        if elapsed < _FINGERBANK_MIN_INTERVAL:
            time.sleep(_FINGERBANK_MIN_INTERVAL - elapsed)
        # Reserve the slot before releasing the lock.
        _fingerbank_last_call = time.monotonic()

    # Make the network call outside the lock so other threads can proceed
    # with cache lookups while this request is in flight.
    params: dict[str, str] = {"dhcp_fingerprint": dhcp_fingerprint}
    if vendor_class:
        params["vendor_class_identifier"] = vendor_class
    if hostname:
        params["hostname"] = hostname
    if FINGERBANK_API_KEY:
        params["key"] = FINGERBANK_API_KEY

    log.debug(
        "fingerbank_request",
        fingerprint=dhcp_fingerprint,
        vendor_class=vendor_class,
        hostname=hostname,
        authenticated=bool(FINGERBANK_API_KEY),
    )

    try:
        resp = requests.get(_FINGERBANK_API_URL, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            device = data.get("device") or {}
            parents = device.get("parents") or []
            # Walk parents bottom-up to find a recognised category name.
            device_type = "unknown"
            for parent in reversed(parents):
                pname = (parent.get("name") or "").lower()
                if pname in _FINGERBANK_CATEGORY_MAP:
                    device_type = _FINGERBANK_CATEGORY_MAP[pname]
                    break
            result: dict = {
                "device_name": device.get("name", ""),
                "device_type": device_type,
                "score": data.get("score", 0),
            }
            with _fingerbank_lock:
                _fingerbank_cache[cache_key] = result
            log.debug(
                "fingerbank_hit",
                fingerprint=dhcp_fingerprint,
                device=result["device_name"],
                device_type=result["device_type"],
                score=result["score"],
            )
            return result
        if resp.status_code == 404:
            # Unknown fingerprint — cache empty result to avoid retrying.
            with _fingerbank_lock:
                _fingerbank_cache[cache_key] = {}
            log.debug("fingerbank_unknown_fingerprint", fingerprint=dhcp_fingerprint)
            return None
        log.debug("fingerbank_http_error", status=resp.status_code)
        return None
    except Exception as exc:
        log.debug("fingerbank_lookup_error", error=str(exc))
        return None


# ─── Schema bootstrap ────────────────────────────────────────────────────────

_MIGRATIONS_DIR = "/app/migrations"
REQUIRED_MIGRATIONS = ["0001", "0002", "0003", "0006"]


def apply_migrations(required_versions):
    """Apply all required migrations that have not yet been recorded.

    Reads SQL from ``_MIGRATIONS_DIR``/NNNN_*.sql files and applies each
    version in ascending order, skipping any already recorded in
    schema_migrations.
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version     VARCHAR(16) NOT NULL PRIMARY KEY,
                    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
        conn.commit()
        for version in sorted(required_versions):
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = %s",
                    (version,)
                )
                if cur.fetchone():
                    continue
                sql_file = None
                for name in sorted(os.listdir(_MIGRATIONS_DIR)):
                    if name.startswith(f"{version}_") and name.endswith(".sql"):
                        sql_file = os.path.join(_MIGRATIONS_DIR, name)
                        break
                if sql_file is None:
                    raise RuntimeError(
                        f"Migration {version} not found in {_MIGRATIONS_DIR}"
                    )
                with open(sql_file) as fh:
                    sql = fh.read()
                cur.execute(sql)
                cur.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)"
                    " ON CONFLICT (version) DO NOTHING",
                    (version,)
                )
                conn.commit()
                log.info("migration_applied", version=version, file=os.path.basename(sql_file))
    finally:
        conn.close()
    log.info("migrations_complete")


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

    Called once at startup *after* ``apply_migrations``.  Uses env-var values as
    the fallback so that existing deployments keep working unchanged.
    """
    global NETWORK_RANGES, SCAN_INTERVAL, PIHOLE_URL, PIHOLE_PASSWORD
    global IOT_LEARNING_HOURS, PIHOLE_IOT_GROUP, DASHBOARD_URL
    global DNS_SNIFF_ENABLED, DNS_SNIFF_IFACE
    global SSDP_ENABLED, SSDP_TIMEOUT
    global MDNS_ENABLED, NETBIOS_ENABLED
    global BANNER_GRAB_ENABLED, BANNER_GRAB_TIMEOUT
    global DHCP_SNIFF_ENABLED, ARP_SNIFF_ENABLED
    global SNIFF_PROCESS_INTERVAL
    global WSD_ENABLED, WSD_TIMEOUT
    global FINGERBANK_ENABLED, FINGERBANK_API_KEY

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
    SNIFF_PROCESS_INTERVAL = int(get_setting("SNIFF_PROCESS_INTERVAL", str(SNIFF_PROCESS_INTERVAL)))
    WSD_ENABLED          = get_setting("WSD_ENABLED", str(WSD_ENABLED).lower()).lower() == "true"
    WSD_TIMEOUT          = int(get_setting("WSD_TIMEOUT", str(WSD_TIMEOUT)))
    FINGERBANK_ENABLED   = get_setting("FINGERBANK_ENABLED", str(FINGERBANK_ENABLED).lower()).lower() == "true"
    FINGERBANK_API_KEY   = get_setting("FINGERBANK_API_KEY", FINGERBANK_API_KEY)
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
    2. Insert those FQDNs into ``iot_allowlist`` with the device's ``device_id``
       so each entry is traceable back to the specific IoT device that learned it.
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

                # ── 2. Store FQDNs in iot_allowlist tied to this device ──────────
                if domains:
                    # Clamp domain names to the VARCHAR(255) column limit.
                    safe_domains = [d[:_FQDN_MAX_LEN] for d in domains if d]
                    with conn.cursor() as cur:
                        for fqdn in safe_domains:
                            cur.execute(
                                """
                                INSERT INTO iot_allowlist (device_id, fqdn)
                                VALUES (%s, %s)
                                ON CONFLICT (device_id, fqdn) DO NOTHING
                                """,
                                (device_id, fqdn),
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
        _enrich_and_classify(host)

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
    """Scapy packet callback — extract device info from DHCP packets.

    Watches for DHCPDISCOVER (type 1) and DHCPREQUEST (type 3) packets,
    which are sent by clients and carry:
    - DHCP option 12 (hostname): the client's self-reported hostname.
    - DHCP option 55 (param_req_list): the Parameter Request List, whose
      exact sequence of option codes is unique to the client's TCP/IP stack
      and is used by fingerbank.org for passive device classification.
    - DHCP option 60 (vendor_class_id): the firmware / DHCP-client name, a
      strong IoT indicator (e.g. "udhcp 1.30.0" for BusyBox-based devices).

    Enqueues dicts with ``mac``, ``hostname``, and optionally ``ip``,
    ``dhcp_vendor_class``, and ``dhcp_fingerprint`` for processing by
    :func:`process_dhcp_sniff_queue`.
    """
    try:
        if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
            return
        if not pkt.haslayer(Ether):
            return

        msg_type: int | None = None
        hostname: str | None = None
        req_ip: str | None = None
        vendor_class: str | None = None
        dhcp_fingerprint: str | None = None

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
            elif code == "vendor_class_id":
                # DHCP option 60 — Vendor Class Identifier.
                # Strings like "udhcp 1.30.0", "espressif", "shelly" identify
                # the firmware / DHCP-client stack, giving an extra IoT signal.
                vendor_class = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
            elif code == "param_req_list":
                # DHCP option 55 — Parameter Request List.
                # The sequence of option codes the client requests is specific
                # to its TCP/IP stack; fingerbank.org uses this as the primary
                # key for passive device-type classification.
                try:
                    if isinstance(value, (list, tuple)):
                        dhcp_fingerprint = ",".join(str(v) for v in value)
                    elif isinstance(value, bytes):
                        dhcp_fingerprint = ",".join(str(b) for b in value)
                except Exception:
                    pass

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
        if vendor_class:
            entry["dhcp_vendor_class"] = vendor_class
        if dhcp_fingerprint:
            entry["dhcp_fingerprint"] = dhcp_fingerprint
        try:
            _dhcp_hostname_queue.put_nowait(entry)
        except queue.Full:
            pass
    except Exception as exc:
        log.debug("dhcp_packet_handler_error", error=str(exc))


def start_dhcp_sniffer() -> threading.Thread:
    """Start a daemon thread that sniffs DHCP packets for device hints.

    Captures DHCP client messages (DHCPDISCOVER and DHCPREQUEST) on ports 67
    and 68.  Hostname hints (option 12) and Vendor Class Identifier strings
    (option 60) are enqueued for DB update via :func:`process_dhcp_sniff_queue`.
    The VCI string provides a firmware-level IoT signal that is independent of
    MAC OUI assignments — for example BusyBox-based IoT Linux sends
    ``"udhcp X.Y.Z"`` which matches :data:`_IOT_DHCP_VCI_KEYWORDS`.

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
    """Drain the DHCP sniffer queue and update device records in the DB.

    For each enqueued entry:

    - Updates ``hostname`` when currently absent and back-fills a missing IP.
    - When the DHCP Vendor Class Identifier (option 60) matches a known IoT
      firmware keyword and the device_type is still ``unknown``, upgrades it
      to ``iot`` immediately.
    - When a DHCP option-55 fingerprint is present, queries fingerbank.org to
      identify the device by its DHCP Parameter Request List sequence.  The
      result is stored in ``extra_info.fingerbank_device_name`` and, when the
      returned category differs from the current device_type, the device_type
      is upgraded (never downgraded from a more-specific type).

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
        dhcp_vci = (entry.get("dhcp_vendor_class") or "").lower()
        dhcp_fp = entry.get("dhcp_fingerprint") or ""
        if not mac or not hostname:
            continue

        vci_is_iot = bool(dhcp_vci and any(kw in dhcp_vci for kw in _IOT_DHCP_VCI_KEYWORDS))

        # Query fingerbank if we have an option-55 fingerprint.
        fb_result: dict | None = None
        if dhcp_fp:
            fb_result = fingerbank_lookup(dhcp_fp, vendor_class=dhcp_vci, hostname=hostname)

        # Derive the best device_type hint from all signals.
        # Priority: fingerbank > VCI IoT keyword.  Never set "unknown".
        inferred_type: str | None = None
        if fb_result and fb_result.get("device_type") and fb_result["device_type"] != "unknown":
            inferred_type = fb_result["device_type"]
        elif vci_is_iot:
            inferred_type = "iot"

        # Build extra_info patch with fingerbank results.
        extra_patch: dict = {}
        if fb_result and fb_result.get("device_name"):
            extra_patch["fingerbank_device_name"] = fb_result["device_name"]
            extra_patch["fingerbank_score"] = fb_result.get("score", 0)
        if dhcp_fp:
            extra_patch["dhcp_fingerprint"] = dhcp_fp

        with conn.cursor() as cur:
            if inferred_type and extra_patch:
                cur.execute(
                    """
                    UPDATE devices
                    SET hostname    = COALESCE(NULLIF(hostname, ''), %s),
                        ip_address  = COALESCE(ip_address, %s),
                        device_type = CASE WHEN device_type = 'unknown' THEN %s ELSE device_type END,
                        extra_info  = extra_info || %s::jsonb,
                        last_seen   = NOW()
                    WHERE mac_address = %s
                      AND (hostname IS NULL OR hostname = '' OR device_type = 'unknown'
                           OR extra_info->>'fingerbank_device_name' IS NULL)
                    """,
                    (hostname, ip, inferred_type, json.dumps(extra_patch), mac),
                )
            elif inferred_type:
                cur.execute(
                    """
                    UPDATE devices
                    SET hostname    = COALESCE(NULLIF(hostname, ''), %s),
                        ip_address  = COALESCE(ip_address, %s),
                        device_type = CASE WHEN device_type = 'unknown' THEN %s ELSE device_type END,
                        last_seen   = NOW()
                    WHERE mac_address = %s
                      AND (hostname IS NULL OR hostname = '' OR device_type = 'unknown')
                    """,
                    (hostname, ip, inferred_type, mac),
                )
            elif extra_patch:
                cur.execute(
                    """
                    UPDATE devices
                    SET hostname    = COALESCE(NULLIF(hostname, ''), %s),
                        ip_address  = COALESCE(ip_address, %s),
                        extra_info  = extra_info || %s::jsonb,
                        last_seen   = NOW()
                    WHERE mac_address = %s
                      AND (hostname IS NULL OR hostname = ''
                           OR extra_info->>'fingerbank_device_name' IS NULL)
                    """,
                    (hostname, ip, json.dumps(extra_patch), mac),
                )
            else:
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
                log.info(
                    "dhcp_hostname_updated",
                    mac=mac, hostname=hostname, ip=ip,
                    dhcp_vci=dhcp_vci or None, vci_iot=vci_is_iot,
                    fingerbank=fb_result.get("device_name") if fb_result else None,
                )

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
        _enrich_and_classify(host)

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

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        try:
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
    finally:
        sock.close()

    log.info("ssdp_discover_done", found=len(responses))
    return responses


# ─── WSD / WS-Discovery active probe ─────────────────────────────────────────

_WSD_MULTICAST_ADDR = "239.255.255.250"
_WSD_PORT = 3702

# WS-Discovery Probe message (SOAP 1.2).  Sent to the WSD multicast group;
# Windows PCs, network printers, and ONVIF-compliant IP cameras reply with
# a ProbeMatch that includes device type strings, scope URIs, and HTTP
# endpoint addresses even when they do not support SSDP/UPnP.
# The {msg_uuid} placeholder is filled by uuid.uuid4() whose output is
# restricted to hex digits and hyphens — no XML special characters.
_WSD_PROBE_XML = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope'
    ' xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
    ' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
    ' xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
    "<soap:Header>"
    "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
    "<wsa:Action>"
    "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"
    "</wsa:Action>"
    "<wsa:MessageID>urn:uuid:{msg_uuid}</wsa:MessageID>"
    "</soap:Header>"
    "<soap:Body><wsd:Probe><wsd:Types/></wsd:Probe></soap:Body>"
    "</soap:Envelope>"
)

_WSD_NS = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsd":  "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "wsa":  "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "wsdp": "http://schemas.xmlsoap.org/ws/2006/02/devprof",
}


def wsd_discover(timeout: int = 5) -> dict[str, dict]:
    """Discover WS-Discovery (WSD) devices via UDP multicast on port 3702.

    Sends a WS-Discovery Probe to the standard multicast address
    (239.255.255.250:3702) and waits *timeout* seconds for ProbeMatch
    responses.  Windows PCs share device info via WSD even with SSDP
    disabled; network printers and ONVIF cameras also respond here.

    Each ProbeMatch yields:

    - ``wsd_types``: space-separated device-type declarations, e.g.
      ``wsdp:Device pub:NetworkVideoTransmitter`` (ONVIF camera),
      ``wscn:ScanDeviceType wsdp:Device`` (scanner), ``pri:Printer`` (printer).
    - ``wsd_scopes``: space-separated scope URIs, e.g.
      ``onvif://www.onvif.org/name/AXIS%20P1448-LE``.
    - ``wsd_xaddrs``: space-separated HTTP endpoint URLs (device service URLs).

    Returns a dict mapping IP address → enrichment dict.
    """
    if not WSD_ENABLED:
        return {}

    probe = _WSD_PROBE_XML.format(msg_uuid=uuid.uuid4()).encode("utf-8")
    responses: dict[str, dict] = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        try:
            sock.sendto(probe, (_WSD_MULTICAST_ADDR, _WSD_PORT))
        except Exception as exc:
            log.warning("wsd_send_error", error=str(exc))
            return {}

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65507)
                ip = addr[0]
                if ip in responses:
                    continue
                try:
                    root = ET.fromstring(data.decode("utf-8", errors="replace"))
                    types_el = root.find(".//wsd:Types", _WSD_NS)
                    scopes_el = root.find(".//wsd:Scopes", _WSD_NS)
                    xaddrs_el = root.find(".//wsd:XAddrs", _WSD_NS)
                    entry: dict = {}
                    if types_el is not None and types_el.text:
                        entry["wsd_types"] = types_el.text.strip()
                    if scopes_el is not None and scopes_el.text:
                        entry["wsd_scopes"] = scopes_el.text.strip()
                    if xaddrs_el is not None and xaddrs_el.text:
                        entry["wsd_xaddrs"] = xaddrs_el.text.strip()
                    if entry:
                        responses[ip] = entry
                except ET.ParseError as exc:
                    log.debug("wsd_parse_error", ip=ip, error=str(exc))
            except TimeoutError:
                break
            except OSError:
                break
            except Exception as exc:
                log.debug("wsd_recv_error", error=str(exc))
                break
    finally:
        sock.close()

    log.info("wsd_discover_done", found=len(responses))
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
    # IoT-specific service types
    "_hue._tcp.local.",             # Philips Hue bridge
    "_deconz._tcp.local.",          # deCONZ Zigbee gateway
    "_wled._tcp.local.",            # WLED LED controller
    "_elg._tcp.local.",             # Elgato smart accessories
    "_axis-video._tcp.local.",      # Axis network cameras
    "_androidtvremote._tcp.local.", # Android TV remote
    "_viziocast._tcp.local.",       # Vizio Cast
    "_nvstream._tcp.local.",        # NVIDIA Shield / game streaming
    "_amazon-setup._tcp.local.",    # Amazon Echo setup
    "_miio._udp.local.",            # Xiaomi Mi IO protocol
    "_mesh-tunnel._tcp.local.",     # Matter / Thread mesh
    "_octoprint._tcp.local.",       # OctoPrint 3D printer controller
    "_esphomelib._tcp.local.",      # ESPHome IoT devices
    "_ambientweather._tcp.local.",  # Ambient Weather stations
    "_smartthings._tcp.local.",     # Samsung SmartThings
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

    - ``mdns_services``: list of service entry dicts (including raw TXT properties)
    - ``mdns_hostname``: the ``.local`` hostname from the first entry that provides one
    - ``mdns_txt_model``: model name extracted from TXT record keys ``md``, ``model``, ``mn``
    - ``mdns_txt_type``: device-type hint from TXT record keys ``ty``, ``dt``
    - ``mdns_txt_friendly_name``: friendly name from TXT record key ``fn``

    TXT record key/value pairs carry rich metadata on Apple HomeKit accessories
    (``md`` = model, ``am`` = Apple model identifier), Chromecasts (``fn`` =
    friendly name), printers (``ty`` = device type), and ESPHome devices.
    Surfacing these as top-level fields lets :func:`guess_device_type` use them
    without iterating nested service lists.
    """
    # TXT record keys whose values represent a model name.
    _MODEL_KEYS = {"md", "model", "mn", "am"}
    # TXT record keys whose values represent a device type/category string.
    _TYPE_KEYS = {"ty", "dt"}
    # TXT record key for friendly/display name.
    _FNAME_KEY = "fn"

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

        # Extract high-value TXT record fields and promote to top-level keys.
        props = entry.get("properties") or {}
        for raw_key, raw_val in props.items():
            key_l = raw_key.lower() if isinstance(raw_key, str) else ""
            val_s = str(raw_val).strip() if raw_val else ""
            if not val_s:
                continue
            if key_l in _MODEL_KEYS and not enrichment[ip].get("mdns_txt_model"):
                enrichment[ip]["mdns_txt_model"] = val_s
            elif key_l in _TYPE_KEYS and not enrichment[ip].get("mdns_txt_type"):
                enrichment[ip]["mdns_txt_type"] = val_s
            elif key_l == _FNAME_KEY and not enrichment[ip].get("mdns_txt_friendly_name"):
                enrichment[ip]["mdns_txt_friendly_name"] = val_s

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


def _parse_nmap_ssl_cert(output: str) -> dict:
    """Parse nmap ``ssl-cert`` script text output into structured cert fields.

    nmap's ``ssl-cert`` NSE script produces human-readable text such as::

        Subject: commonName=device.local/organizationName=Acme Corp
        Subject Alternative Name: DNS:device.local, DNS:*.device.local
        Issuer: commonName=Acme Root CA/organizationName=Acme Corp

    Returns a dict that may contain ``tls_cn``, ``tls_org``,
    ``tls_issuer_cn``, and ``tls_sans`` — the same keys produced by
    :func:`tls_cert_info` — so both code paths can be consumed identically.
    """
    result: dict = {}
    subject_match = re.search(r"Subject: (.+?)(?:\n|$)", output)
    if subject_match:
        subject_str = subject_match.group(1)
        cn = re.search(r"commonName=([^/\n]+)", subject_str)
        org = re.search(r"organizationName=([^/\n]+)", subject_str)
        if cn:
            result["tls_cn"] = cn.group(1).strip()
        if org:
            result["tls_org"] = org.group(1).strip()
    issuer_match = re.search(r"Issuer: (.+?)(?:\n|$)", output)
    if issuer_match:
        cn = re.search(r"commonName=([^/\n]+)", issuer_match.group(1))
        if cn:
            result["tls_issuer_cn"] = cn.group(1).strip()
    san_match = re.search(r"Subject Alternative Name: (.+?)(?:\n|$)", output)
    if san_match:
        sans = [
            p.strip()[4:]
            for p in san_match.group(1).split(",")
            if p.strip().startswith("DNS:")
        ]
        if sans:
            result["tls_sans"] = sans
    return result


def _parse_snmp_info(output: str) -> dict:
    """Parse nmap ``snmp-info`` script text output into structured fields.

    nmap's ``snmp-info`` NSE script produces output such as::

        Enterprise: enterprises.9 (Cisco Systems, Inc.)
        sysDescr: Cisco IOS Software, Version 15.1(4)M12a ...
        sysObjectID: 1.3.6.1.4.1.9.1.620
        sysContact: noc@example.com
        sysName: core-rtr-01
        sysLocation: Building A, Server Room

    Returns a dict with any of these keys that are present:
    ``snmp_sysdescr``, ``snmp_sysname``, ``snmp_contact``, ``snmp_location``,
    ``snmp_enterprise``.
    """
    result: dict = {}
    for line in output.splitlines():
        line = line.strip()
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if not val:
            continue
        if key.lower() == "sysdescr":
            result["snmp_sysdescr"] = val
        elif key.lower() == "sysname":
            result["snmp_sysname"] = val
        elif key.lower() == "syscontact":
            result["snmp_contact"] = val
        elif key.lower() == "syslocation":
            result["snmp_location"] = val
        elif key.lower() == "enterprise":
            # Strip trailing parenthetical OUI annotation, keep the text part.
            m = re.search(r"\((.+?)\)", val)
            result["snmp_enterprise"] = m.group(1).strip() if m else val
    return result


def enrich_from_banners(ip: str, open_ports: list[dict]) -> dict:
    """Grab HTTP server banners, TLS certificate info, SNMP metadata, and TCP
    banners for *ip*.

    First checks for NSE script results embedded in *open_ports* by
    :func:`nmap_scan`.  Using nmap's built-in scripts avoids opening additional
    TCP connections for data that nmap has already collected during the
    port/service scan pass.

    Falls back to direct socket probes (``HEAD /`` and TLS handshake) only
    when nmap script output is not present — for example, when a host was
    discovered via ARP or Pi-hole without a prior nmap scan, or when the
    scripts produced no output for a particular port.

    Script outputs consumed:

    - ``http-server-header`` → ``http_server``
    - ``http-title`` → ``http_title``
    - ``ssl-cert`` → ``tls_cn``, ``tls_org``, ``tls_issuer_cn``, ``tls_sans``
    - ``snmp-info`` → ``snmp_sysdescr``, ``snmp_sysname``, ``snmp_contact``,
      ``snmp_location``, ``snmp_enterprise``
    - ``banner`` → ``tcp_banner`` (first non-HTTP/HTTPS port that has one)

    Returns a (possibly empty) dict of enrichment fields.
    """
    if not BANNER_GRAB_ENABLED or not open_ports:
        return {}

    result: dict = {}
    http_ports = [p for p in open_ports if p.get("service") in ("http",) or p["port"] in (80, 8080)]
    https_ports = [p for p in open_ports if p.get("service") in ("https", "ssl") or p["port"] in (443, 8443)]
    snmp_ports = [p for p in open_ports if p.get("service") == "snmp" or p["port"] in (161, 162)]
    other_ports = [p for p in open_ports if p not in http_ports and p not in https_ports and p not in snmp_ports]

    # ── HTTP: prefer nmap http-server-header + http-title scripts, fall back to socket ──
    for p in http_ports:
        scripts = p.get("scripts", {})
        header_val = scripts.get("http-server-header", "").strip()
        if header_val:
            result["http_server"] = header_val
            break
    if not result.get("http_server"):
        for p in http_ports:
            banner = http_banner(ip, p["port"], timeout=BANNER_GRAB_TIMEOUT)
            if banner:
                result["http_server"] = banner
                break

    # ── HTTP title: nmap http-title script ───────────────────────────────────
    for p in http_ports + https_ports:
        scripts = p.get("scripts", {})
        title_val = scripts.get("http-title", "").strip()
        # Strip the common "Did not follow redirect to ..." noise
        if title_val and not title_val.lower().startswith("did not follow"):
            result["http_title"] = title_val
            break

    # ── HTTPS: prefer nmap ssl-cert script, fall back to TLS socket ──────────
    for p in https_ports:
        scripts = p.get("scripts", {})
        cert_output = scripts.get("ssl-cert", "")
        if cert_output:
            cert = _parse_nmap_ssl_cert(cert_output)
            if cert:
                result.update(cert)
                # Also grab the HTTP server header for this HTTPS port if
                # the nmap script reported it.
                if not result.get("http_server"):
                    header_val = scripts.get("http-server-header", "").strip()
                    if header_val:
                        result["http_server"] = header_val
                break
    if not result.get("tls_cn"):
        for p in https_ports:
            cert = tls_cert_info(ip, p["port"], timeout=BANNER_GRAB_TIMEOUT)
            if cert:
                result.update(cert)
                if not result.get("http_server"):
                    banner = http_banner(ip, p["port"], timeout=BANNER_GRAB_TIMEOUT)
                    if banner:
                        result["http_server"] = banner
                break

    # ── SNMP: nmap snmp-info script ───────────────────────────────────────────
    for p in snmp_ports:
        scripts = p.get("scripts", {})
        snmp_output = scripts.get("snmp-info", "")
        if snmp_output:
            snmp_fields = _parse_snmp_info(snmp_output)
            if snmp_fields:
                result.update(snmp_fields)
                break

    # ── TCP banner: nmap banner script (non-HTTP/HTTPS/SNMP ports) ───────────
    for p in other_ports:
        scripts = p.get("scripts", {})
        banner_val = scripts.get("banner", "").strip()
        if banner_val:
            result["tcp_banner"] = banner_val
            break

    return result


# ─── nmap port/OS scan ───────────────────────────────────────────────────────

def nmap_scan(ip: str) -> dict:
    """Run a quick nmap scan on *ip* and return port list + OS guess.

    Uses nmap's built-in NSE scripts so that enrichment data is collected in
    the same scan pass rather than requiring separate socket connections.
    Scripts enabled:

    - ``http-server-header`` — HTTP ``Server:`` response header
    - ``http-title`` — HTML page title (useful for device identification)
    - ``ssl-cert`` — TLS certificate fields (CN, org, SANs)
    - ``snmp-info`` — SNMP system description, name, contact, location
    - ``banner`` — generic TCP banner for non-HTTP services

    The script output is attached to each port entry under the ``"scripts"``
    key and consumed by :func:`enrich_from_banners`.
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(
            ip,
            arguments=(
                "-O -sV --osscan-guess -T4 --host-timeout 10s --open"
                " --script=http-server-header,http-title,ssl-cert,snmp-info,banner"
            ),
        )
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
                port_data: dict = {
                    "port": port,
                    "protocol": proto,
                    "service": info.get("name", ""),
                    "version": info.get("version", ""),
                }
                # Include NSE script output so enrich_from_banners() can
                # consume http-server-header and ssl-cert results without
                # opening additional TCP connections.
                scripts = info.get("script", {})
                if scripts:
                    port_data["scripts"] = scripts
                open_ports.append(port_data)

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
# All entries are matched as case-insensitive substrings of the vendor field,
# so a short prefix like "espressif" covers "Espressif Systems, Inc." and any
# future variant reported by MAC-vendor databases.
#
# Note: a subset of these keywords also appears in ``device_classifier.py``'s
# ``VENDOR_KEYWORDS`` list, which is the RF classifier's binary feature set.
# The two lists serve different roles: ``VENDOR_KEYWORDS`` drives the trained
# model (must be kept short for tractable feature counts), while
# ``_IOT_VENDOR_KEYWORDS`` drives the heuristic rule engine (can be as broad
# as needed, no size constraint).  Both sets must be updated when adding new
# IoT module / chip OEM keywords so that both the RF classifier and the
# heuristic fallback benefit from the new signal.
_IOT_VENDOR_KEYWORDS: frozenset[str] = frozenset({
    # Microcontroller / embedded-SoC manufacturers
    "espressif", "espressif systems", "raspberry pi", "raspberrypi",
    "microchip technology", "nordic semiconductor", "silicon labs", "silabs",
    "texas instruments", "stmicroelectronics", "nxp semiconductors",
    "arduino", "particle industries", "pycom", "seeed", "adafruit",
    "bouffalo lab", "beken corporation", "winner micro",
    # Smart-home protocols / hubs
    "z-wave", "zigbee", "insteon", "lutron", "leviton", "ge lighting",
    "smartthings", "samsung smarthings", "hubitat",
    "aeotec", "fibar group", "fibaro", "homeseer", "micasaverde",
    "athom", "zipato", "vera control",
    # Smart lighting
    "signify", "philips lighting", "lifx", "osram", "sylvania", "sengled",
    "innr", "yeelight", "milight", "nanoleaf", "govee", "feit electric",
    "ikea of sweden", "magic home", "zengge", "magichue",
    # Smart plugs / switches / automation
    "tuya", "ewelink", "shelly", "sonoff", "tasmota", "esphome", "meross",
    "wemo", "belkin", "kasa", "tp-link", "tp link", "tplink",
    "gosund", "switchbot", "wonder innovation", "broadlink",
    # Thermostats / HVAC
    "nest", "ecobee", "honeywell", "tado", "thermosmart",
    "emerson electric", "johnson controls", "bosch thermotechnology",
    # IP cameras / doorbells / security
    "ring", "arlo", "blink", "eufy", "amcrest", "foscam", "reolink",
    "hikvision", "dahua", "axis communications", "hanwha", "vivotek",
    "pelco", "mobotix", "uniview", "zosi", "zmodo", "annke", "tenvis",
    "doorbird", "bird home automation", "august home",
    "alarm.com", "digital ally",
    # Smart speakers / voice assistants / streaming
    "sonos", "roku", "amazon technologies", "amazon.com",
    "google nest", "nest labs",
    # Smart locks / access control
    "august home", "kwikset", "allegion", "dormakaba",
    # Robot vacuums / smart appliances
    "irobot", "ecovacs robotics", "roborock", "neato robotics", "shark ninja",
    # Consumer IoT / misc
    "wyze", "anker innovations", "xiaomi", "aqara", "miio",
    "d-link", "dlink", "vizio", "tcl", "hisense",
    "withings", "netatmo", "eve systems", "elgato",
    "somfy", "hunter douglas", "velux",
    "chamberlain", "liftmaster", "genie company",
    # IoT module / chip makers whose OUI appears on commodity IoT hardware
    "smart innovation",   # Smart Innovation LLC — IoT WiFi modules
    "hui zhou gaoshengda",  # Hui Zhou Gaoshengda Technology — IoT/media module OEM
    "shenzhen aisens",
    "shenzhen bilian",
})

# OS / firmware fingerprint substrings that indicate embedded systems.
_IOT_OS_KEYWORDS: frozenset[str] = frozenset({
    "embedded linux", "uclinux", "openwrt", "lede", "dd-wrt", "buildroot",
    "vxworks", "freertos", "threadx", "nucleus rtos", "contiki", "tinyos",
    "busybox", "yocto", "mongoose os", "micropython",
    "zephyr", "riot os", "nuttx", "azure rtos", "mbed os",
    "balena", "ubuntu core", "android things",
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
    8009,   # Google Cast (Chromecast)
    8008,   # Google Cast control channel
    9999,   # TP-Link Kasa smart home protocol
    4911,   # Niagara BACnet (building automation)
    18443,  # Some smart home hub APIs
    49153,  # Belkin WeMo UPnP event listener
})

# Hostname substrings that indicate IoT devices.
_IOT_HOSTNAME_KEYWORDS: frozenset[str] = frozenset({
    # ESP / Arduino microcontroller defaults
    "esp-", "esp8266", "esp32", "wemos", "arduino-",
    # Firmware / platform names that appear in mDNS hostnames
    "shelly", "tasmota", "sonoff", "tuya-", "esphome-",
    # Xiaomi smart home
    "miio-", "yeelink-",
    # Amazon smart devices
    "amazon-", "echo-", "alexa-", "fire-tv", "firetv", "firestick",
    # Google / Nest smart devices
    "google-home", "googlehome", "googlenest", "nest-", "nest-hub",
    # Apple smart devices
    "homepod", "appletv", "apple-tv",
    # Other smart speakers / streaming
    "roku-", "lifx", "chromecast-",
    # Ring / Arlo / Wyze / security
    "ring-", "arlo-", "wyze-", "blink-",
    # IP cameras
    "cam-", "nvr-", "dvr-", "ipcam", "ipcamera",
    # Smart lighting / mesh
    "hue-bridge", "philips-hue", "tradfri", "dirigera", "govee-", "wled-",
    # Smart home controllers / hubs
    "ecobee", "tado-", "octoprint", "homebridge",
    "hassio", "homeassistant", "ha-",
    "smartthings", "hubitat",
    # Misc smart home
    "broadlink", "switchbot", "meross-",
    "roomba", "robovac", "roborock",
    "insteon-", "vera-", "homeseer",
    "netatmo-", "withings-",
    "doorbell", "smartplug", "smartbulb",
    "sensor-", "plug-",
})

# HTTP ``Server`` header substrings that identify IoT / embedded web servers.
# Matched case-insensitively against the ``http_server`` field captured by
# :func:`enrich_from_banners`.  Embedded web servers like GoAhead, Boa, and
# lwIP are almost exclusively found on IoT and industrial devices.
_IOT_HTTP_SERVER_KEYWORDS: frozenset[str] = frozenset({
    # Embedded / lightweight web servers
    "lwip",            # Lightweight IP stack (ESP8266, ESP32, many IoT SoCs)
    "goahead",         # Embedthis GoAhead (IP cameras, smart home, HVAC)
    "boa",             # Boa web server (legacy IoT devices, routers)
    "uhttpd",          # OpenWrt µHTTPd
    "mini_httpd",      # mini_httpd (embedded systems)
    "mongoose",        # Mongoose OS / Cesanta web server (ESP, embedded)
    "micropython",     # MicroPython HTTP server
    "esp-idf",         # Espressif IoT Development Framework
    "shelly",          # Shelly smart relays / dimmers
    "tasmota",         # Tasmota open-source firmware
    "openwrt",         # OpenWrt — embedded Linux for routers / hubs
    "dd-wrt",          # DD-WRT router firmware
    # IP camera / NVR brands
    "hikvision",       # Hikvision IP cameras
    "dnvrs-webs",      # Dahua NVR / DVR web server
    "dahua",           # Dahua IP cameras
    "axis",            # Axis network cameras
    "vivotek",         # VIVOTEK IP cameras
    "amcrest",         # Amcrest cameras
    "reolink",         # Reolink cameras
    "foscam",          # Foscam cameras
    "netwave",         # NetWave IP cameras
    # Smart home brands
    "ewelink",         # Sonoff / eWeLink firmware
    "wemo",            # Belkin WeMo smart plug
    "homeseer",        # HomeSeer smart home controller
    "vera",            # MiCasaVerde Vera home controller
})

# DHCP option 60 (Vendor Class Identifier) substrings that indicate embedded /
# IoT DHCP clients.  Many IoT devices advertise their firmware or DHCP client
# name in this option, giving a reliable classification signal that is
# independent of MAC OUI assignments.
_IOT_DHCP_VCI_KEYWORDS: frozenset[str] = frozenset({
    "udhcp",        # BusyBox udhcpd / udhcpc (embedded Linux — ubiquitous in IoT)
    "busybox",      # BusyBox DHCP client
    "shelly",       # Shelly firmware DHCP client
    "esp-idf",      # Espressif IDF DHCP client
    "tasmota",      # Tasmota firmware
    "openwrt",      # OpenWrt DHCP client
    "dd-wrt",       # DD-WRT firmware
    "freertos",     # FreeRTOS TCP/IP stack
    "contiki",      # Contiki OS DHCP
    "lwip",         # lwIP DHCP client (very common in ESP chips)
    "micropython",  # MicroPython urequests / usocket
    "mongoose",     # Mongoose OS
})

# UPnP manufacturer name substrings that identify IoT devices.
# Matched case-insensitively against the ``upnp_manufacturer`` field extracted
# from UPnP device-description XML by :func:`ssdp_discover`.
_IOT_UPNP_MANUFACTURERS: frozenset[str] = frozenset({
    "tuya", "espressif", "shelly", "philips", "sonos", "ring", "nest",
    "ecobee", "amazon", "google", "ikea", "govee", "irobot", "ecovacs",
    "roborock", "withings", "netatmo", "fibaro", "aeotec", "belkin",
    "wemo", "kasa", "switchbot", "broadlink", "hikvision", "dahua",
    "axis", "amcrest", "reolink", "foscam", "wyze", "eufy", "blink",
    "arlo", "august", "chamberlain", "liftmaster",
    # Streaming / smart-TV manufacturers advertised via UPnP
    "roku", "tcl", "hisense", "vizio", "tivo", "directv", "samsung",
    "lg electronics", "lg", "sony", "sharp", "panasonic",
})

# HTML page title substrings (from nmap ``http-title`` NSE script) that
# indicate IoT / embedded devices.  Matched case-insensitively.
_IOT_HTTP_TITLE_KEYWORDS: frozenset[str] = frozenset({
    # Routers / gateways
    "router", "gateway", "modem", "tp-link", "tplink", "netgear", "asus router",
    "d-link", "dlink", "linksys", "belkin", "zyxel", "mikrotik", "routeros",
    "openwrt", "dd-wrt", "tomato", "asuswrt", "merlin",
    # Access points / switches
    "access point", "unifi", "ubiquiti", "edgerouter", "edgeswitch",
    "aironet", "aruba", "ruckus", "meraki",
    # IP cameras / NVRs
    "ip camera", "network camera", "ipcam", "hikvision", "dahua", "foscam",
    "amcrest", "reolink", "axis camera", "vivotek", "nvr", "dvr",
    # Smart home devices / hubs
    "smart home", "home automation", "home assistant", "homebridge",
    "smartthings", "hubitat", "vera", "fibaro", "domoticz", "openhab",
    # NAS / storage
    "synology diskstation", "qnap", "nas manager", "diskstation manager",
    "readynas", "buffalo nas",
    # Printers
    "hp laserjet", "hp officejet", "hp deskjet", "brother", "canon print",
    "epson", "xerox", "printer", "jetdirect",
    # Smart speakers / media
    "chromecast", "google home", "amazon echo", "fire tv", "roku",
    "apple tv", "sonos", "plex media",
    # Misc embedded / IoT
    "shelly", "tasmota", "esphome", "wled", "octoprint",
})

# SNMP sysDescr substrings that identify specific device categories.
# Matched case-insensitively against the ``snmp_sysdescr`` field.
_SNMP_NETWORK_DEVICE_KEYWORDS: frozenset[str] = frozenset({
    "cisco ios", "cisco nx-os", "ios-xe", "ios xr",
    "junos", "juniper",
    "routeros", "mikrotik",
    "edgeos", "edgerouter",
    "arubaos", "aruba",
    "openwrt", "dd-wrt",
    "zyxel", "zywall",
    "fortios", "fortigate",
    "panos", "pan-os",
    "comware",
    "procurve",
    "extremexos",
    "sonic", "dell sonic",
    "freebsd",          # pfSense / OPNsense
    "opnsense", "pfsense",
})

_SNMP_PRINTER_KEYWORDS: frozenset[str] = frozenset({
    "jetdirect", "laserjet", "officejet", "deskjet",
    "brother", "bizhub", "konica", "kyocera",
    "xerox", "lexmark", "ricoh", "epson", "canon",
    "printer", "print server",
})

_SNMP_IOT_KEYWORDS: frozenset[str] = frozenset({
    "esp-idf", "freertos", "ucos", "lwip", "contiki",
    "shelly", "tasmota", "openwrt", "lede",
    "hikvision", "dahua", "axis", "amcrest",
    "raspberry pi", "raspbian",
})

# OUI vendor strings that reliably identify dedicated network infrastructure.
# These are distinct from IoT vendors — they do NOT appear in _IOT_VENDOR_KEYWORDS.
_NETWORK_DEVICE_VENDOR_KEYWORDS: frozenset[str] = frozenset({
    "ubiquiti", "ubnt",
    "cisco systems", "cisco",
    "juniper networks", "juniper",
    "aruba networks", "aruba",
    "mikrotik", "routerboard",
    "zyxel",
    "fortinet",
    "meraki",
    "ruckus",
    "aerohive",
    "sophos",
    "watchguard",
    "barracuda",
    "sonicwall",
    "palo alto",
    "extreme networks",
    "cambium networks",
    "cradlepoint",
})

# OUI vendor strings that reliably identify NAS / storage appliances.
_NAS_SERVER_VENDOR_KEYWORDS: frozenset[str] = frozenset({
    "synology",
    "qnap",
    "western digital",
    "wd connected",
    "drobo",
    "asustor",
    "buffalo",
    "netgear ready",  # ReadyNAS
    "seagate technology",
    "promise technology",
    "overland-tandberg",
})

def guess_device_type(
    vendor: str | None,
    open_ports: list[dict],
    os_guess: str | None,
    extra_info: str | None = None,
    hostname: str | None = None,
    mac: str | None = None,
) -> str:
    """Heuristic device-type classifier.

    Uses MAC vendor string, nmap OS fingerprint, open port set, mDNS service
    types and TXT records, WSD device-type strings, UPnP device/manufacturer
    fields, HTTP server banner, HTTP page title, SNMP sysDescr/sysName,
    DHCP fingerbank results, MAC address randomization flag, and hostname to
    produce a best-effort device category.

    Returns one of: ``iot``, ``desktop``, ``server``, ``mobile``,
    ``printer``, ``network_device``, or ``unknown``.
    """

    vendor_l = (vendor or "").lower()
    os_l = (os_guess or "").lower()
    hostname_l = (hostname or "").lower()
    ports = {p["port"] for p in open_ports}
    extra = extra_info or {}

    # ── mDNS service-type hints (highest specificity) ─────────────────────────
    # Collect ALL advertised service types before applying rules so that
    # multi-service combinations (e.g. _airplay + _spotify-connect) are
    # evaluated together rather than returning on the first matching service.
    _mdns_stypes: set[str] = {
        svc.get("service_type", "") for svc in extra.get("mdns_services", [])
    }
    if _mdns_stypes:
        _has_companion = any("_companion-link._tcp" in s for s in _mdns_stypes)
        _has_workstation = any("_workstation._tcp" in s for s in _mdns_stypes)
        _has_ssh_mdns = any("_ssh._tcp" in s for s in _mdns_stypes)

        if any("_googlecast._tcp" in s or "_cast._tcp" in s for s in _mdns_stypes):
            return "iot"
        if any("_homekit._tcp" in s or "_hap._tcp" in s or "_matter._tcp" in s for s in _mdns_stypes):
            return "iot"
        if any("_printer._tcp" in s or "_ipp._tcp" in s or "_ipps._tcp" in s for s in _mdns_stypes):
            return "printer"
        if _has_workstation:
            return "desktop"
        if any("_smb._tcp" in s or "_afpovertcp._tcp" in s for s in _mdns_stypes):
            return "desktop"
        # Streaming / media device indicators (e.g. Roku, Sonos, Android TV) —
        # check before _airplay._tcp so these devices are not misclassified as mobile.
        if any("_spotify-connect._tcp" in s for s in _mdns_stypes):
            return "iot"
        # Additional IoT-specific mDNS service types
        if any(
            kw in s
            for s in _mdns_stypes
            for kw in (
                "_hue._tcp", "_deconz._tcp", "_wled._tcp", "_elg._tcp",
                "_axis-video._tcp", "_androidtvremote._tcp", "_viziocast._tcp",
                "_nvstream._tcp", "_amazon-setup._tcp", "_miio._udp",
            )
        ):
            return "iot"
        # _companion-link._tcp is an iOS/iPadOS Continuity protocol.  A device
        # advertising it without desktop-class mDNS (_workstation, _ssh) is a
        # phone or tablet.
        if _has_companion and not (_has_workstation or _has_ssh_mdns):
            return "mobile"
        # _airplay._tcp / _raop._tcp without _companion-link → Apple TV, HomePod,
        # or a third-party AirPlay receiver (Roku, Android TV).  Classify as iot
        # rather than mobile; macOS laptops with AirPlay will have been caught
        # earlier by _workstation._tcp or the RF classifier.
        if any("_airplay._tcp" in s or "_raop._tcp" in s for s in _mdns_stypes):
            return "iot"

    # ── mDNS TXT record hints (model / device-type strings from Bonjour TXTs) ─
    # Keys like ``md`` (HomeKit model), ``ty`` (printer type), ``am`` (Apple
    # model identifier like "iPhone14,2") expose the exact device identity.
    mdns_txt_type_l = extra.get("mdns_txt_type", "").lower() if isinstance(extra.get("mdns_txt_type"), str) else ""
    mdns_txt_model_l = extra.get("mdns_txt_model", "").lower() if isinstance(extra.get("mdns_txt_model"), str) else ""
    if mdns_txt_type_l:
        if any(kw in mdns_txt_type_l for kw in ("printer", "scanner", "fax")):
            return "printer"
        if any(kw in mdns_txt_type_l for kw in ("camera", "nvr", "iot", "smart")):
            return "iot"
    if mdns_txt_model_l:
        # Apple model identifiers: "iPhone" / "iPad" → mobile; "MacBook" → desktop
        if any(kw in mdns_txt_model_l for kw in ("iphone", "ipad", "ipod")):
            return "mobile"
        if any(kw in mdns_txt_model_l for kw in ("macbook", "imac", "mac mini", "mac pro")):
            return "desktop"
        if any(kw in mdns_txt_model_l for kw in _IOT_VENDOR_KEYWORDS):
            return "iot"

    # ── WSD device-type hints (Windows PCs, printers, ONVIF cameras) ──────────
    wsd_types_l = extra.get("wsd_types", "").lower() if isinstance(extra.get("wsd_types"), str) else ""
    wsd_scopes_l = extra.get("wsd_scopes", "").lower() if isinstance(extra.get("wsd_scopes"), str) else ""
    if wsd_types_l:
        if any(kw in wsd_types_l for kw in ("pri:printer", "printdevice", "wscn:")):
            return "printer"
        if any(kw in wsd_types_l for kw in ("networkvideotransmitter", "networkvideodisplay")):
            return "iot"  # ONVIF IP camera
        if "scandevicetype" in wsd_types_l:
            return "printer"  # WS-Scan scanner
    if wsd_scopes_l:
        if "onvif" in wsd_scopes_l:
            return "iot"  # ONVIF-capable camera/encoder

    # ── UPnP device-type hints ────────────────────────────────────────────────
    upnp_type = extra.get("upnp_device_type", "")
    upnp_mfr = extra.get("upnp_manufacturer", "").lower()
    upnp_friendly = extra.get("upnp_friendly_name", "").lower()
    upnp_model = extra.get("upnp_model_name", "").lower()
    if "InternetGatewayDevice" in upnp_type:
        return "network_device"
    if "MediaRenderer" in upnp_type or "MediaServer" in upnp_type:
        return "iot"
    if "printer" in upnp_type.lower():
        return "printer"
    if "WLANAccessPoint" in upnp_type or "WANDevice" in upnp_type:
        return "network_device"
    if any(v in upnp_mfr for v in _IOT_UPNP_MANUFACTURERS):
        return "iot"
    # Also check UPnP friendly name and model for IoT keywords
    upnp_combined = f"{upnp_friendly} {upnp_model}"
    if any(kw in upnp_combined for kw in _IOT_VENDOR_KEYWORDS):
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

    # ── Dedicated network infrastructure vendors ──────────────────────────────
    # Checked after IoT (Ubiquiti is never IoT; Cisco, Aruba, etc. likewise).
    if any(kw in vendor_l for kw in _NETWORK_DEVICE_VENDOR_KEYWORDS):
        return "network_device"

    # ── NAS / storage appliance vendors ──────────────────────────────────────
    if any(kw in vendor_l for kw in _NAS_SERVER_VENDOR_KEYWORDS):
        return "server"

    # ── HTTP server banner hints ──────────────────────────────────────────────
    http_server_l = extra.get("http_server", "").lower() if isinstance(extra.get("http_server"), str) else ""
    if http_server_l and any(kw in http_server_l for kw in _IOT_HTTP_SERVER_KEYWORDS):
        return "iot"

    # ── HTTP page title hints ─────────────────────────────────────────────────
    http_title_l = extra.get("http_title", "").lower() if isinstance(extra.get("http_title"), str) else ""
    if http_title_l:
        if any(kw in http_title_l for kw in _IOT_HTTP_TITLE_KEYWORDS):
            return "iot"
        # Printer titles (HP / Epson / Canon / etc.)
        if any(kw in http_title_l for kw in ("printer", "jetdirect", "laserjet", "officejet")):
            return "printer"
        # NAS / storage appliance
        if any(kw in http_title_l for kw in ("diskstation", "qnap", "nas", "readynas")):
            return "server"

    # ── SNMP sysDescr hints ───────────────────────────────────────────────────
    snmp_descr_l = extra.get("snmp_sysdescr", "").lower() if isinstance(extra.get("snmp_sysdescr"), str) else ""
    snmp_name_l = extra.get("snmp_sysname", "").lower() if isinstance(extra.get("snmp_sysname"), str) else ""
    if snmp_descr_l:
        if any(kw in snmp_descr_l for kw in _SNMP_NETWORK_DEVICE_KEYWORDS):
            return "network_device"
        if any(kw in snmp_descr_l for kw in _SNMP_PRINTER_KEYWORDS):
            return "printer"
        if any(kw in snmp_descr_l for kw in _SNMP_IOT_KEYWORDS):
            return "iot"
        if "windows" in snmp_descr_l:
            return "desktop"
        # Linux host with SSH open is likely a server; without = ambiguous
        if "linux" in snmp_descr_l:
            return "server" if 22 in ports else "unknown"
    # SNMP sysName can also disambiguate (e.g. "rtr-01", "sw-01")
    if snmp_name_l and any(kw in snmp_name_l for kw in ("rtr", "router", "sw-", "switch", "fw-", "ap-")):
        return "network_device"

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

    # ── MAC randomization → mobile device ────────────────────────────────────
    # Locally-administered (private/random) MACs with no known OUI vendor are
    # almost exclusively modern phones and tablets using MAC address rotation.
    if mac and not vendor_l and _is_locally_administered_mac(mac):
        return "mobile"

    # ── Open-port heuristics ──────────────────────────────────────────────────
    if 9100 in ports or "print" in vendor_l:
        return "printer"

    # ── Network device ────────────────────────────────────────────────────────
    if 80 in ports or 443 in ports or 8080 in ports:
        return "network_device"

    return "unknown"


# ─── Per-host enrichment helper ──────────────────────────────────────────────

def _enrich_and_classify(host: dict, extra_seed: dict | None = None) -> dict:
    """Run the full enrichment pipeline for a single host dict.

    Mutates *host* in-place: populates ``hostname``, ``vendor``,
    ``open_ports``, ``os_guess``, ``extra_info``, and ``device_type``.
    Returns the same *host* object for convenience (not a copy).

    Any pre-existing values (e.g. a hostname from Pi-hole or DHCP) are kept
    and only filled in when absent.

    *extra_seed* is an optional dict of already-collected enrichment data
    (e.g. SSDP UPnP fields or SSDP/mDNS/NetBIOS data from the scan loop)
    that is merged into ``extra_info`` before the ``device_type`` classifier
    runs.  If *host* already has an ``extra_info`` key, *extra_seed* is
    merged on top of it so neither source is lost.
    """
    ip = host["ip"]
    mac = host.get("mac", "")

    log.debug(
        "enrich_start",
        ip=ip,
        mac=mac,
        hostname=host.get("hostname"),
        vendor=host.get("vendor"),
    )

    host["hostname"] = host.get("hostname") or resolve_hostname(ip)
    host["vendor"] = host.get("vendor") or vendor_lookup(mac)

    scan_data = nmap_scan(ip)
    host.update(scan_data)

    extra_info: dict = host.get("extra_info") or {}
    if extra_seed:
        extra_info.update(extra_seed)

    banner_data = enrich_from_banners(ip, host.get("open_ports", []))
    if banner_data:
        extra_info.update(banner_data)
        if banner_data.get("tls_cn") and not host.get("hostname"):
            host["hostname"] = banner_data["tls_cn"]

    host["extra_info"] = extra_info

    ports_open = [p["port"] for p in host.get("open_ports", [])]
    log.debug(
        "enrich_scan_complete",
        ip=ip,
        hostname=host.get("hostname"),
        vendor=host.get("vendor"),
        open_ports=ports_open,
        os_guess=host.get("os_guess"),
        extra_info_keys=sorted(extra_info.keys()),
        dhcp_fingerprint=extra_info.get("dhcp_fingerprint"),
    )

    # ── RF classifier (primary) ───────────────────────────────────────────────
    # Try the RandomForest models first.  classify_device() returns a
    # (device_type, os_family, confidence) triple.  Both predictions share the
    # same feature vector and are only accepted above RF_MIN_CONFIDENCE.
    # The heuristic is used as a fallback when RF confidence is too low.
    dhcp_fp: str | None = extra_info.get("dhcp_fingerprint") or None
    rf_type: str = "unknown"
    rf_os: str = "unknown"
    rf_conf: float = 0.0
    if _dc is not None:
        rf_type, rf_os, rf_conf = _dc.classify_device(
            host.get("vendor"),
            host.get("open_ports", []),
            extra_info,
            dhcp_fingerprint=dhcp_fp,
        )
    else:
        log.debug("rf_classify_skipped", ip=ip, reason="classifier_not_loaded")

    if rf_type != "unknown":
        host["device_type"] = rf_type
        log.debug(
            "rf_classify_used",
            ip=ip, device_type=rf_type, os_family=rf_os, confidence=round(rf_conf, 3),
        )
    else:
        # Heuristic fallback — retains all the high-specificity rules
        # (mDNS service types, WSD, UPnP, SNMP, fingerbank result, etc.)
        log.debug(
            "rf_classify_fallback",
            ip=ip,
            reason="rf_type_unknown",
            rf_confidence=round(rf_conf, 3),
        )
        host["device_type"] = guess_device_type(
            host.get("vendor"), host.get("open_ports", []),
            host.get("os_guess"), extra_info, host.get("hostname"),
            mac=mac,
        )

    # Fill in os_guess from the RF os_family prediction when nmap did not
    # detect the OS (which is most of the time without a privileged scan).
    if rf_os not in ("unknown", "") and not host.get("os_guess"):
        host["os_guess"] = rf_os

    log.debug(
        "enrich_complete",
        ip=ip,
        device_type=host.get("device_type"),
        os_guess=host.get("os_guess"),
        hostname=host.get("hostname"),
        vendor=host.get("vendor"),
    )

    return host


# ─── Persistence ─────────────────────────────────────────────────────────────

def upsert_device(conn, rdb, device: dict) -> bool:
    """Insert or update a device record.  Returns True if the device is new.

    For brand-new IoT devices the function also calls :func:`start_iot_learning`
    to create a Pi-hole learning group and record the 48-hour observation
    session.  The ``iot_learning_started`` event published by that function
    replaces the standard ``new_device`` event for IoT devices so that the
    guardian service does not attempt to quarantine them.

    Duplicate-prevention: if no record exists for *device["mac"]* but the
    same IP already has a record whose MAC is the synthetic placeholder we
    generated earlier (``_synthetic_mac_for_ip``), that placeholder row is
    updated in-place with the now-known real MAC instead of creating a second
    row for the same physical device.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT id, status FROM devices WHERE mac_address = %s", (device["mac"],))
        row = cur.fetchone()

        if row is None:
            # Before inserting, check whether this IP already has a record
            # carrying our synthetic placeholder MAC.  If so, promote it to
            # the real MAC rather than adding a duplicate row.
            synthetic_mac = _synthetic_mac_for_ip(device["ip"])
            if device["mac"] != synthetic_mac:
                cur.execute(
                    "SELECT id, status FROM devices WHERE mac_address = %s",
                    (synthetic_mac,),
                )
                synthetic_row = cur.fetchone()
                if synthetic_row is not None:
                    # Replace the synthetic MAC with the real one.  Use only
                    # mac_address in the WHERE clause (it is UNIQUE) so the
                    # update succeeds even when the stored ip_address was
                    # changed by a concurrent scan/sniffer between the SELECT
                    # above and this UPDATE.
                    cur.execute(
                        """
                        UPDATE devices
                        SET mac_address=%s, ip_address=%s,
                            ipv6_address=COALESCE(%s, ipv6_address),
                            hostname=%s, vendor=%s, device_type=%s,
                            os_guess=%s, open_ports=%s, extra_info=%s,
                            last_seen=NOW()
                        WHERE mac_address=%s
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
                            synthetic_mac,
                        ),
                    )
                    if cur.rowcount > 0:
                        conn.commit()
                        log.info(
                            "synthetic_mac_replaced",
                            ip=device["ip"],
                            old_mac=synthetic_mac,
                            new_mac=device["mac"],
                            vendor=device.get("vendor"),
                        )
                        return False
                    # rowcount == 0 means the synthetic row was concurrently
                    # removed (e.g. promoted by another thread) between our
                    # SELECT and this UPDATE.  Fall through to a normal INSERT.
                    conn.rollback()
            else:
                # We are about to insert a synthetic-MAC placeholder.  Guard
                # against a race where a concurrent scan/sniffer has ALREADY
                # promoted this IP to a real MAC — we must not re-create a
                # stale synthetic row alongside the real one.
                cur.execute(
                    "SELECT id FROM devices WHERE ip_address = %s AND mac_address NOT LIKE '02:%%'",
                    (device["ip"],),
                )
                if cur.fetchone() is not None:
                    log.debug(
                        "synthetic_mac_skipped_real_exists",
                        ip=device["ip"],
                        mac=device["mac"],
                    )
                    return False

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


# ─── Continuous sniff processor ─────────────────────────────────────────────

def _process_ssdp_standalone(conn, rdb) -> int:
    """Run SSDP discovery and upsert newly found devices into the database.

    Sends UPnP/SSDP multicast probes and performs full enrichment (hostname,
    vendor, nmap, banner grab) for any responding IP that is not yet tracked.
    Called by :func:`_sniff_processor_loop` so that SSDP-discovered devices
    reach the database between full scan cycles.

    Returns the number of new devices added.
    """
    ssdp_data = ssdp_discover(timeout=SSDP_TIMEOUT)
    if not ssdp_data:
        return 0

    log.info("ssdp_standalone_process", candidates=len(ssdp_data))
    new_count = 0

    with conn.cursor() as cur:
        cur.execute(
            "SELECT ip_address FROM devices WHERE ip_address = ANY(%s)",
            (list(ssdp_data.keys()),),
        )
        known_ips: set[str] = {row["ip_address"] for row in cur.fetchall() if row["ip_address"]}

    for ip, ssdp_entry in ssdp_data.items():
        if ip in known_ips:
            continue

        mac = arp_resolve(ip)
        if not mac:
            log.debug("ssdp_standalone_no_mac", ip=ip)
            continue

        host: dict = {"ip": ip, "mac": mac}
        _enrich_and_classify(host, extra_seed=ssdp_entry)

        is_new = upsert_device(conn, rdb, host)
        if is_new:
            new_count += 1
            log.info("ssdp_standalone_new_device", ip=ip, mac=mac, vendor=host.get("vendor"))

    return new_count


def _process_mdns_standalone(conn) -> int:
    """Drain the mDNS/Zeroconf service queue and update device records.

    Processes mDNS service announcements captured by the Zeroconf
    :class:`ServiceBrowser` thread.  For each IP with pending mDNS data:

    - Updates the ``hostname`` column when the device exists but currently has
      no hostname.
    - Merges ``mdns_services``, ``mdns_hostname``, and TXT-record fields
      (``mdns_txt_model``, ``mdns_txt_type``, ``mdns_txt_friendly_name``) into
      ``extra_info``.

    Called by :func:`_sniff_processor_loop` so that mDNS enrichment is applied
    between full scan cycles rather than only when :func:`run_scan` executes.

    Returns the number of device rows updated.
    """
    mdns_data = process_mdns_queue()
    if not mdns_data:
        return 0

    log.info("mdns_standalone_process", candidates=len(mdns_data))
    updated = 0

    for ip, entry in mdns_data.items():
        hostname = entry.get("mdns_hostname")
        services = entry.get("mdns_services", [])
        extra_patch: dict = {"mdns_services": services}
        if hostname:
            extra_patch["mdns_hostname"] = hostname
        # Propagate TXT record fields so guess_device_type can use them.
        for txt_key in ("mdns_txt_model", "mdns_txt_type", "mdns_txt_friendly_name"):
            if entry.get(txt_key):
                extra_patch[txt_key] = entry[txt_key]

        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE devices
                SET hostname   = COALESCE(NULLIF(hostname, ''), %s),
                    extra_info = extra_info || %s::jsonb,
                    last_seen  = NOW()
                WHERE ip_address = %s
                """,
                (hostname, json.dumps(extra_patch), ip),
            )
        if cur.rowcount > 0:
            updated += 1
            log.info("mdns_standalone_hint_applied", ip=ip, hostname=hostname)

    conn.commit()
    return updated


def _process_wsd_standalone(conn, rdb) -> int:
    """Run WSD discovery and upsert newly found devices into the database.

    Sends a WS-Discovery Probe and performs full enrichment (hostname, vendor,
    nmap, banner grab) for any responding IP not yet tracked.  Called by
    :func:`_sniff_processor_loop` so that WSD-discovered devices reach the
    database between full scan cycles.

    Returns the number of new devices added.
    """
    wsd_data = wsd_discover(timeout=WSD_TIMEOUT)
    if not wsd_data:
        return 0

    log.info("wsd_standalone_process", candidates=len(wsd_data))
    new_count = 0

    with conn.cursor() as cur:
        cur.execute(
            "SELECT ip_address FROM devices WHERE ip_address = ANY(%s)",
            (list(wsd_data.keys()),),
        )
        known_ips: set[str] = {row["ip_address"] for row in cur.fetchall() if row["ip_address"]}

    for ip, wsd_entry in wsd_data.items():
        if ip in known_ips:
            continue

        mac = arp_resolve(ip)
        if not mac:
            log.debug("wsd_standalone_no_mac", ip=ip)
            continue

        host: dict = {"ip": ip, "mac": mac}
        _enrich_and_classify(host, extra_seed=wsd_entry)

        is_new = upsert_device(conn, rdb, host)
        if is_new:
            new_count += 1
            log.info("wsd_standalone_new_device", ip=ip, mac=mac, wsd_types=wsd_entry.get("wsd_types"))

    return new_count


def _sniff_processor_loop() -> None:
    """Background thread that continuously processes sniff queues.

    Drains the ARP, DNS, mDNS, and DHCP passive-sniff queues and runs SSDP,
    WSD, and mDNS/Zeroconf discovery at :data:`SNIFF_PROCESS_INTERVAL`-second
    intervals.  This ensures that devices detected via passive sniffing (DHCP
    offers, DNS queries, ARP broadcasts, mDNS announcements, SSDP/WSD responses)
    are written to the database promptly — without waiting for the next full
    ``SCAN_INTERVAL`` window.

    Runs as a daemon thread so it exits automatically when the main thread
    terminates.
    """
    log.info("sniff_processor_start", interval=SNIFF_PROCESS_INTERVAL)
    while True:
        time.sleep(SNIFF_PROCESS_INTERVAL)
        try:
            conn = get_db()
            rdb = get_redis()
            try:
                if ARP_SNIFF_ENABLED:
                    process_arp_sniff_queue(conn, rdb)
                if DNS_SNIFF_ENABLED:
                    process_dns_sniff_queue(conn, rdb)
                    process_mdns_sniff_queue(conn)
                if DHCP_SNIFF_ENABLED:
                    process_dhcp_sniff_queue(conn)
                if MDNS_ENABLED:
                    _process_mdns_standalone(conn)
                if SSDP_ENABLED:
                    _process_ssdp_standalone(conn, rdb)
                if WSD_ENABLED:
                    _process_wsd_standalone(conn, rdb)
            finally:
                conn.close()
        except Exception as exc:
            log.error("sniff_processor_error", error=str(exc))


# ─── Main scan loop ──────────────────────────────────────────────────────────

def run_scan():
    log.info("scan_cycle_start", networks=NETWORK_RANGES)
    conn = get_db()
    rdb = get_redis()

    try:
        # ── Cycle-level enrichment passes (run once per scan, not per host) ───────
        # SSDP/UPnP — send M-SEARCH multicast and fetch device descriptions.
        ssdp_data: dict[str, dict] = ssdp_discover(timeout=SSDP_TIMEOUT) if SSDP_ENABLED else {}

        # WSD/WS-Discovery — Windows PCs, printers, ONVIF cameras on port 3702.
        wsd_data: dict[str, dict] = wsd_discover(timeout=WSD_TIMEOUT) if WSD_ENABLED else {}

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

            # ── Step 4b: WSD — add any IPs only found via WS-Discovery ───────────
            for ip, wsd_entry in wsd_data.items():
                if ip not in host_by_ip:
                    host = {"ip": ip}
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

                # Merge WSD/WS-Discovery data for this host's IP.
                if host["ip"] in wsd_data:
                    extra_info.update(wsd_data[host["ip"]])

                # Merge mDNS data for this host's IP.
                if host["ip"] in mdns_data:
                    mdns_entry = mdns_data[host["ip"]]
                    extra_info["mdns_services"] = mdns_entry.get("mdns_services", [])
                    # Promote mDNS TXT model/type fields to top-level extra_info.
                    for txt_key in ("mdns_txt_model", "mdns_txt_type", "mdns_txt_friendly_name"):
                        if mdns_entry.get(txt_key):
                            extra_info[txt_key] = mdns_entry[txt_key]
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

                # nmap port/OS scan + banner/cert grab + device-type classification.
                # Pass the SSDP/mDNS/NetBIOS-merged dict as extra_seed so the
                # helper merges banner results on top of it before classifying.
                _enrich_and_classify(host, extra_seed=extra_info)

                is_new = upsert_device(conn, rdb, host)
                if is_new:
                    new_count += 1

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

    finally:
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
    apply_migrations(REQUIRED_MIGRATIONS)
    _load_settings()

    # Load the RF device-type classifier model (built at image build time by
    # train_classifier.py).  Failure is non-fatal: the heuristic takes over.
    if _dc is not None:
        _dc.load_classifier()

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

    # Start the continuous sniff-queue processor so that passively sniffed
    # devices (ARP, DNS, DHCP, mDNS, SSDP) are written to the database at
    # SNIFF_PROCESS_INTERVAL-second intervals rather than waiting for the next
    # full SCAN_INTERVAL window.
    threading.Thread(target=_sniff_processor_loop, name="sniff-processor", daemon=True).start()

    # Run once immediately, then on schedule
    run_scan()
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)

    while True:
        schedule.run_pending()
        time.sleep(10)


if __name__ == "__main__":
    main()
