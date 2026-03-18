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

import json
import hashlib
import logging
import os
import queue
import re
import socket
import ssl
import threading
import time
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
from scapy.all import ARP, DNS, DNSQR, Ether, IP, UDP, srp, sniff  # noqa: F401
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

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, LOG_LEVEL, logging.INFO)),
)
log = structlog.get_logger()

# ─── MAC vendor lookup ───────────────────────────────────────────────────────
mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()
except Exception:
    log.warning("mac_vendor_update_failed", msg="Using cached vendor list")


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)


# ─── Schema bootstrap ────────────────────────────────────────────────────────

def ensure_schema():
    """Create tables this service reads from or writes to.

    Scoped to: ``users`` (FK dependency for devices), ``devices``,
    ``scan_runs``.  All DDL uses ``IF NOT EXISTS`` so this is safe to call
    on every startup.
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
        "CREATE INDEX IF NOT EXISTS idx_devices_mac    ON devices(mac_address)",
        "CREATE INDEX IF NOT EXISTS idx_devices_ip     ON devices(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)",
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


# ─── ARP sweep ───────────────────────────────────────────────────────────────

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


# ─── DNS packet sniffer ──────────────────────────────────────────────────────

# Background thread posts newly-seen source IPs into this queue so that the
# main scan loop can enrich and upsert them without racing with the sniffer.
# Queue is thread-safe: the sniffer thread calls put() and the main thread
# calls get_nowait() in process_dns_sniff_queue().  maxsize caps memory use
# in high-traffic environments; excess items are dropped silently.
_dns_sniff_queue: queue.Queue = queue.Queue(maxsize=10_000)


def _dns_packet_handler(pkt) -> None:
    """Scapy packet callback — enqueue the source IP of every DNS query."""
    try:
        if (
            pkt.haslayer(IP)
            and pkt.haslayer(UDP)
            and pkt.haslayer(DNS)
            and pkt[DNS].qr == 0  # query, not response
            and pkt.haslayer(DNSQR)
        ):
            try:
                _dns_sniff_queue.put_nowait(pkt[IP].src)
            except queue.Full:
                pass  # queue is bounded; drop the item rather than block
    except Exception as exc:
        log.debug("dns_packet_handler_error", error=str(exc))


def start_dns_sniffer() -> threading.Thread:
    """Start a daemon thread that sniffs DNS query packets.

    The thread runs ``scapy.sniff()`` with ``filter="udp port 53"`` so that
    every DNS query seen on the network interface triggers
    :func:`_dns_packet_handler`.  The thread is a daemon so it is
    automatically cleaned up when the main process exits.

    Returns the :class:`threading.Thread` object (already started).
    """
    def _loop() -> None:
        log.info("dns_sniffer_start", iface=DNS_SNIFF_IFACE or "auto")
        try:
            sniff(
                filter="udp port 53",
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
            host.get("vendor"), host.get("open_ports", []), host.get("os_guess"), extra_info
        )

        is_new = upsert_device(conn, rdb, host)
        if is_new:
            new_count += 1
            log.info("dns_sniff_new_device", ip=ip, mac=mac, vendor=host.get("vendor"))

    return new_count


# ─── SSDP / UPnP discovery ───────────────────────────────────────────────────

_SSDP_MULTICAST_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_SSDP_MX = 3


def _xml_text(element, tag: str, ns: dict) -> str | None:
    """Return the text of a child XML element, or None if absent."""
    child = element.find(tag, ns)
    return child.text.strip() if child is not None and child.text else None


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

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(msg, (_SSDP_MULTICAST_ADDR, _SSDP_PORT))
    except Exception as exc:
        log.warning("ssdp_send_error", error=str(exc))
        return {}

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
    try:
        return mac_lookup.lookup(mac)
    except VendorNotFoundError:
        return None
    except Exception:
        return None


def guess_device_type(vendor: str | None, open_ports: list[dict], os_guess: str | None, extra_info: dict | None = None) -> str:
    """Heuristic device-type classifier.

    Uses MAC vendor string, nmap OS fingerprint, open port set, mDNS service
    types, and UPnP device type to produce a best-effort device category.
    """
    vendor_l = (vendor or "").lower()
    os_l = (os_guess or "").lower()
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

    # ── MAC vendor heuristics ─────────────────────────────────────────────────
    iot_vendors = {"tuya", "espressif", "shelly", "philips", "sonos", "ring", "nest", "ecobee", "tp-link"}
    if any(v in vendor_l for v in iot_vendors):
        return "iot"

    # ── OS fingerprint heuristics ─────────────────────────────────────────────
    if "windows" in os_l:
        return "desktop"
    if "linux" in os_l and 22 in ports:
        return "server"
    if "android" in os_l or "apple" in vendor_l:
        return "mobile"

    # ── Open-port heuristics ──────────────────────────────────────────────────
    if 9100 in ports or "print" in vendor_l:
        return "printer"
    if 80 in ports or 443 in ports or 8080 in ports:
        return "network_device"
    return "unknown"


# ─── Persistence ─────────────────────────────────────────────────────────────

def upsert_device(conn, rdb, device: dict) -> bool:
    """Insert or update a device record.  Returns True if the device is new."""
    with conn.cursor() as cur:
        cur.execute("SELECT id, status FROM devices WHERE mac_address = %s", (device["mac"],))
        row = cur.fetchone()

        if row is None:
            cur.execute(
                """
                INSERT INTO devices
                    (mac_address, ip_address, hostname, vendor, device_type, os_guess,
                     open_ports, extra_info, status, first_seen, last_seen)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'new',NOW(),NOW())
                RETURNING id
                """,
                (
                    device["mac"],
                    device["ip"],
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

            # Publish event so guardian / dashboard react immediately
            rdb.publish(
                "thebox:events",
                json.dumps(
                    {
                        "type": "new_device",
                        "device_id": device_id,
                        "mac": device["mac"],
                        "ip": device["ip"],
                        "vendor": device.get("vendor"),
                        "device_type": device.get("device_type", "unknown"),
                        "ts": datetime.now(timezone.utc).isoformat(),
                    }
                ),
            )
            return True
        else:
            cur.execute(
                """
                UPDATE devices
                SET ip_address=%s, hostname=%s, vendor=%s, device_type=%s,
                    os_guess=%s, open_ports=%s, extra_info=%s, last_seen=NOW()
                WHERE mac_address=%s
                """,
                (
                    device["ip"],
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
                host.get("vendor"), host.get("open_ports", []), host.get("os_guess"), extra_info
            )

            is_new = upsert_device(conn, rdb, host)
            if is_new:
                new_count += 1

        # Process any devices discovered via DNS packet sniffing since the
        # last scan cycle.
        if DNS_SNIFF_ENABLED:
            new_count += process_dns_sniff_queue(conn, rdb)

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


def main():
    log.info("discovery_service_start", networks=NETWORK_RANGES, interval=SCAN_INTERVAL)

    ensure_schema()

    # Start the background DNS-packet sniffer (requires NET_RAW capability).
    if DNS_SNIFF_ENABLED:
        start_dns_sniffer()
    else:
        log.info("dns_sniffer_disabled")

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
