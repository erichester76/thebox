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
"""

import json
import hashlib
import logging
import os
import queue
import socket
import threading
import time
from datetime import datetime, timezone

import nmap
import psycopg2
import psycopg2.extras
import redis
import requests
import schedule
import structlog
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from scapy.all import ARP, DNS, DNSQR, Ether, IP, UDP, srp, sniff  # noqa: F401

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
        # Skip placeholder / all-zero MACs
        if not hwaddr or hwaddr in ("00:00:00:00:00:00", ""):
            continue
        # Pi-hole v6: each IP entry carries its own name (hostname is per-IP)
        for ip_entry in entry.get("ips", []):
            ip_addr = ip_entry.get("ip") if isinstance(ip_entry, dict) else ip_entry
            hostname = (
                ip_entry.get("name") if isinstance(ip_entry, dict) else None
            ) or None
            if ip_addr:
                clients.append({"ip": ip_addr, "mac": hwaddr, "hostname": hostname})

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
        host["device_type"] = guess_device_type(
            host.get("vendor"), host.get("open_ports", []), host.get("os_guess")
        )

        is_new = upsert_device(conn, rdb, host)
        if is_new:
            new_count += 1
            log.info("dns_sniff_new_device", ip=ip, mac=mac, vendor=host.get("vendor"))

    return new_count


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


def guess_device_type(vendor: str | None, open_ports: list[dict], os_guess: str | None) -> str:
    """Heuristic device-type classifier."""
    vendor_l = (vendor or "").lower()
    os_l = (os_guess or "").lower()
    ports = {p["port"] for p in open_ports}

    iot_vendors = {"tuya", "espressif", "shelly", "philips", "sonos", "ring", "nest", "ecobee", "tp-link"}
    if any(v in vendor_l for v in iot_vendors):
        return "iot"
    if "windows" in os_l:
        return "desktop"
    if "linux" in os_l and 22 in ports:
        return "server"
    if "android" in os_l or "apple" in vendor_l:
        return "mobile"
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
                     open_ports, status, first_seen, last_seen)
                VALUES (%s,%s,%s,%s,%s,%s,%s,'new',NOW(),NOW())
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
                    os_guess=%s, open_ports=%s, last_seen=NOW()
                WHERE mac_address=%s
                """,
                (
                    device["ip"],
                    device.get("hostname"),
                    device.get("vendor"),
                    device.get("device_type", "unknown"),
                    device.get("os_guess"),
                    json.dumps(device.get("open_ports", [])),
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

    for network in NETWORK_RANGES:
        # Record scan start
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO scan_runs (network_range) VALUES (%s) RETURNING id",
                (network,),
            )
            scan_id = cur.fetchone()["id"]
        conn.commit()

        hosts = arp_sweep(network)
        if not hosts:
            log.info("arp_sweep_empty_nmap_fallback", network=network)
            hosts = nmap_ping_sweep(network)

        # Merge Pi-hole network clients so devices that answered Pi-hole DNS
        # queries (but didn't respond to ARP) are also discovered.
        pihole_clients = query_pihole_clients()
        if pihole_clients:
            host_by_ip = {h["ip"]: h for h in hosts}
            for client in pihole_clients:
                if client["ip"] not in host_by_ip:
                    hosts.append(client)
                    host_by_ip[client["ip"]] = client
                elif not host_by_ip[client["ip"]].get("mac"):
                    # Back-fill MAC from Pi-hole if ARP didn't capture it
                    host_by_ip[client["ip"]]["mac"] = client["mac"]
            log.info("pihole_merge_done", total_after_merge=len(hosts))

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
            # Enrich
            host["hostname"] = host.get("hostname") or resolve_hostname(host["ip"])
            host["vendor"] = host.get("vendor") or vendor_lookup(host["mac"])
            scan_data = nmap_scan(host["ip"])
            host.update(scan_data)
            host["device_type"] = guess_device_type(
                host.get("vendor"), host.get("open_ports", []), host.get("os_guess")
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

    # Start the background DNS-packet sniffer (requires NET_RAW capability).
    if DNS_SNIFF_ENABLED:
        start_dns_sniffer()
    else:
        log.info("dns_sniffer_disabled")

    # Run once immediately, then on schedule
    run_scan()
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)

    while True:
        schedule.run_pending()
        time.sleep(10)


if __name__ == "__main__":
    main()
