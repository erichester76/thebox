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
from datetime import datetime, timedelta, timezone

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

# IoT learning period
IOT_LEARNING_HOURS = int(os.environ.get("IOT_LEARNING_HOURS", "48"))
PIHOLE_IOT_GROUP = os.environ.get("PIHOLE_IOT_GROUP", "iot")

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
    gid = (data.get("group") or {}).get("id")
    if gid is None:
        log.warning("pihole_group_create_failed", name=name)
    else:
        log.info("pihole_group_created", name=name, id=gid)
    return gid


def pihole_delete_group(sid: str, name: str) -> None:
    """Delete a Pi-hole group by name (best-effort; errors are logged only)."""
    _pihole_request("DELETE", f"/groups/{name}", sid)
    log.info("pihole_group_deleted", name=name)


def pihole_assign_client_to_groups(sid: str, client_ip: str, group_ids: list[int]) -> bool:
    """Assign a Pi-hole client (by IP address) to a set of groups.

    Tries to update an existing client first; creates a new client record if
    the update returns no ``client`` key (which Pi-hole does for unknown IPs).
    Returns True when the assignment succeeded.
    """
    body = {"groups": group_ids, "comment": "IoT device managed by TheBox"}
    data = _pihole_request("PUT", f"/clients/{client_ip}", sid, json=body)
    if "client" in data:
        return True

    # Client doesn't exist yet — create it
    create_body = {"client": client_ip, "comment": "IoT device managed by TheBox", "groups": group_ids}
    data = _pihole_request("POST", "/clients", sid, json=create_body)
    if "client" not in data:
        log.warning("pihole_client_assign_failed", ip=client_ip, groups=group_ids)
        return False
    return True


def pihole_get_queries_for_client(
    sid: str, client_ip: str, from_ts: float, until_ts: float
) -> list[str]:
    """Return all unique DNS query domains recorded for *client_ip* in the given time window.

    Iterates through paginated results using the ``cursor`` field returned by
    the Pi-hole v6 queries API.  Stops when Pi-hole returns an empty page or
    no cursor.
    """
    domains: set[str] = set()
    cursor: str | None = None

    while True:
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
        for q in page:
            domain = q.get("domain")
            if domain:
                domains.add(domain)

        cursor = data.get("cursor")
        if not cursor or not page:
            break

    log.info("pihole_queries_fetched", client=client_ip, count=len(domains))
    return list(domains)


def pihole_add_domain_to_allowlist(sid: str, domain: str, group_ids: list[int]) -> bool:
    """Add *domain* to the Pi-hole exact allow-list and assign it to *group_ids*.

    If the domain already exists on the allow-list the call is a no-op
    (Pi-hole returns the existing entry).  Returns True on success.
    """
    body = {"domain": domain, "comment": "IoT learned domain", "groups": group_ids, "enabled": True}
    data = _pihole_request("POST", "/domains/allow/exact", sid, json=body)
    return "domain" in data


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

            # ── 1. Collect DNS queries from Pi-hole ──────────────────────────
            domains: list[str] = []
            if sid:
                from_ts = started_at.timestamp()
                until_ts = datetime.now(timezone.utc).timestamp()
                domains = pihole_get_queries_for_client(sid, ip, from_ts, until_ts)
                log.info("iot_learning_domains_found", device_id=device_id, ip=ip, count=len(domains))

            # ── 2. Store FQDNs in iot_allowlist as global entries ────────────
            if domains:
                with conn.cursor() as cur:
                    for fqdn in domains:
                        cur.execute(
                            """
                            INSERT INTO iot_allowlist (device_id, fqdn)
                            VALUES (NULL, %s)
                            ON CONFLICT (fqdn) WHERE device_id IS NULL DO NOTHING
                            """,
                            (fqdn,),
                        )
                conn.commit()

                # ── 3. Add domains to Pi-hole allow-list for the iot group ───
                if sid and iot_group_id is not None:
                    for fqdn in domains:
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


def main():
    log.info(
        "discovery_service_start",
        networks=NETWORK_RANGES,
        interval=SCAN_INTERVAL,
        iot_learning_hours=IOT_LEARNING_HOURS,
        pihole_iot_group=PIHOLE_IOT_GROUP,
    )

    ensure_schema()

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
