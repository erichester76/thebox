"""
TheBox — Redirector Service
===========================
Redirects DNS and DHCP traffic to TheBox/Pi-hole using increasingly
intrusive methods, and enforces device quarantine via ARP spoofing.

Redirect modes (REDIRECT_MODE env var, comma-separated list):
  passive          — Monitor only; no active redirection (default, least
                     intrusive).
  redirect_dns     — Install iptables DNAT rules so that any DNS query
                     arriving on this host is forwarded to Pi-hole.  Requires
                     TheBox to already be in the traffic path (e.g. as the
                     default gateway).
  arp_spoof        — Periodically send gratuitous ARP replies to all LAN
                     hosts telling them that TheBox's MAC is the default
                     gateway.  Enables interception of DNS traffic without
                     requiring devices to be reconfigured.
  dhcp_advertise   — Listen for DHCP discover/request packets and inject
                     offers/acks that advertise TheBox/Pi-hole as the DNS
                     server.  Works alongside the upstream DHCP server.
  dhcp_starvation  — Exhaust the upstream DHCP pool with fabricated discover
                     packets so that devices fall back to TheBox as their DHCP
                     server.  WARNING: highly disruptive — use only when
                     TheBox is intended to be the sole DHCP server.
  gateway_takeover — ARP-spoof every active LAN host *and* the upstream
                     router simultaneously so that all IP traffic flows
                     through TheBox for inspection / filtering (most
                     intrusive).

Quarantine enforcement:
  Listens on the shared Redis event bus for ``quarantine_device`` /
  ``unquarantine_device`` events published by the guardian service and
  ARP-spoofs the named device so that its traffic is intercepted.  When
  BLACKHOLE_QUARANTINED=true, additional iptables rules drop the spoofed
  traffic (except DHCP and DNS so the device can still request an address
  and receive a block-page response).
"""

import json
import logging
import os
import random
import subprocess
import threading
import time

import psycopg2
import psycopg2.extras
import redis
import schedule
import structlog
from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    Ether,
    IP,
    UDP,
    get_if_addr,
    get_if_hwaddr,
    sendp,
    sniff,
    srp,
)

# ─── Configuration ───────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# Comma-separated list of active redirect modes
REDIRECT_MODE_RAW = os.environ.get("REDIRECT_MODE", "passive")
REDIRECT_MODES: set[str] = {m.strip().lower() for m in REDIRECT_MODE_RAW.split(",") if m.strip()}

NETWORK_INTERFACE = os.environ.get("NETWORK_INTERFACE", "eth0")
# Auto-detected from the kernel routing table if not supplied
GATEWAY_IP = os.environ.get("GATEWAY_IP", "")
NETWORK_RANGES = [r.strip() for r in os.environ.get("NETWORK_RANGES", "192.168.1.0/24").split(",")]
# Pi-hole IP — falls back to BOX_IP / own interface address
PIHOLE_IP = os.environ.get("PIHOLE_IP", "")
BOX_IP = os.environ.get("BOX_IP", "")

# When True, iptables rules are added to drop all quarantined-device traffic
# except DHCP (udp/67-68) and DNS (udp+tcp/53).
BLACKHOLE_QUARANTINED = os.environ.get("BLACKHOLE_QUARANTINED", "false").lower() == "true"
# Seconds between ARP refresh packets
ARP_REFRESH_INTERVAL = int(os.environ.get("ARP_REFRESH_INTERVAL", "10"))

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, LOG_LEVEL, logging.INFO)),
)
log = structlog.get_logger()


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)


# ─── Network helpers ─────────────────────────────────────────────────────────

def get_own_ip() -> str:
    """Return the primary IP address of NETWORK_INTERFACE."""
    try:
        return get_if_addr(NETWORK_INTERFACE)
    except Exception as exc:
        log.warning("get_own_ip_failed", iface=NETWORK_INTERFACE, error=str(exc))
        return ""


def get_own_mac() -> str:
    """Return the MAC address of NETWORK_INTERFACE."""
    try:
        return get_if_hwaddr(NETWORK_INTERFACE)
    except Exception as exc:
        log.warning("get_own_mac_failed", iface=NETWORK_INTERFACE, error=str(exc))
        return "00:00:00:00:00:00"


def detect_gateway() -> str:
    """Parse the kernel routing table to find the default gateway IP."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, check=True,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    except Exception as exc:
        log.warning("gateway_detection_failed", error=str(exc))
    return ""


def get_mac_for_ip(ip: str) -> str:
    """Send an ARP request for *ip* and return its MAC, or '' on failure."""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(pkt, timeout=2, verbose=False, iface=NETWORK_INTERFACE)
        if answered:
            return answered[0][1].hwsrc
    except Exception as exc:
        log.warning("arp_request_failed", ip=ip, error=str(exc))
    return ""


def run_cmd(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        log.warning("cmd_failed", cmd=" ".join(args), stderr=result.stderr.strip())
    return result


# ─── Database helpers ────────────────────────────────────────────────────────

def ensure_schema():
    """Create tables this service reads from or writes to.

    Scoped to: ``redirect_events``, ``alerts``.  All DDL uses
    ``IF NOT EXISTS`` so this is safe to call on every startup.
    """
    statements = [
        # redirect_events — redirector writes every ARP-spoof / DNS-redirect action
        """CREATE TABLE IF NOT EXISTS redirect_events (
            id          SERIAL PRIMARY KEY,
            action      VARCHAR(64)  NOT NULL,
            target_ip   VARCHAR(45)  NOT NULL,
            target_mac  VARCHAR(17),
            mode        VARCHAR(64)  NOT NULL,
            detail      TEXT,
            device_id   INTEGER REFERENCES devices(id),
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        # alerts — redirector writes quarantine-start / stop alerts
        """CREATE TABLE IF NOT EXISTS alerts (
            id           SERIAL PRIMARY KEY,
            source       VARCHAR(64) NOT NULL,
            level        VARCHAR(16) NOT NULL DEFAULT 'info',
            title        VARCHAR(255) NOT NULL,
            detail       TEXT,
            device_id    INTEGER REFERENCES devices(id),
            acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS idx_redirect_target_ip ON redirect_events(target_ip)",
        "CREATE INDEX IF NOT EXISTS idx_redirect_created   ON redirect_events(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_level       ON alerts(level)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created     ON alerts(created_at)",
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
    """Return the current value for *key* from the settings table."""
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
    """Read redirector settings from the database, falling back to env vars."""
    global REDIRECT_MODES, NETWORK_INTERFACE, GATEWAY_IP, NETWORK_RANGES
    global PIHOLE_IP, BOX_IP, BLACKHOLE_QUARANTINED, ARP_REFRESH_INTERVAL

    raw_mode = get_setting("REDIRECT_MODE", ",".join(REDIRECT_MODES) or "passive")
    REDIRECT_MODES    = {m.strip().lower() for m in raw_mode.split(",") if m.strip()}
    NETWORK_INTERFACE = get_setting("NETWORK_INTERFACE", NETWORK_INTERFACE)
    GATEWAY_IP        = get_setting("GATEWAY_IP", GATEWAY_IP)
    NETWORK_RANGES    = [r.strip() for r in get_setting("NETWORK_RANGES", ",".join(NETWORK_RANGES)).split(",") if r.strip()]
    PIHOLE_IP         = get_setting("PIHOLE_IP", PIHOLE_IP)
    BOX_IP            = get_setting("BOX_IP", BOX_IP)
    BLACKHOLE_QUARANTINED = get_setting("BLACKHOLE_QUARANTINED", str(BLACKHOLE_QUARANTINED).lower()).lower() == "true"
    ARP_REFRESH_INTERVAL  = int(get_setting("ARP_REFRESH_INTERVAL", str(ARP_REFRESH_INTERVAL)))
    log.info("settings_loaded", redirect_modes=sorted(REDIRECT_MODES))


def log_redirect_event(
    conn,
    action: str,
    target_ip: str,
    target_mac: str | None,
    mode: str,
    detail: str | None = None,
):
    """Persist a redirection action in the redirect_events table."""
    device_id = None
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM devices WHERE ip_address=%s LIMIT 1", (target_ip,))
        row = cur.fetchone()
        if row:
            device_id = row["id"]

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO redirect_events
                (action, target_ip, target_mac, mode, detail, device_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (action, target_ip, target_mac, mode, detail, device_id),
        )
    conn.commit()


def create_alert(
    conn,
    source: str,
    level: str,
    title: str,
    detail: str,
    device_id: int | None = None,
):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO alerts (source, level, title, detail, device_id) VALUES (%s,%s,%s,%s,%s)",
            (source, level, title, detail, device_id),
        )
    conn.commit()


# ─── ARP helpers ─────────────────────────────────────────────────────────────

def arp_spoof(target_ip: str, spoof_ip: str, target_mac: str | None = None):
    """
    Send an ARP reply to *target_ip* claiming that *spoof_ip* maps to our MAC.
    If *target_mac* is None a broadcast Ethernet destination is used.
    """
    own_mac = get_own_mac()
    dst_mac = target_mac or "ff:ff:ff:ff:ff:ff"
    pkt = Ether(dst=dst_mac) / ARP(
        op=2,           # is-at (reply)
        pdst=target_ip,
        hwdst=dst_mac,
        psrc=spoof_ip,
        hwsrc=own_mac,
    )
    sendp(pkt, iface=NETWORK_INTERFACE, verbose=False)


def restore_arp(
    target_ip: str,
    spoof_ip: str,
    real_mac: str,
    target_mac: str | None = None,
):
    """Send a corrective ARP reply that restores *real_mac* for *spoof_ip*."""
    dst_mac = target_mac or "ff:ff:ff:ff:ff:ff"
    pkt = Ether(dst=dst_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=dst_mac,
        psrc=spoof_ip,
        hwsrc=real_mac,
    )
    sendp(pkt, iface=NETWORK_INTERFACE, verbose=False)
    log.info("arp_restored", target_ip=target_ip, spoof_ip=spoof_ip, real_mac=real_mac)


# ─── Per-device quarantine enforcement ───────────────────────────────────────

# Mapping of quarantined IP → state dict (mac, gateway_ip, gateway_mac)
_quarantine_targets: dict[str, dict] = {}
_quarantine_lock = threading.Lock()


def _quarantine_spoof_loop(
    target_ip: str,
    target_mac: str,
    gateway_ip: str,
    gateway_mac: str,
):
    """Continuously ARP-spoof a quarantined device until it is released."""
    log.info("quarantine_spoof_start", ip=target_ip)
    while True:
        with _quarantine_lock:
            if target_ip not in _quarantine_targets:
                break
        # Poison victim's ARP cache: gateway → TheBox
        arp_spoof(target_ip, gateway_ip, target_mac)
        # Poison gateway's ARP cache: victim → TheBox
        if gateway_ip and gateway_mac:
            arp_spoof(gateway_ip, target_ip, gateway_mac)
        time.sleep(ARP_REFRESH_INTERVAL)

    # Restore real ARP mappings when released
    if gateway_ip and gateway_mac:
        restore_arp(target_ip, gateway_ip, gateway_mac, target_mac)
        restore_arp(gateway_ip, target_ip, target_mac, gateway_mac)
    log.info("quarantine_spoof_stop", ip=target_ip)


def start_quarantine(ip: str, mac: str | None, gateway_ip: str, gateway_mac: str):
    """Begin ARP-spoofing a quarantined device and optionally blackhole it."""
    with _quarantine_lock:
        if ip in _quarantine_targets:
            return  # already active

        resolved_mac = mac or get_mac_for_ip(ip)
        if not resolved_mac:
            log.warning("quarantine_no_mac", ip=ip)
            return

        if BLACKHOLE_QUARANTINED:
            _setup_blackhole_iptables(ip)

        entry: dict = {
            "mac": resolved_mac,
            "gateway_ip": gateway_ip,
            "gateway_mac": gateway_mac,
        }
        t = threading.Thread(
            target=_quarantine_spoof_loop,
            args=(ip, resolved_mac, gateway_ip, gateway_mac),
            daemon=True,
        )
        entry["thread"] = t
        _quarantine_targets[ip] = entry
        t.start()

    log.info("quarantine_started", ip=ip, mac=resolved_mac, blackhole=BLACKHOLE_QUARANTINED)
    try:
        conn = get_db()
        log_redirect_event(
            conn, "quarantine_start", ip, resolved_mac, "arp_spoof",
            f"gateway_ip={gateway_ip} blackhole={BLACKHOLE_QUARANTINED}",
        )
        create_alert(
            conn, "redirector", "warning",
            f"Device quarantined via ARP spoof: {ip}",
            f"IP: {ip}  MAC: {resolved_mac}  Gateway: {gateway_ip}\n"
            f"Blackhole: {BLACKHOLE_QUARANTINED}",
        )
        conn.close()
    except Exception as exc:
        log.error("db_log_failed", error=str(exc))


def stop_quarantine(ip: str):
    """Release a device from ARP-spoof quarantine."""
    with _quarantine_lock:
        if ip not in _quarantine_targets:
            return
        del _quarantine_targets[ip]  # spoof loop checks this and stops

    if BLACKHOLE_QUARANTINED:
        _teardown_blackhole_iptables(ip)

    log.info("quarantine_released", ip=ip)
    try:
        conn = get_db()
        log_redirect_event(conn, "quarantine_stop", ip, None, "arp_spoof")
        conn.close()
    except Exception as exc:
        log.error("db_log_failed", error=str(exc))


def _setup_blackhole_iptables(ip: str):
    """Insert iptables rules that drop all traffic from *ip* except DHCP/DNS."""
    rules = [
        # Allow DNS (UDP + TCP)
        ["iptables", "-I", "FORWARD", "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        ["iptables", "-I", "FORWARD", "-s", ip, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
        # Allow DHCP discover/request
        ["iptables", "-I", "FORWARD", "-s", ip, "-p", "udp", "--dport", "67", "-j", "ACCEPT"],
        # Drop everything else
        ["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"],
    ]
    for rule in rules:
        run_cmd(rule)
    log.info("blackhole_iptables_set", ip=ip)


def _teardown_blackhole_iptables(ip: str):
    """Remove the blackhole iptables rules for *ip*."""
    rules = [
        ["iptables", "-D", "FORWARD", "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-s", ip, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-s", ip, "-p", "udp", "--dport", "67", "-j", "ACCEPT"],
        ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
    ]
    for rule in rules:
        run_cmd(rule, check=False)
    log.info("blackhole_iptables_removed", ip=ip)


# ─── redirect_dns mode ───────────────────────────────────────────────────────

def setup_dns_redirect(pihole_ip: str):
    """
    Install iptables DNAT rules that forward all DNS traffic (port 53 UDP/TCP)
    arriving at this host to Pi-hole.  This is effective when TheBox is
    already the default gateway for LAN devices.
    """
    log.info("redirect_dns_setup", pihole_ip=pihole_ip)
    rules = [
        # Redirect incoming DNS UDP queries to Pi-hole
        ["iptables", "-t", "nat", "-I", "PREROUTING",
         "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", f"{pihole_ip}:53"],
        # Redirect incoming DNS TCP queries to Pi-hole
        ["iptables", "-t", "nat", "-I", "PREROUTING",
         "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", f"{pihole_ip}:53"],
        # Allow the forwarded DNS traffic
        ["iptables", "-I", "FORWARD", "-p", "udp", "--dport", "53", "-d", pihole_ip, "-j", "ACCEPT"],
        ["iptables", "-I", "FORWARD", "-p", "tcp", "--dport", "53", "-d", pihole_ip, "-j", "ACCEPT"],
    ]
    for rule in rules:
        # Idempotent: skip if rule already exists
        check_args = list(rule)
        check_args[2] = "-C"
        chk = run_cmd(check_args, check=False)
        if chk.returncode != 0:
            run_cmd(rule)
    log.info("redirect_dns_rules_installed", pihole_ip=pihole_ip)


# ─── arp_spoof mode ──────────────────────────────────────────────────────────

def run_arp_spoof_mode(gateway_ip: str, pihole_ip: str):
    """
    Periodically scan the LAN and send ARP replies to every active host
    telling them that TheBox's MAC is the default gateway.  This intercepts
    DNS/DHCP traffic without requiring any device configuration changes.
    """
    log.info("arp_spoof_mode_start", gateway_ip=gateway_ip, pihole_ip=pihole_ip)

    def _loop():
        while True:
            try:
                own_ip = BOX_IP or get_own_ip()
                for network in NETWORK_RANGES:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
                    answered, _ = srp(pkt, timeout=2, verbose=False, iface=NETWORK_INTERFACE)
                    for _, rcv in answered:
                        victim_ip = rcv.psrc
                        victim_mac = rcv.hwsrc
                        if victim_ip in (own_ip, gateway_ip):
                            continue
                        # Tell victim: TheBox is the gateway
                        arp_spoof(victim_ip, gateway_ip, victim_mac)
            except Exception as exc:
                log.error("arp_spoof_loop_error", error=str(exc))
            time.sleep(ARP_REFRESH_INTERVAL)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t


# ─── gateway_takeover mode ───────────────────────────────────────────────────

def run_gateway_takeover_mode(gateway_ip: str, gateway_mac: str):
    """
    ARP-spoof every active LAN host *and* the upstream router simultaneously
    so that all IP traffic is forwarded through TheBox (full MitM).
    IP forwarding must be enabled (handled in main()).
    """
    log.info("gateway_takeover_mode_start", gateway_ip=gateway_ip)

    def _loop():
        while True:
            try:
                own_ip = BOX_IP or get_own_ip()
                for network in NETWORK_RANGES:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
                    answered, _ = srp(pkt, timeout=2, verbose=False, iface=NETWORK_INTERFACE)
                    for _, rcv in answered:
                        victim_ip = rcv.psrc
                        victim_mac = rcv.hwsrc
                        if victim_ip in (own_ip, gateway_ip):
                            continue
                        # Tell victim: TheBox is the gateway
                        arp_spoof(victim_ip, gateway_ip, victim_mac)
                        # Tell gateway: TheBox is the victim
                        if gateway_mac:
                            arp_spoof(gateway_ip, victim_ip, gateway_mac)
            except Exception as exc:
                log.error("gateway_takeover_loop_error", error=str(exc))
            time.sleep(ARP_REFRESH_INTERVAL)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t


# ─── dhcp_advertise mode ─────────────────────────────────────────────────────

def _build_dhcp_offer(
    xid: int, client_mac: str, offered_ip: str, server_ip: str, dns_ip: str
) -> Ether:
    """Build a DHCP Offer packet advertising *dns_ip* as the DNS server."""
    chaddr = bytes.fromhex(client_mac.replace(":", ""))
    return (
        Ether(dst=client_mac)
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=offered_ip, siaddr=server_ip, xid=xid, chaddr=chaddr)
        / DHCP(options=[
            ("message-type", "offer"),
            ("server_id", server_ip),
            ("lease_time", 86400),
            ("subnet_mask", "255.255.255.0"),
            ("router", server_ip),
            ("name_server", dns_ip),
            "end",
        ])
    )


def _build_dhcp_ack(
    xid: int, client_mac: str, offered_ip: str, server_ip: str, dns_ip: str
) -> Ether:
    """Build a DHCP ACK packet."""
    chaddr = bytes.fromhex(client_mac.replace(":", ""))
    return (
        Ether(dst=client_mac)
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=offered_ip, siaddr=server_ip, xid=xid, chaddr=chaddr)
        / DHCP(options=[
            ("message-type", "ack"),
            ("server_id", server_ip),
            ("lease_time", 86400),
            ("subnet_mask", "255.255.255.0"),
            ("router", server_ip),
            ("name_server", dns_ip),
            "end",
        ])
    )


def run_dhcp_advertise_mode(own_ip: str, pihole_ip: str):
    """
    Sniff for DHCP Discover/Request packets and inject Offer/ACK responses
    that advertise Pi-hole as the DNS server.
    """
    log.info("dhcp_advertise_mode_start", own_ip=own_ip, dns=pihole_ip)
    dns_ip = pihole_ip or own_ip
    # mac → assigned_ip mapping (simple in-memory state)
    _leases: dict[str, str] = {}

    def _handle_dhcp(pkt):
        if not pkt.haslayer(DHCP):
            return
        dhcp_opts = {k: v for k, v in pkt[DHCP].options if isinstance(k, str)}
        msg_type = dhcp_opts.get("message-type")
        if msg_type not in (1, 3):  # 1 = Discover, 3 = Request
            return

        client_mac = pkt[Ether].src
        xid = pkt[BOOTP].xid

        # Assign a simple /24 address if we haven't seen this client before
        if client_mac not in _leases:
            suffix = random.randint(100, 200)
            base = ".".join(own_ip.split(".")[:3])
            _leases[client_mac] = f"{base}.{suffix}"
        offered_ip = _leases[client_mac]

        if msg_type == 1:   # Discover → Offer
            reply = _build_dhcp_offer(xid, client_mac, offered_ip, own_ip, dns_ip)
            sendp(reply, iface=NETWORK_INTERFACE, verbose=False)
            log.info("dhcp_offer_sent", client_mac=client_mac, offered_ip=offered_ip, dns=dns_ip)
        elif msg_type == 3:  # Request → ACK
            reply = _build_dhcp_ack(xid, client_mac, offered_ip, own_ip, dns_ip)
            sendp(reply, iface=NETWORK_INTERFACE, verbose=False)
            log.info("dhcp_ack_sent", client_mac=client_mac, offered_ip=offered_ip, dns=dns_ip)

    def _sniff():
        sniff(
            iface=NETWORK_INTERFACE,
            filter="udp and (port 67 or port 68)",
            prn=_handle_dhcp,
            store=False,
        )

    t = threading.Thread(target=_sniff, daemon=True)
    t.start()
    return t


# ─── dhcp_starvation mode ────────────────────────────────────────────────────

def run_dhcp_starvation_mode(burst_size: int = 256, interval: int = 30):
    """
    Flood the upstream DHCP server with discover packets using randomised
    source MACs in order to exhaust its lease pool.  Once the pool is full,
    new devices will receive no offer from the upstream server and will fall
    back to TheBox's DHCP (dhcp_advertise mode).

    WARNING: This is highly disruptive and should only be used when TheBox
    is the intended DHCP server for the network.
    """
    log.warning(
        "dhcp_starvation_mode_start",
        burst_size=burst_size,
        interval_s=interval,
        msg="DHCP starvation is disruptive — ensure TheBox is the intended DHCP server",
    )

    def _burst():
        for _ in range(burst_size):
            rand_mac = ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))
            chaddr = bytes.fromhex(rand_mac.replace(":", ""))
            pkt = (
                Ether(src=rand_mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src="0.0.0.0", dst="255.255.255.255")
                / UDP(sport=68, dport=67)
                / BOOTP(op=1, chaddr=chaddr, xid=random.randint(1, 0xFFFFFFFF))
                / DHCP(options=[("message-type", "discover"), "end"])
            )
            sendp(pkt, iface=NETWORK_INTERFACE, verbose=False)
        log.info("dhcp_starvation_burst_sent", count=burst_size)

    def _loop():
        while True:
            try:
                _burst()
            except Exception as exc:
                log.error("dhcp_starvation_error", error=str(exc))
            time.sleep(interval)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t


# ─── Redis event subscriber ──────────────────────────────────────────────────

def subscribe_loop(gateway_ip: str, gateway_mac: str):
    """
    Subscribe to the shared Redis event bus and react to quarantine /
    unquarantine events published by the guardian service.
    """
    rdb = get_redis()
    pubsub = rdb.pubsub()
    pubsub.subscribe("thebox:events")
    log.info("subscribed_to_events")

    for message in pubsub.listen():
        if message["type"] != "message":
            continue
        try:
            event = json.loads(message["data"])
            etype = event.get("type")
            if etype == "quarantine_device":
                ip = event.get("ip")
                mac = event.get("mac")
                if ip:
                    start_quarantine(ip, mac, gateway_ip, gateway_mac)
            elif etype == "unquarantine_device":
                ip = event.get("ip")
                if ip:
                    stop_quarantine(ip)
        except Exception as exc:
            log.error("event_handling_error", error=str(exc))


# ─── Periodic quarantine re-sync ─────────────────────────────────────────────

def sync_quarantine_targets(gateway_ip: str, gateway_mac: str):
    """
    Query the database for quarantined devices and ensure each one has an
    active ARP-spoof loop running.  Handles restarts and missed events.
    """
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ip_address, mac_address FROM devices WHERE status='quarantined'"
            )
            rows = cur.fetchall()
        conn.close()
        for row in rows:
            ip = row["ip_address"]
            mac = row["mac_address"]
            if ip and mac and ip not in _quarantine_targets:
                start_quarantine(ip, mac, gateway_ip, gateway_mac)
    except Exception as exc:
        log.error("quarantine_sync_error", error=str(exc))


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    ensure_schema()
    _load_settings()

    log.info("redirector_service_start", modes=sorted(REDIRECT_MODES))

    # Resolve network identity
    own_ip = BOX_IP or get_own_ip()
    gateway_ip = GATEWAY_IP or detect_gateway()
    gateway_mac = get_mac_for_ip(gateway_ip) if gateway_ip else ""
    pihole_ip = PIHOLE_IP or own_ip  # Pi-hole typically runs on TheBox itself

    log.info(
        "network_identity",
        own_ip=own_ip,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        pihole_ip=pihole_ip,
        iface=NETWORK_INTERFACE,
    )

    # IP forwarding is required for MitM / gateway modes
    if REDIRECT_MODES & {"arp_spoof", "gateway_takeover", "dhcp_starvation"}:
        run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    # ── Start configured redirect modes ──────────────────────────────────────
    if "redirect_dns" in REDIRECT_MODES:
        if not pihole_ip:
            log.error("redirect_dns_no_pihole_ip")
        else:
            setup_dns_redirect(pihole_ip)

    if "arp_spoof" in REDIRECT_MODES:
        if not gateway_ip:
            log.error("arp_spoof_no_gateway", msg="Cannot ARP-spoof without a known gateway IP")
        else:
            run_arp_spoof_mode(gateway_ip, pihole_ip)

    if "dhcp_advertise" in REDIRECT_MODES:
        if not own_ip:
            log.error("dhcp_advertise_no_ip", msg="Cannot start DHCP advertiser without a local IP")
        else:
            run_dhcp_advertise_mode(own_ip, pihole_ip)

    if "dhcp_starvation" in REDIRECT_MODES:
        run_dhcp_starvation_mode()

    if "gateway_takeover" in REDIRECT_MODES:
        if not gateway_ip:
            log.error("gateway_takeover_no_gateway")
        else:
            run_gateway_takeover_mode(gateway_ip, gateway_mac)

    if "passive" in REDIRECT_MODES or not REDIRECT_MODES:
        log.info("passive_mode_active", msg="Monitoring only — no active redirection")

    # ── Subscribe for quarantine/unquarantine events ──────────────────────────
    t = threading.Thread(
        target=subscribe_loop,
        args=(gateway_ip, gateway_mac),
        daemon=True,
    )
    t.start()

    # ── Periodic DB sync — recover quarantine state after restart ─────────────
    schedule.every(60).seconds.do(sync_quarantine_targets, gateway_ip, gateway_mac)

    # Run once immediately to enforce any existing quarantined devices
    sync_quarantine_targets(gateway_ip, gateway_mac)

    while True:
        schedule.run_pending()
        time.sleep(5)


if __name__ == "__main__":
    main()
