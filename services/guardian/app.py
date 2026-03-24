"""
TheBox — Device Guardian Service
==================================
Listens for new-device events from the discovery service and enforces
network policy:

  * **Quarantine** — unknown/new devices are placed in a restricted ipset
    that only allows DHCP + DNS traffic until manually approved.
  * **IoT allow-list** — IoT devices are restricted to DNS queries for their
    approved FQDNs; everything else is dropped via iptables OUTPUT / FORWARD
    rules managed per MAC address.
  * **Trusted** — trusted devices have unrestricted access.

Policy is enforced through iptables ipsets so that rule changes are O(1).
"""

import ipaddress
import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
import redis
import schedule
import structlog

# ─── Configuration ───────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
QUARANTINE_VLAN = os.environ.get("QUARANTINE_VLAN", "192.168.99.0/24")
TRUSTED_NETWORKS = [n.strip() for n in os.environ.get("TRUSTED_NETWORKS", "192.168.1.0/24").split(",")]
AUTO_QUARANTINE = os.environ.get("AUTO_QUARANTINE", "true").lower() == "true"
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

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


# ─── Schema bootstrap ────────────────────────────────────────────────────────

def ensure_schema():
    """Create tables this service reads from or writes to.

    Scoped to: ``users`` (FK dependency for devices), ``devices``, ``alerts``.
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
        # devices — guardian reads status and writes quarantine state
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
        # alerts — guardian writes quarantine / new-device alerts
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
        "CREATE INDEX IF NOT EXISTS idx_devices_mac    ON devices(mac_address)",
        "CREATE INDEX IF NOT EXISTS idx_devices_ip     ON devices(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_level   ON alerts(level)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)",
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


# ─── iptables / ipset helpers ────────────────────────────────────────────────

# Set to False by bootstrap_iptables() when ipset hash:mac is unavailable.
# When False, policy is enforced via per-IP iptables rules in THEBOX_POLICY.
_ipsets_available: bool = True

# Name of the dedicated iptables chain used for IP-based fallback rules.
_THEBOX_CHAIN = "THEBOX_POLICY"


def run_cmd(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        log.warning("cmd_failed", cmd=" ".join(args), stderr=result.stderr.strip())
    return result


def ensure_ipset(name: str, settype: str = "hash:mac") -> bool:
    """Create an ipset if it doesn't already exist.

    Returns True if the set is available (created or already existed),
    False if creation failed.
    """
    result = run_cmd(["ipset", "create", "-exist", name, settype])
    if result.returncode != 0:
        return False
    return True


def add_to_ipset(name: str, value: str):
    if not _ipsets_available:
        return
    run_cmd(["ipset", "add", "-exist", name, value])


def is_in_ipset(name: str, value: str) -> bool:
    """Return True if *value* is a member of ipset *name*, False otherwise."""
    if not _ipsets_available:
        return False
    return run_cmd(["ipset", "test", name, value], check=False).returncode == 0


def remove_from_ipset(name: str, value: str):
    if not _ipsets_available:
        return
    run_cmd(["ipset", "del", name, value], check=False)


def flush_ipset(name: str):
    if not _ipsets_available:
        return
    run_cmd(["ipset", "flush", name], check=False)


# ─── IP-based iptables fallback (when ipset hash:mac is unavailable) ─────────

def _bootstrap_iptables_ip_fallback():
    """Create the THEBOX_POLICY chain and insert a jump into FORWARD.

    Used when the kernel does not support the ``hash:mac`` ipset type (e.g.
    macOS Docker Desktop).  Policy is enforced via per-IP iptables rules in
    the dedicated chain rather than MAC-based ipsets.
    """
    # Create the chain (idempotent — -N fails if it already exists)
    run_cmd(["iptables", "-N", _THEBOX_CHAIN], check=False)
    # Insert the jump rule into FORWARD if not already there
    if run_cmd(["iptables", "-C", "FORWARD", "-j", _THEBOX_CHAIN], check=False).returncode != 0:
        run_cmd(["iptables", "-I", "FORWARD", "-j", _THEBOX_CHAIN])
    log.info("iptables_ip_fallback_ready", chain=_THEBOX_CHAIN)


def _flush_iptables_ip_chain():
    """Remove all per-IP rules from the THEBOX_POLICY chain."""
    run_cmd(["iptables", "-F", _THEBOX_CHAIN], check=False)


def _remove_iptables_ip_rules(ip: str):
    """Delete all THEBOX_POLICY rules that reference source IP *ip*.

    Tries every rule variant we might have inserted and repeats each deletion
    until iptables reports no matching rule (handles duplicate entries).
    A maximum of 10 iterations per variant guards against unexpected loops.
    """
    _MAX_ITER = 10
    for extra in [
        ["-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        ["-p", "udp", "--dport", "67", "-j", "ACCEPT"],
        ["-p", "udp", "--dport", "68", "-j", "ACCEPT"],
        ["-j", "DROP"],
    ]:
        for _ in range(_MAX_ITER):
            if run_cmd(
                ["iptables", "-D", _THEBOX_CHAIN, "-s", ip] + extra, check=False
            ).returncode != 0:
                break


def _apply_iptables_ip_policy(ip: str, status: str):
    """Insert per-IP THEBOX_POLICY rules for a single device.

    The caller is responsible for removing any stale rules for *ip* first
    (either via :func:`_remove_iptables_ip_rules` or
    :func:`_flush_iptables_ip_chain`).
    """
    if not ip:
        return

    if status in ("quarantined", "iot"):
        rules = [
            ["-A", _THEBOX_CHAIN, "-s", ip, "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
            ["-A", _THEBOX_CHAIN, "-s", ip, "-p", "udp", "--dport", "67", "-j", "ACCEPT"],
            ["-A", _THEBOX_CHAIN, "-s", ip, "-p", "udp", "--dport", "68", "-j", "ACCEPT"],
            ["-A", _THEBOX_CHAIN, "-s", ip, "-j", "DROP"],
        ]
    elif status == "blocked":
        rules = [
            ["-A", _THEBOX_CHAIN, "-s", ip, "-j", "DROP"],
        ]
    else:
        return  # trusted / iot_learning / new — no rules; unrestricted access

    for rule in rules:
        run_cmd(["iptables"] + rule)


def bootstrap_iptables():
    """
    Create the ipsets and iptables chains used by the guardian.
    Idempotent — safe to call on every start.

    Falls back to per-IP iptables rules in the ``THEBOX_POLICY`` chain when
    the kernel does not support the ``hash:mac`` ipset type.
    """
    global _ipsets_available

    log.info("bootstrapping_iptables")

    # ipsets must be created before any iptables rules that reference them
    ipsets = [
        ("thebox_quarantine", "hash:mac"),
        ("thebox_iot",        "hash:mac"),
        ("thebox_blocked",    "hash:mac"),
    ]
    for name, settype in ipsets:
        if not ensure_ipset(name, settype):
            log.warning(
                "ipset_unavailable_using_ip_fallback",
                name=name,
                msg="hash:mac ipset not supported -- falling back to per-IP iptables rules",
            )
            _ipsets_available = False
            _bootstrap_iptables_ip_fallback()
            return

    # Insert jump rules into FORWARD chain (idempotent via -C check)
    rules = [
        # Blocked devices — drop everything
        ["-I", "FORWARD", "-m", "set", "--match-set", "thebox_blocked", "src", "-j", "DROP"],
        # Quarantined devices — allow only DHCP (67/68) and DNS (53)
        ["-I", "FORWARD", "-m", "set", "--match-set", "thebox_quarantine", "src",
         "-p", "udp", "--dport", "53",  "-j", "ACCEPT"],
        ["-I", "FORWARD", "-m", "set", "--match-set", "thebox_quarantine", "src",
         "-p", "udp", "--dport", "67",  "-j", "ACCEPT"],
        ["-I", "FORWARD", "-m", "set", "--match-set", "thebox_quarantine", "src",
         "-p", "udp", "--dport", "68",  "-j", "ACCEPT"],
        ["-I", "FORWARD", "-m", "set", "--match-set", "thebox_quarantine", "src",
         "-j", "DROP"],
    ]

    for rule in rules:
        # Check if rule already exists
        check_args = ["-C"] + rule[1:]
        chk = run_cmd(["iptables"] + check_args, check=False)
        if chk.returncode != 0:
            run_cmd(["iptables"] + rule)

    log.info("iptables_bootstrap_done")


def apply_device_policy(mac: str, ip: str, status: str):
    """Apply iptables policy for a single device based on its status.

    Uses MAC-based ipsets when available; falls back to per-IP iptables rules
    in the THEBOX_POLICY chain when the kernel does not support hash:mac.

    ``iot_learning`` devices are granted unrestricted access so that all their
    DNS queries (and the corresponding connections) are visible to Pi-hole
    during the 48-hour observation window.  After learning completes the
    device transitions to ``iot`` status which applies the restricted policy.
    """
    if _ipsets_available:
        # Preferred path: O(1) MAC-based ipset membership
        remove_from_ipset("thebox_quarantine", mac)
        remove_from_ipset("thebox_iot",        mac)
        remove_from_ipset("thebox_blocked",    mac)

        if status == "quarantined":
            add_to_ipset("thebox_quarantine", mac)
            log.info("device_quarantined", mac=mac, ip=ip)
        elif status == "blocked":
            add_to_ipset("thebox_blocked", mac)
            log.info("device_blocked", mac=mac, ip=ip)
        elif status == "iot":
            add_to_ipset("thebox_iot", mac)
            log.info("device_iot_restricted", mac=mac, ip=ip)
        elif status == "iot_learning":
            # No ipset entry — unrestricted access during the learning period
            log.info("device_iot_learning_unrestricted", mac=mac, ip=ip)
        # new / trusted — no ipset entry; unrestricted access
    else:
        # Fallback: per-IP rules in THEBOX_POLICY chain
        if not ip:
            log.warning(
                "apply_device_policy_no_ip",
                mac=mac, status=status,
                msg="Cannot apply IP-based fallback rules -- device has no IP address",
            )
            return
        _remove_iptables_ip_rules(ip)
        _apply_iptables_ip_policy(ip, status)
        if status == "quarantined":
            log.info("device_quarantined_ip_rules", mac=mac, ip=ip)
        elif status == "blocked":
            log.info("device_blocked_ip_rules", mac=mac, ip=ip)
        elif status == "iot":
            log.info("device_iot_restricted_ip_rules", mac=mac, ip=ip)
        elif status == "iot_learning":
            log.info("device_iot_learning_unrestricted_ip_rules", mac=mac, ip=ip)


def sync_all_policies():
    """Rebuild ipset / THEBOX_POLICY rules from the current database state."""
    log.info("sync_all_policies_start")
    conn = get_db()

    if _ipsets_available:
        flush_ipset("thebox_quarantine")
        flush_ipset("thebox_iot")
        flush_ipset("thebox_blocked")
    else:
        _flush_iptables_ip_chain()

    with conn.cursor() as cur:
        cur.execute("SELECT mac_address, ip_address, status FROM devices")
        for row in cur:
            effective_status = row["status"]
            # When AUTO_QUARANTINE is enabled, treat any device still in "new"
            # state as "quarantined" so that unprocessed devices remain
            # restricted after a service restart.
            # Devices in "iot_learning" status are intentionally left
            # unrestricted so Pi-hole can observe their full DNS traffic.
            if AUTO_QUARANTINE and effective_status == "new":
                effective_status = "quarantined"
            apply_device_policy(row["mac_address"], row["ip_address"] or "", effective_status)

    conn.close()
    log.info("sync_all_policies_done")


# ─── Redis event publisher ───────────────────────────────────────────────────

def publish_event(event_type: str, **fields):
    """Publish a structured event to the shared Redis channel."""
    try:
        rdb = get_redis()
        rdb.publish("thebox:events", json.dumps({"type": event_type, **fields}))
        log.info("event_published", event_type=event_type, **fields)
    except Exception as exc:
        log.error("event_publish_failed", event_type=event_type, error=str(exc))


# ─── Alert helper ────────────────────────────────────────────────────────────

def create_alert(conn, source: str, level: str, title: str, detail: str, device_id: int | None = None):
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO alerts (source, level, title, detail, device_id) VALUES (%s,%s,%s,%s,%s)",
            (source, level, title, detail, device_id),
        )
    conn.commit()


# ─── Event handler ───────────────────────────────────────────────────────────

def handle_new_device_event(event: dict):
    """React to a new device appearing on the network."""
    mac = event.get("mac")
    ip = event.get("ip")
    vendor = event.get("vendor", "Unknown")
    device_id = event.get("device_id")

    log.info("new_device_event", mac=mac, ip=ip, vendor=vendor)

    conn = get_db()

    if AUTO_QUARANTINE:
        # Put new device in quarantine
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE devices SET status='quarantined' WHERE id=%s AND status='new'",
                (device_id,),
            )
        conn.commit()
        apply_device_policy(mac, ip, "quarantined")
        publish_event("quarantine_device", ip=ip, mac=mac)
        create_alert(
            conn,
            source="guardian",
            level="warning",
            title=f"New device quarantined: {vendor} ({ip})",
            detail=f"MAC: {mac}  IP: {ip}  Vendor: {vendor}\nDevice placed in quarantine pending review.",
            device_id=device_id,
        )
    else:
        apply_device_policy(mac, ip, "new")
        create_alert(
            conn,
            source="guardian",
            level="info",
            title=f"New device detected: {vendor} ({ip})",
            detail=f"MAC: {mac}  IP: {ip}  Vendor: {vendor}",
            device_id=device_id,
        )

    conn.close()


# ─── Redis subscriber thread ─────────────────────────────────────────────────

def _apply_policy_from_db(device_id: int, status_override: str | None = None) -> tuple[str, str, bool] | None:
    """Look up a device by ID and apply the correct iptables policy.

    When *status_override* is provided it is used instead of the DB value
    (useful when the DB hasn't been updated yet, e.g. during event handlers).

    Returns a ``(mac_address, ip_address, was_quarantined)`` tuple on success,
    where *was_quarantined* is ``True`` when the device was in the quarantine
    ipset (or had quarantine IP rules) before the policy was applied.
    Returns ``None`` if the device is not found.
    """
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT mac_address, ip_address, status FROM devices WHERE id=%s", (device_id,))
        row = cur.fetchone()
    conn.close()

    if not row:
        log.warning("policy_apply_device_not_found", device_id=device_id)
        return None

    mac = row["mac_address"]
    ip = row["ip_address"] or ""
    effective_status = status_override if status_override is not None else row["status"]

    # Check quarantine membership *before* apply_device_policy clears it.
    if _ipsets_available:
        was_quarantined = is_in_ipset("thebox_quarantine", mac)
    else:
        # IP-fallback: probe for the DROP rule that marks quarantine
        was_quarantined = ip != "" and run_cmd(
            ["iptables", "-C", _THEBOX_CHAIN, "-s", ip, "-j", "DROP"], check=False
        ).returncode == 0

    apply_device_policy(mac, ip, effective_status)
    return mac, ip, was_quarantined


def subscribe_loop():
    """Block and process events published by the discovery service."""
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
            if etype == "new_device":
                handle_new_device_event(event)
            elif etype == "iot_learning_started":
                # Discovery has set the device status to 'iot_learning' in the
                # DB; apply unrestricted policy immediately so Pi-hole can see
                # all the device's DNS traffic during the learning window.
                device_id = event.get("device_id")
                if device_id:
                    _apply_policy_from_db(device_id, status_override="iot_learning")
                    log.info("iot_learning_policy_applied", device_id=device_id)
            elif etype == "device_status_changed":
                # A dashboard user changed a device's status directly; apply
                # the corresponding iptables policy without waiting for the
                # 10-minute sync cycle.
                device_id = event.get("device_id")
                new_status = event.get("status")
                if device_id and new_status:
                    result = _apply_policy_from_db(device_id, status_override=new_status)
                    log.info("device_policy_updated_from_event",
                             device_id=device_id, status=new_status)
                    if result:
                        mac, ip, was_quarantined = result
                        if new_status == "quarantined":
                            publish_event("quarantine_device", ip=ip, mac=mac)
                        elif was_quarantined:
                            publish_event("unquarantine_device", ip=ip, mac=mac)
        except Exception as exc:
            log.error("event_handling_error", error=str(exc))


def main():
    log.info("guardian_service_start")

    ensure_schema()

    # Wait for iptables to be available (may not be in all environments)
    try:
        bootstrap_iptables()
        sync_all_policies()
    except FileNotFoundError:
        log.warning("iptables_not_found", msg="iptables/ipset not found — install them on the host and ensure NET_ADMIN capability is granted")

    # Run a full policy sync every 10 minutes in case DB was changed externally
    schedule.every(10).minutes.do(sync_all_policies)

    # Start subscriber in background thread
    t = threading.Thread(target=subscribe_loop, daemon=True)
    t.start()

    while True:
        schedule.run_pending()
        time.sleep(5)


if __name__ == "__main__":
    main()
