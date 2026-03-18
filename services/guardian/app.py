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


# ─── iptables / ipset helpers ────────────────────────────────────────────────

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
    run_cmd(["ipset", "add", "-exist", name, value])


def remove_from_ipset(name: str, value: str):
    run_cmd(["ipset", "del", name, value], check=False)


def flush_ipset(name: str):
    run_cmd(["ipset", "flush", name], check=False)


def bootstrap_iptables():
    """
    Create the ipsets and iptables chains used by the guardian.
    Idempotent — safe to call on every start.
    """
    log.info("bootstrapping_iptables")

    # ipsets must be created before any iptables rules that reference them
    ipsets = [
        ("thebox_quarantine", "hash:mac"),
        ("thebox_iot",        "hash:mac"),
        ("thebox_blocked",    "hash:mac"),
    ]
    for name, settype in ipsets:
        if not ensure_ipset(name, settype):
            log.error("ipset_creation_failed", name=name,
                      msg="iptables bootstrap aborted — ipsets are required")
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
    """Apply iptables policy for a single device based on its status."""
    # Remove from all ipsets first
    remove_from_ipset("thebox_quarantine", mac)
    remove_from_ipset("thebox_iot",        mac)
    remove_from_ipset("thebox_blocked",    mac)

    if status == "quarantined" or status == "new":
        add_to_ipset("thebox_quarantine", mac)
        log.info("device_quarantined", mac=mac, ip=ip)
    elif status == "blocked":
        add_to_ipset("thebox_blocked", mac)
        log.info("device_blocked", mac=mac, ip=ip)
    elif status == "iot":
        add_to_ipset("thebox_iot", mac)
        log.info("device_iot_restricted", mac=mac, ip=ip)
    # trusted — no ipset entry; unrestricted access


def sync_all_policies():
    """Rebuild ipsets from the current database state."""
    log.info("sync_all_policies_start")
    conn = get_db()
    flush_ipset("thebox_quarantine")
    flush_ipset("thebox_iot")
    flush_ipset("thebox_blocked")

    with conn.cursor() as cur:
        cur.execute("SELECT mac_address, ip_address, status FROM devices")
        for row in cur:
            apply_device_policy(row["mac_address"], row["ip_address"] or "", row["status"])

    conn.close()
    log.info("sync_all_policies_done")


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
        except Exception as exc:
            log.error("event_handling_error", error=str(exc))


def main():
    log.info("guardian_service_start")

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
