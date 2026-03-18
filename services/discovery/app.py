"""
TheBox — Network Discovery Service
===================================
Continuously scans the local network to discover devices, resolve hostnames,
identify vendors via MAC OUI lookup, and attempt OS fingerprinting.  New
devices are stored in PostgreSQL and a "new_device" event is published to
Redis so that the guardian and dashboard services can react in real-time.
"""

import json
import logging
import os
import socket
import time
from datetime import datetime, timezone

import nmap
import psycopg2
import psycopg2.extras
import redis
import schedule
import structlog
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from scapy.all import ARP, Ether, srp  # noqa: F401

# ─── Configuration ───────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
NETWORK_RANGES = [r.strip() for r in os.environ.get("NETWORK_RANGES", "192.168.1.0/24").split(",")]
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", "300"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

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
        new_count = 0

        for host in hosts:
            # Enrich
            host["hostname"] = resolve_hostname(host["ip"])
            host["vendor"] = vendor_lookup(host["mac"])
            scan_data = nmap_scan(host["ip"])
            host.update(scan_data)
            host["device_type"] = guess_device_type(
                host.get("vendor"), host.get("open_ports", []), host.get("os_guess")
            )

            is_new = upsert_device(conn, rdb, host)
            if is_new:
                new_count += 1

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

    # Run once immediately, then on schedule
    run_scan()
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)

    while True:
        schedule.run_pending()
        time.sleep(10)


if __name__ == "__main__":
    main()
