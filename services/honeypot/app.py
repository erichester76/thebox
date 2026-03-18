"""
TheBox — Honeypot Service
==========================
Listens on a configurable set of TCP ports and logs every connection attempt
to PostgreSQL.  Repeated hits from the same IP within a short window trigger
an alert and can optionally instruct the guardian to block that IP.

Simulated banners are served for common protocols to encourage attackers to
reveal credentials or scanning behaviour.
"""

import ipaddress
import json
import logging
import os
import socket
import threading
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
import redis
import structlog

# ─── Configuration ───────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
HONEYPOT_PORTS = [
    int(p.strip())
    for p in os.environ.get(
        "HONEYPOT_PORTS", "21,22,23,25,80,110,143,443,445,3306,3389,8080"
    ).split(",")
]
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# IPs/CIDRs to silently ignore (e.g. Docker bridge gateways, loopback).
# Default covers RFC-1918 private Docker bridge ranges and loopback.
_IGNORED_NETWORKS_RAW = os.environ.get(
    "HONEYPOT_IGNORED_NETWORKS", "172.16.0.0/12,127.0.0.0/8"
)
IGNORED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
for _raw in _IGNORED_NETWORKS_RAW.split(","):
    _raw = _raw.strip()
    if not _raw:
        continue
    try:
        IGNORED_NETWORKS.append(ipaddress.ip_network(_raw, strict=False))
    except ValueError as exc:
        raise ValueError(
            f"HONEYPOT_IGNORED_NETWORKS contains an invalid network: {_raw!r}"
        ) from exc


def is_ignored(ip: str) -> bool:
    """Return True if *ip* falls within any configured ignored network."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in IGNORED_NETWORKS)


# Hits within THRESHOLD_WINDOW seconds that exceed THRESHOLD_COUNT are "critical"
THRESHOLD_COUNT = 3
THRESHOLD_WINDOW = 60  # seconds

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, LOG_LEVEL, logging.INFO)),
)
log = structlog.get_logger()

# ─── Fake banners per port ────────────────────────────────────────────────────
BANNERS: dict[int, bytes] = {
    21:   b"220 FTP server ready\r\n",
    22:   b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    23:   b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f",
    25:   b"220 mail.example.com ESMTP\r\n",
    80:   b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>",
    110:  b"+OK POP3 server ready\r\n",
    143:  b"* OK IMAP4rev1 Server Ready\r\n",
    3306: b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x36\x00",
    3389: b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x01\x08\x00\x02\x00\x00\x00",
}


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)


# ─── Schema bootstrap ────────────────────────────────────────────────────────

def ensure_schema():
    """Create tables this service reads from or writes to.

    Scoped to: ``users`` (FK dependency for devices), ``devices``,
    ``honeypot_events``, ``alerts``.  All DDL uses ``IF NOT EXISTS`` so
    this is safe to call on every startup.
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
        # devices — honeypot looks up device_id by source IP
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
        # honeypot_events — honeypot writes every connection attempt
        """CREATE TABLE IF NOT EXISTS honeypot_events (
            id              SERIAL PRIMARY KEY,
            src_ip          VARCHAR(45) NOT NULL,
            src_port        INTEGER,
            dst_port        INTEGER NOT NULL,
            protocol        VARCHAR(10) NOT NULL DEFAULT 'tcp',
            payload_preview TEXT,
            severity        VARCHAR(16) NOT NULL DEFAULT 'low',
            device_id       INTEGER REFERENCES devices(id),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        # alerts — honeypot writes high/critical severity alerts
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
        "CREATE INDEX IF NOT EXISTS idx_devices_ip        ON devices(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_honeypot_src_ip   ON honeypot_events(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_honeypot_created  ON honeypot_events(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_level      ON alerts(level)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created    ON alerts(created_at)",
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


# ─── Severity classifier ──────────────────────────────────────────────────────

def classify_severity(src_ip: str, rdb: redis.Redis) -> str:
    """Return 'critical' if src_ip has hit the honeypot many times recently."""
    key = f"thebox:honeypot:hits:{src_ip}"
    count = rdb.incr(key)
    rdb.expire(key, THRESHOLD_WINDOW)
    if count >= THRESHOLD_COUNT * 3:
        return "critical"
    if count >= THRESHOLD_COUNT:
        return "high"
    return "low"


# ─── Event logger ────────────────────────────────────────────────────────────

def log_event(src_ip: str, src_port: int, dst_port: int, payload_preview: str, severity: str):
    conn = get_db()
    rdb = get_redis()

    # Look up matching device
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM devices WHERE ip_address=%s LIMIT 1", (src_ip,))
        row = cur.fetchone()
        device_id = row["id"] if row else None

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO honeypot_events
                (src_ip, src_port, dst_port, protocol, payload_preview, severity, device_id)
            VALUES (%s,%s,%s,'tcp',%s,%s,%s)
            """,
            (src_ip, src_port, dst_port, payload_preview[:500] if payload_preview else None, severity, device_id),
        )
    conn.commit()

    log.info(
        "honeypot_hit",
        src_ip=src_ip,
        src_port=src_port,
        dst_port=dst_port,
        severity=severity,
    )

    if severity in ("high", "critical"):
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (source, level, title, detail, device_id)
                VALUES ('honeypot', %s, %s, %s, %s)
                """,
                (
                    severity,
                    f"Honeypot alert: {src_ip} → port {dst_port}",
                    f"Source: {src_ip}:{src_port}  →  port {dst_port}\nSeverity: {severity}",
                    device_id,
                ),
            )
        conn.commit()

        # Publish block request for guardian
        rdb.publish(
            "thebox:events",
            json.dumps(
                {
                    "type": "block_ip",
                    "ip": src_ip,
                    "reason": f"honeypot_{severity}",
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
            ),
        )

    conn.close()


# ─── Per-port listener ───────────────────────────────────────────────────────

def handle_connection(conn_sock: socket.socket, addr: tuple, dst_port: int, rdb: redis.Redis):
    src_ip, src_port = addr[0], addr[1]

    # Silently drop connections from internal/Docker networks
    if is_ignored(src_ip):
        conn_sock.close()
        return

    payload_preview = ""
    try:
        # Send a fake banner if we have one
        banner = BANNERS.get(dst_port)
        if banner:
            conn_sock.sendall(banner)

        # Attempt to read a small payload
        conn_sock.settimeout(3)
        try:
            data = conn_sock.recv(1024)
            payload_preview = data.decode("utf-8", errors="replace")
        except Exception:
            pass
    finally:
        conn_sock.close()

    severity = classify_severity(src_ip, rdb)
    log_event(src_ip, src_port, dst_port, payload_preview, severity)


def listen_on_port(port: int):
    rdb = get_redis()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        # Intentionally binding to all interfaces: the honeypot must be reachable
        # from any network address on the host to catch incoming attack traffic.
        srv.bind(("0.0.0.0", port))  # noqa: S104
    except OSError as exc:
        log.warning("bind_failed", port=port, error=str(exc))
        return
    srv.listen(50)
    log.info("honeypot_listening", port=port)

    while True:
        try:
            client_sock, addr = srv.accept()
            t = threading.Thread(
                target=handle_connection,
                args=(client_sock, addr, port, rdb),
                daemon=True,
            )
            t.start()
        except Exception as exc:
            log.error("accept_error", port=port, error=str(exc))


def main():
    log.info("honeypot_service_start", ports=HONEYPOT_PORTS)
    ensure_schema()
    threads = []
    for port in HONEYPOT_PORTS:
        t = threading.Thread(target=listen_on_port, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    # Keep main thread alive
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
