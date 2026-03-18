"""
TheBox — Honeypot Service
==========================
Listens on a configurable set of TCP ports and logs every connection attempt
to PostgreSQL.  Repeated hits from the same IP within a short window trigger
an alert and can optionally instruct the guardian to block that IP.

Simulated banners and multi-turn protocol interaction are used to encourage
attackers to reveal credentials or scanning behaviour.  Each event records an
interaction_level (none / banner / data / credentials / commands) and an
inferred intent (scan / recon / probe / brute_force / exploit / sweep).
Port-sweep detection groups rapid multi-port hits from the same source into a
single sweep alert.
"""

import ipaddress
import json
import logging
import os
import re
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
        "HONEYPOT_PORTS",
        "21,22,23,25,53,80,110,135,143,389,443,445,1433,3306,3389,"
        "5432,5900,5985,6379,8080,8443,9200,11211,27017",
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


# Hits within THRESHOLD_WINDOW seconds that exceed THRESHOLD_COUNT are "high/critical".
# These can be tuned via environment variables without code changes.
THRESHOLD_COUNT = int(os.environ.get("HONEYPOT_THRESHOLD_COUNT", "3"))
THRESHOLD_WINDOW = int(os.environ.get("HONEYPOT_THRESHOLD_WINDOW", "60"))  # seconds

# Port-sweep detection: SWEEP_THRESHOLD distinct ports from one IP within SWEEP_WINDOW
SWEEP_THRESHOLD = int(os.environ.get("HONEYPOT_SWEEP_THRESHOLD", "4"))
SWEEP_WINDOW = int(os.environ.get("HONEYPOT_SWEEP_WINDOW", "60"))  # seconds

# Interaction recv timeout (seconds)
RECV_TIMEOUT = int(os.environ.get("HONEYPOT_RECV_TIMEOUT", "4"))

# Maximum characters stored for payload_preview per event
MAX_PAYLOAD_PREVIEW_LENGTH = int(os.environ.get("HONEYPOT_MAX_PAYLOAD_LENGTH", "2000"))

# Credential attempts are tracked across a wider window to detect slow brute-force.
# This multiplier × THRESHOLD_WINDOW gives the credential tracking window (seconds).
CREDENTIAL_WINDOW_MULTIPLIER = int(os.environ.get("HONEYPOT_CREDENTIAL_WINDOW_MULTIPLIER", "5"))

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, LOG_LEVEL, logging.INFO)),
)
log = structlog.get_logger()

# ─── Fake banners per port ────────────────────────────────────────────────────
BANNERS: dict[int, bytes] = {
    21:    b"220 FTP server (vsftpd 3.0.5) ready.\r\n",
    22:    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    23:    b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f",
    25:    b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
    80:    b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Welcome</h1></body></html>",
    110:   b"+OK Dovecot POP3 server ready <abc123@mail.example.com>\r\n",
    143:   b"* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot ready.\r\n",
    389:   b"0\x0c\x02\x01\x01a\x07\x0a\x01\x00\x04\x00\x04\x00",  # LDAP BindResponse
    443:   b"\x15\x03\x03\x00\x02\x02\x28",  # TLS Alert (unrecognised_name)
    445:   b"\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x88\x01\xc8",  # SMB negotiate
    1433:  b"\x04\x01\x00\x2b\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00",  # MSSQL pre-login
    3306:  b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x36\x00\x08\x00\x00\x00\x6e\x7a\x33\x3a\x52\x7c\x63\x26\x00\xff\xff\xff\x02\x00\xff\xc3\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x76\x21\x3d\x50\x5c\x5a\x32\x2a\x7a\x55\x3f\x00",
    3389:  b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x01\x08\x00\x02\x00\x00\x00",
    5432:  b"R\x00\x00\x00\x08\x00\x00\x00\x03",  # PostgreSQL MD5 auth request
    5900:  b"RFB 003.008\n",  # VNC server version
    5985:  b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n",  # WinRM
    6379:  b"-NOAUTH Authentication required.\r\n",  # Redis
    8080:  b"HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html\r\n\r\n<html><body>Apache Tomcat/9.0.80</body></html>",
    8443:  b"\x15\x03\x03\x00\x02\x02\x28",  # TLS Alert
    9200:  b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"name":"node-1","cluster_name":"elasticsearch","version":{"number":"8.11.0","lucene_version":"9.8.0"},"tagline":"You Know, for Search"}\r\n',
    11211: b"VERSION 1.6.21\r\n",  # Memcached
    27017: b"\x2c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00",  # MongoDB
}


# ─── Exploit-pattern signatures ──────────────────────────────────────────────
# If any of these byte sequences appear in received data we flag as 'exploit'.
_EXPLOIT_PATTERNS = [
    re.compile(rb"[\x00-\x08\x0b\x0e-\x1f]{8,}"),  # long runs of control chars (shellcode-like)
    re.compile(rb"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}"),  # URL-encoded sequences
    re.compile(rb"(?i)(union\s+select|exec\s*\(|drop\s+table|insert\s+into)"),  # SQL injection
    re.compile(rb"(?i)(<script|javascript:|onerror=|onload=)"),  # XSS
    re.compile(rb"(?i)(\.\.[\\/]){2,}"),  # Path traversal
    re.compile(rb"(?i)(cmd\.exe|/bin/sh|/bin/bash|powershell)"),  # Shell invocation
]


def _looks_like_exploit(data: bytes) -> bool:
    return any(p.search(data) for p in _EXPLOIT_PATTERNS)


# ─── Protocol interaction handlers ───────────────────────────────────────────
# Each handler receives a connected socket and a list that records the
# conversation.  It returns the achieved interaction_level string.

def _recv_line(sock: socket.socket, max_bytes: int = 512) -> str:
    """Read up to *max_bytes* with the current socket timeout; return decoded string."""
    try:
        data = sock.recv(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _interact_ftp(sock: socket.socket, conv: list[str]) -> str:
    """FTP: wait for USER command, respond with 331, then wait for PASS."""
    sock.settimeout(RECV_TIMEOUT)
    line = _recv_line(sock)
    if not line:
        return "banner"
    conv.append(f"C: {line.strip()}")
    if line.upper().startswith("USER "):
        sock.sendall(b"331 Password required.\r\n")
        line2 = _recv_line(sock)
        if line2:
            conv.append(f"C: {line2.strip()}")
            if line2.upper().startswith("PASS "):
                sock.sendall(b"530 Login incorrect.\r\n")
                return "credentials"
        return "data"
    return "data"


def _interact_smtp(sock: socket.socket, conv: list[str]) -> str:
    """SMTP: handle EHLO → MAIL FROM → RCPT TO flow."""
    sock.settimeout(RECV_TIMEOUT)
    level = "banner"
    for _step in range(6):
        line = _recv_line(sock)
        if not line:
            break
        conv.append(f"C: {line.strip()}")
        cmd = line.strip().upper()
        if cmd.startswith("EHLO") or cmd.startswith("HELO"):
            sock.sendall(b"250-mail.example.com\r\n250 OK\r\n")
            level = "data"
        elif cmd.startswith("MAIL FROM"):
            sock.sendall(b"250 OK\r\n")
            level = "data"
        elif cmd.startswith("RCPT TO"):
            sock.sendall(b"250 OK\r\n")
            level = "data"
        elif cmd.startswith("AUTH"):
            sock.sendall(b"334 \r\n")
            level = "credentials"
        elif cmd.startswith("DATA"):
            sock.sendall(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
            level = "commands"
            break
        elif cmd.startswith("QUIT"):
            sock.sendall(b"221 Bye\r\n")
            break
        else:
            sock.sendall(b"500 Unrecognized command\r\n")
    return level


def _interact_http(sock: socket.socket, conv: list[str]) -> str:
    """HTTP/HTTPS-alt: read and echo a minimal HTTP request."""
    sock.settimeout(RECV_TIMEOUT)
    raw = b""
    try:
        while len(raw) < 4096:
            chunk = sock.recv(1024)
            if not chunk:
                break
            raw += chunk
            if b"\r\n\r\n" in raw or b"\n\n" in raw:
                break
    except Exception:
        pass
    if not raw:
        return "banner"
    decoded = raw.decode("utf-8", errors="replace")
    # Record first line only in conversation for brevity
    first_line = decoded.splitlines()[0] if decoded.splitlines() else decoded[:80]
    conv.append(f"C: {first_line}")
    # Minimal response already sent as banner; close politely
    sock.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
    # Check for interesting HTTP paths
    if any(kw in decoded.lower() for kw in ("/admin", "/phpmyadmin", "/wp-login", "/.env", "/etc/passwd")):
        return "commands"
    return "data"


def _interact_pop3(sock: socket.socket, conv: list[str]) -> str:
    """POP3: wait for USER, respond, wait for PASS."""
    sock.settimeout(RECV_TIMEOUT)
    line = _recv_line(sock)
    if not line:
        return "banner"
    conv.append(f"C: {line.strip()}")
    if line.upper().startswith("USER "):
        sock.sendall(b"+OK Send PASS\r\n")
        line2 = _recv_line(sock)
        if line2:
            conv.append(f"C: {line2.strip()}")
            if line2.upper().startswith("PASS "):
                sock.sendall(b"-ERR Authentication failed.\r\n")
                return "credentials"
        return "data"
    return "data"


def _interact_imap(sock: socket.socket, conv: list[str]) -> str:
    """IMAP: handle LOGIN command."""
    sock.settimeout(RECV_TIMEOUT)
    for _step in range(4):
        line = _recv_line(sock)
        if not line:
            break
        conv.append(f"C: {line.strip()}")
        upper = line.strip().upper()
        if "LOGIN" in upper or "AUTHENTICATE" in upper:
            sock.sendall(b"* NO [AUTHENTICATIONFAILED] Authentication failed.\r\n")
            return "credentials"
        if "CAPABILITY" in upper:
            sock.sendall(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n")
            return "data"
    return "data" if conv else "banner"


def _interact_redis_proto(sock: socket.socket, conv: list[str]) -> str:
    """Redis: read a command, respond with error."""
    sock.settimeout(RECV_TIMEOUT)
    data = _recv_line(sock, 512)
    if not data:
        return "banner"
    conv.append(f"C: {data.strip()}")
    upper = data.strip().upper()
    if upper.startswith("AUTH") or (upper.startswith("*2") and "AUTH" in upper):
        sock.sendall(b"-ERR invalid password\r\n")
        return "credentials"
    if upper.startswith("CONFIG") or upper.startswith("SLAVEOF") or upper.startswith("REPLICAOF"):
        sock.sendall(b"-ERR operation not permitted\r\n")
        return "commands"
    sock.sendall(b"-ERR unknown command\r\n")
    return "data"


def _interact_vnc(sock: socket.socket, conv: list[str]) -> str:
    """VNC: expect client version string, then send auth challenge."""
    sock.settimeout(RECV_TIMEOUT)
    client_ver = _recv_line(sock, 32)
    if not client_ver:
        return "banner"
    conv.append(f"C: {client_ver.strip()}")
    # Security type 2 = VNC authentication
    sock.sendall(b"\x00\x00\x00\x01\x02")  # 1 security type: VNC auth
    challenge = _recv_line(sock, 32)
    if challenge:
        conv.append(f"C: (VNC auth response {len(challenge)} bytes)")
        return "credentials"
    return "data"


def _interact_telnet(sock: socket.socket, conv: list[str]) -> str:
    """Telnet: skip negotiation bytes then wait for login."""
    sock.settimeout(RECV_TIMEOUT)
    sock.sendall(b"\r\nlogin: ")
    line = _recv_line(sock, 128)
    if not line:
        return "banner"
    conv.append(f"C: {line.strip()}")
    sock.sendall(b"Password: ")
    passwd = _recv_line(sock, 128)
    if passwd:
        conv.append(f"C: (password {len(passwd.strip())} chars)")
        sock.sendall(b"\r\nLogin incorrect\r\n")
        return "credentials"
    return "data"


# Map each port to its interaction handler (called AFTER the banner is sent).
_PROTOCOL_HANDLERS = {
    21:   _interact_ftp,
    23:   _interact_telnet,
    25:   _interact_smtp,
    80:   _interact_http,
    110:  _interact_pop3,
    143:  _interact_imap,
    587:  _interact_smtp,
    6379: _interact_redis_proto,
    5900: _interact_vnc,
    8080: _interact_http,
    8443: _interact_http,
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
            id                SERIAL PRIMARY KEY,
            src_ip            VARCHAR(45) NOT NULL,
            src_port          INTEGER,
            dst_port          INTEGER NOT NULL,
            protocol          VARCHAR(10) NOT NULL DEFAULT 'tcp',
            payload_preview   TEXT,
            severity          VARCHAR(16) NOT NULL DEFAULT 'low',
            interaction_level VARCHAR(16) NOT NULL DEFAULT 'none',
            intent            VARCHAR(32) NOT NULL DEFAULT 'scan',
            is_sweep          BOOLEAN NOT NULL DEFAULT FALSE,
            ports_scanned     JSONB,
            device_id         INTEGER REFERENCES devices(id),
            created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
        # Migration: add new columns to existing tables if they don't exist yet
        "ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS interaction_level VARCHAR(16) NOT NULL DEFAULT 'none'",
        "ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS intent VARCHAR(32) NOT NULL DEFAULT 'scan'",
        "ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS is_sweep BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS ports_scanned JSONB",
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

def classify_severity(src_ip: str, rdb: redis.Redis, interaction_level: str, intent: str, is_sweep: bool) -> str:
    """Return severity based on hit frequency, interaction depth, and inferred intent."""
    key = f"thebox:honeypot:hits:{src_ip}"
    count = rdb.incr(key)
    rdb.expire(key, THRESHOLD_WINDOW)

    # Exploit attempts are always critical
    if intent == "exploit":
        return "critical"
    # Brute force or sweep with high hit count
    if intent == "brute_force" or (is_sweep and count >= THRESHOLD_COUNT):
        return "critical"
    # Credentials seen → high; sweep → high
    if interaction_level in ("credentials", "commands") or is_sweep:
        return "high"
    # Many hits even without credentials
    if count >= THRESHOLD_COUNT * 3:
        return "critical"
    if count >= THRESHOLD_COUNT:
        return "high"
    return "low"


# ─── Sweep detector ───────────────────────────────────────────────────────────

def detect_sweep(src_ip: str, dst_port: int, rdb: redis.Redis) -> tuple[bool, list[int]]:
    """Track which ports *src_ip* has probed recently.

    Returns (is_sweep, sorted_port_list).  A sweep is declared when the same
    source IP hits SWEEP_THRESHOLD or more distinct ports within SWEEP_WINDOW.
    """
    key = f"thebox:honeypot:ports:{src_ip}"
    rdb.sadd(key, str(dst_port))
    rdb.expire(key, SWEEP_WINDOW)
    ports = sorted(int(p) for p in rdb.smembers(key))
    return len(ports) >= SWEEP_THRESHOLD, ports


def infer_intent(
    interaction_level: str,
    payload: str,
    is_sweep: bool,
    src_ip: str,
    rdb: redis.Redis,
) -> str:
    """Infer attacker intent from interaction level, payload content, and sweep status."""
    if is_sweep:
        # If credentials were also attempted, escalate beyond sweep
        if interaction_level in ("credentials", "commands"):
            pass  # fall through to more specific checks below
        else:
            return "sweep"

    payload_bytes = payload.encode("utf-8", errors="replace") if payload else b""

    if interaction_level == "none":
        return "scan"

    if interaction_level == "banner":
        return "recon"

    if _looks_like_exploit(payload_bytes):
        return "exploit"

    if interaction_level in ("credentials", "commands"):
        # Check if this IP has attempted credentials multiple times recently
        cred_key = f"thebox:honeypot:creds:{src_ip}"
        cred_count = rdb.incr(cred_key)
        rdb.expire(cred_key, THRESHOLD_WINDOW * CREDENTIAL_WINDOW_MULTIPLIER)
        if cred_count >= 3:
            return "brute_force"
        return "credentials"

    return "probe"


# ─── Event logger ────────────────────────────────────────────────────────────

def log_event(
    src_ip: str,
    src_port: int,
    dst_port: int,
    payload_preview: str,
    severity: str,
    interaction_level: str,
    intent: str,
    is_sweep: bool,
    ports_scanned: list[int],
):
    conn = get_db()
    rdb = get_redis()

    # Look up matching device
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM devices WHERE ip_address=%s LIMIT 1", (src_ip,))
        row = cur.fetchone()
        device_id = row["id"] if row else None

    ports_json = json.dumps(ports_scanned) if ports_scanned else None

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO honeypot_events
                (src_ip, src_port, dst_port, protocol, payload_preview, severity,
                 interaction_level, intent, is_sweep, ports_scanned, device_id)
            VALUES (%s,%s,%s,'tcp',%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                src_ip,
                src_port,
                dst_port,
                payload_preview[:MAX_PAYLOAD_PREVIEW_LENGTH] if payload_preview else None,
                severity,
                interaction_level,
                intent,
                is_sweep,
                ports_json,
                device_id,
            ),
        )
    conn.commit()

    log.info(
        "honeypot_hit",
        src_ip=src_ip,
        src_port=src_port,
        dst_port=dst_port,
        severity=severity,
        interaction_level=interaction_level,
        intent=intent,
        is_sweep=is_sweep,
    )

    if severity in ("high", "critical"):
        # For sweeps, deduplicate: only create ONE sweep alert per IP per window
        if is_sweep:
            sweep_alert_key = f"thebox:honeypot:sweep_alerted:{src_ip}"
            already = rdb.get(sweep_alert_key)
            if already:
                # Alert already raised for this sweep window — skip
                conn.close()
                return
            rdb.setex(sweep_alert_key, SWEEP_WINDOW, "1")
            alert_title = f"Port sweep detected: {src_ip} → {len(ports_scanned)} ports"
            alert_detail = (
                f"Source: {src_ip}:{src_port}\n"
                f"Ports scanned: {', '.join(str(p) for p in ports_scanned)}\n"
                f"Severity: {severity}"
            )
        else:
            alert_title = f"Honeypot alert [{intent}]: {src_ip} → port {dst_port}"
            alert_detail = (
                f"Source: {src_ip}:{src_port}  →  port {dst_port}\n"
                f"Interaction: {interaction_level}  Intent: {intent}\n"
                f"Severity: {severity}"
            )

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (source, level, title, detail, device_id)
                VALUES ('honeypot', %s, %s, %s, %s)
                """,
                (severity, alert_title, alert_detail, device_id),
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

    conversation: list[str] = []
    interaction_level = "none"

    try:
        # Send a fake banner if we have one
        banner = BANNERS.get(dst_port)
        if banner:
            try:
                conn_sock.sendall(banner)
                interaction_level = "banner"
            except Exception:
                pass

        # Run the protocol-specific interaction handler if available
        handler = _PROTOCOL_HANDLERS.get(dst_port)
        if handler:
            try:
                interaction_level = handler(conn_sock, conversation)
            except Exception:
                pass
        else:
            # Generic: try to read any payload the client sends
            conn_sock.settimeout(RECV_TIMEOUT)
            try:
                data = conn_sock.recv(2048)
                if data:
                    interaction_level = "data"
                    conversation.append(data.decode("utf-8", errors="replace"))
            except Exception:
                pass

    finally:
        conn_sock.close()

    payload_preview = "\n".join(conversation) if conversation else ""

    # Sweep detection
    is_sweep, ports_scanned = detect_sweep(src_ip, dst_port, rdb)

    # Intent inference
    intent = infer_intent(interaction_level, payload_preview, is_sweep, src_ip, rdb)

    # Severity classification
    severity = classify_severity(src_ip, rdb, interaction_level, intent, is_sweep)

    log_event(
        src_ip, src_port, dst_port, payload_preview, severity,
        interaction_level, intent, is_sweep, ports_scanned,
    )


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
