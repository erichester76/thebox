"""
TheBox — Web Dashboard
========================
Flask application that provides the unified management UI for all TheBox
services.  Uses Server-Sent Events (SSE) to push live alerts to the browser
and exposes a REST API for the front-end JavaScript.
"""

import json
import logging
import os
import queue
import threading
import time
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
import redis
import requests
import structlog
from flask import Flask, Response, jsonify, render_template, request

# ─── Configuration ───────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
SECRET_KEY = os.environ.get("SECRET_KEY", "")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
PIHOLE_URL = os.environ.get("PIHOLE_URL", "").rstrip("/")
PIHOLE_PASSWORD = os.environ.get("PIHOLE_PASSWORD", "")

# ─── Settings catalogue ───────────────────────────────────────────────────────
# Each entry: (key, env_default, category, description)
# Used to seed the settings table on first startup and to validate API updates.
_SETTINGS_CATALOGUE: list[tuple[str, str, str, str]] = [
    # ── General ──
    ("LOG_LEVEL",      os.environ.get("LOG_LEVEL", "INFO"),                  "general",    "Log level for all services (DEBUG, INFO, WARNING, ERROR)"),
    ("DASHBOARD_URL",  os.environ.get("DASHBOARD_URL", "http://dashboard:3000"), "general", "Internal URL used by the discovery service to register the IoT allow-list feed with Pi-hole"),
    # ── Pi-hole ──
    ("PIHOLE_URL",      os.environ.get("PIHOLE_URL", ""),           "pihole", "Pi-hole v6 API base URL (e.g. http://pihole:80/api)"),
    ("PIHOLE_PASSWORD", os.environ.get("PIHOLE_PASSWORD", ""),      "pihole", "Pi-hole admin password"),
    ("PIHOLE_SID_TTL",  os.environ.get("PIHOLE_SID_TTL", "240"),    "pihole", "Seconds a Pi-hole v6 session ID is cached before re-authenticating"),
    # ── Network Discovery ──
    ("NETWORK_RANGES",       os.environ.get("NETWORK_RANGES", "192.168.1.0/24"),   "discovery", "Comma-separated list of CIDR ranges to scan"),
    ("SCAN_INTERVAL",        os.environ.get("SCAN_INTERVAL", "300"),                "discovery", "Scan interval in seconds"),
    ("DNS_SNIFF_ENABLED",    os.environ.get("DNS_SNIFF_ENABLED", "true"),           "discovery", "Enable DNS packet sniffing to discover devices from their DNS queries"),
    ("DNS_SNIFF_IFACE",      os.environ.get("DNS_SNIFF_IFACE", ""),                 "discovery", "Network interface for DNS sniffing (empty = auto-detect)"),
    ("SSDP_ENABLED",         os.environ.get("SSDP_ENABLED", "true"),                "discovery", "Enable SSDP/UPnP multicast discovery"),
    ("SSDP_TIMEOUT",         os.environ.get("SSDP_TIMEOUT", "5"),                   "discovery", "Seconds to wait for SSDP responses per scan cycle"),
    ("MDNS_ENABLED",         os.environ.get("MDNS_ENABLED", "true"),                "discovery", "Enable mDNS/Zeroconf (Bonjour/Avahi) service browser"),
    ("NETBIOS_ENABLED",      os.environ.get("NETBIOS_ENABLED", "true"),             "discovery", "Enable NetBIOS/NBNS subnet scan via nmap nbstat"),
    ("BANNER_GRAB_ENABLED",  os.environ.get("BANNER_GRAB_ENABLED", "true"),         "discovery", "Enable HTTP/HTTPS banner grabbing"),
    ("BANNER_GRAB_TIMEOUT",  os.environ.get("BANNER_GRAB_TIMEOUT", "3"),            "discovery", "Timeout in seconds for banner grab connections"),
    ("DHCP_SNIFF_ENABLED",   os.environ.get("DHCP_SNIFF_ENABLED", "true"),          "discovery", "Enable DHCP packet sniffing for real-time hostname extraction"),
    ("ARP_SNIFF_ENABLED",    os.environ.get("ARP_SNIFF_ENABLED", "true"),           "discovery", "Enable ARP packet sniffing for real-time device detection"),
    # ── Device Guardian ──
    ("QUARANTINE_VLAN",  os.environ.get("QUARANTINE_VLAN", "192.168.99.0/24"),              "guardian", "CIDR range used for quarantined devices"),
    ("TRUSTED_NETWORKS", os.environ.get("TRUSTED_NETWORKS", "192.168.1.0/24"),              "guardian", "Comma-separated list of trusted network ranges"),
    ("AUTO_QUARANTINE",  os.environ.get("AUTO_QUARANTINE", "true"),                          "guardian", "Automatically quarantine new/unknown devices (true/false)"),
    # ── IoT Learning ──
    ("IOT_LEARNING_HOURS", os.environ.get("IOT_LEARNING_HOURS", "48"),  "iot", "Hours a new IoT device spends in the observation group before being moved to the IoT group"),
    ("PIHOLE_IOT_GROUP",   os.environ.get("PIHOLE_IOT_GROUP", "iot"),   "iot", "Name of the Pi-hole group that IoT devices are placed in after the learning period"),
    # ── Honeypot ──
    ("HONEYPOT_PORTS",                    os.environ.get("HONEYPOT_PORTS", "21,22,23,25,53,80,110,135,143,389,443,445,1433,3306,3389,5432,5900,5985,6379,8080,8443,9200,11211,27017"), "honeypot", "Comma-separated list of ports the honeypot listens on"),
    ("HONEYPOT_IGNORED_NETWORKS",         os.environ.get("HONEYPOT_IGNORED_NETWORKS", "172.16.0.0/12,127.0.0.0/8"), "honeypot", "Comma-separated IPs/CIDRs to silently ignore (e.g. Docker bridge gateway and loopback)"),
    ("HONEYPOT_THRESHOLD_COUNT",          os.environ.get("HONEYPOT_THRESHOLD_COUNT", "3"),      "honeypot", "Hit count from a single IP within HONEYPOT_THRESHOLD_WINDOW seconds before severity escalation"),
    ("HONEYPOT_THRESHOLD_WINDOW",         os.environ.get("HONEYPOT_THRESHOLD_WINDOW", "60"),    "honeypot", "Rolling window in seconds for hit-count threshold"),
    ("HONEYPOT_SWEEP_THRESHOLD",          os.environ.get("HONEYPOT_SWEEP_THRESHOLD", "4"),      "honeypot", "Distinct ports a single IP must probe within the sweep window to be classified as a port sweep"),
    ("HONEYPOT_SWEEP_WINDOW",             os.environ.get("HONEYPOT_SWEEP_WINDOW", "60"),        "honeypot", "Rolling window in seconds for port-sweep detection"),
    ("HONEYPOT_RECV_TIMEOUT",             os.environ.get("HONEYPOT_RECV_TIMEOUT", "4"),         "honeypot", "Seconds the honeypot waits for data after sending the banner"),
    ("HONEYPOT_MAX_PAYLOAD_LENGTH",       os.environ.get("HONEYPOT_MAX_PAYLOAD_LENGTH", "2000"), "honeypot", "Maximum characters stored as payload_preview in the database"),
    ("HONEYPOT_CREDENTIAL_WINDOW_MULTIPLIER", os.environ.get("HONEYPOT_CREDENTIAL_WINDOW_MULTIPLIER", "5"), "honeypot", "Credential tracking window multiplier (THRESHOLD_WINDOW × this = credential TTL seconds)"),
    # ── Redirector ──
    ("REDIRECT_MODE",        os.environ.get("REDIRECT_MODE", "passive"),  "redirector", "Active redirect mode(s): passive, redirect_dns, arp_spoof, dhcp_advertise, dhcp_starvation, gateway_takeover"),
    ("NETWORK_INTERFACE",    os.environ.get("NETWORK_INTERFACE", "eth0"), "redirector", "Network interface used for ARP/packet operations"),
    ("GATEWAY_IP",           os.environ.get("GATEWAY_IP", ""),            "redirector", "Default gateway IP (auto-detected from routing table if empty)"),
    ("PIHOLE_IP",            os.environ.get("PIHOLE_IP", ""),             "redirector", "Pi-hole IP address (defaults to BOX_IP if empty)"),
    ("BOX_IP",               os.environ.get("BOX_IP", ""),                "redirector", "TheBox's own IP address (auto-detected from NETWORK_INTERFACE if empty)"),
    ("BLACKHOLE_QUARANTINED", os.environ.get("BLACKHOLE_QUARANTINED", "false"), "redirector", "Drop all traffic from quarantined devices except DHCP and DNS (true/false)"),
    ("ARP_REFRESH_INTERVAL", os.environ.get("ARP_REFRESH_INTERVAL", "10"), "redirector", "Seconds between ARP refresh packets for active spoof modes"),
]

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, LOG_LEVEL, logging.INFO)),
)
log = structlog.get_logger()

if not SECRET_KEY:
    log.critical("missing_secret_key", msg="SECRET_KEY env var is not set — using an insecure default. Set it before running in production.")
    SECRET_KEY = "insecure-default-change-me"

app = Flask(__name__)
app.secret_key = SECRET_KEY

# SSE subscribers: list of queues, one per connected browser tab
_sse_subscribers: list[queue.Queue] = []
_sse_lock = threading.Lock()


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)


# ─── Schema bootstrap ────────────────────────────────────────────────────────

def ensure_schema():
    """Create tables this service reads from or writes to.

    Scoped to: ``users``, ``devices``, ``iot_allowlist``, ``groups``,
    ``user_groups``, ``device_groups``, ``alerts``, ``honeypot_events``.
    All DDL uses ``IF NOT EXISTS`` so this is safe to call on every startup.
    """
    statements = [
        # users — dashboard manages user records
        """CREATE TABLE IF NOT EXISTS users (
            id              SERIAL PRIMARY KEY,
            username        VARCHAR(64) NOT NULL UNIQUE,
            display_name    VARCHAR(255),
            email           VARCHAR(255),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        # devices — dashboard reads and updates device status / owner
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
        # iot_allowlist — FQDNs that IoT devices are permitted to reach.
        # device_id is nullable: NULL marks a globally-shared entry added by
        # the learning engine; a non-NULL value ties the FQDN to a specific device.
        """CREATE TABLE IF NOT EXISTS iot_allowlist (
            id          SERIAL PRIMARY KEY,
            device_id   INTEGER REFERENCES devices(id) ON DELETE CASCADE,
            fqdn        VARCHAR(255) NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(device_id, fqdn)
        )""",
        # iot_learning_sessions — tracks the 48-hour observation window for each
        # newly discovered or user-assigned IoT device.
        """CREATE TABLE IF NOT EXISTS iot_learning_sessions (
            id                    SERIAL PRIMARY KEY,
            device_id             INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            pihole_group_name     VARCHAR(64) NOT NULL,
            learning_started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            learning_completed_at TIMESTAMPTZ,
            status                VARCHAR(32) NOT NULL DEFAULT 'active',
            UNIQUE(device_id)
        )""",
        # groups — dashboard manages Pi-hole groups
        """CREATE TABLE IF NOT EXISTS groups (
            id                SERIAL PRIMARY KEY,
            name              VARCHAR(64) NOT NULL UNIQUE,
            description       TEXT,
            pihole_group_name VARCHAR(64),
            created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        # user_groups — dashboard manages user ↔ group memberships
        """CREATE TABLE IF NOT EXISTS user_groups (
            user_id  INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
            group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, group_id)
        )""",
        # device_groups — dashboard manages device ↔ group memberships
        """CREATE TABLE IF NOT EXISTS device_groups (
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            PRIMARY KEY (device_id, group_id)
        )""",
        # alerts — dashboard reads and acknowledges alerts
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
        # honeypot_events — dashboard displays honeypot hit log
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
        "CREATE INDEX IF NOT EXISTS idx_devices_mac         ON devices(mac_address)",
        "CREATE INDEX IF NOT EXISTS idx_devices_ip          ON devices(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_devices_status      ON devices(status)",
        "CREATE INDEX IF NOT EXISTS idx_devices_owner       ON devices(owner_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_level        ON alerts(level)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_created      ON alerts(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_honeypot_src_ip     ON honeypot_events(src_ip)",
        "CREATE INDEX IF NOT EXISTS idx_honeypot_created    ON honeypot_events(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_user_groups_group   ON user_groups(group_id)",
        "CREATE INDEX IF NOT EXISTS idx_device_groups_group ON device_groups(group_id)",
        "CREATE INDEX IF NOT EXISTS idx_iot_learning_status  ON iot_learning_sessions(status)",
        "CREATE INDEX IF NOT EXISTS idx_iot_learning_started ON iot_learning_sessions(learning_started_at)",
        # Partial unique index for globally-shared allow-list entries (device_id IS NULL).
        """CREATE UNIQUE INDEX IF NOT EXISTS idx_iot_allowlist_global_fqdn
            ON iot_allowlist(fqdn) WHERE device_id IS NULL""",
        # Upgrade safety: allow NULL device_id on installs created before migration 0002.
        # In PostgreSQL, DROP NOT NULL on an already-nullable column is a no-op,
        # so this statement is safe to execute on both old (NOT NULL) and new (nullable)
        # schemas without needing additional conditional logic.
        "ALTER TABLE iot_allowlist ALTER COLUMN device_id DROP NOT NULL",
        # Migration: add new honeypot columns to existing deployments
        "ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS interaction_level VARCHAR(16) NOT NULL DEFAULT 'none'",
        "ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS intent VARCHAR(32) NOT NULL DEFAULT 'scan'",
        "ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS is_sweep BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS ports_scanned JSONB",
        # settings — runtime configuration key/value store
        """CREATE TABLE IF NOT EXISTS settings (
            key         VARCHAR(64)  NOT NULL PRIMARY KEY,
            value       TEXT         NOT NULL,
            description TEXT,
            category    VARCHAR(32)  NOT NULL DEFAULT 'general',
            updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS idx_settings_category ON settings(category)",
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


# ─── SSE / Redis subscriber ──────────────────────────────────────────────────

def redis_subscriber_loop():
    """Background thread: subscribe to Redis and fan-out to SSE clients."""
    rdb = get_redis()
    pubsub = rdb.pubsub()
    pubsub.subscribe("thebox:events")
    for message in pubsub.listen():
        if message["type"] != "message":
            continue
        payload = message["data"]
        with _sse_lock:
            for q in list(_sse_subscribers):
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    pass


threading.Thread(target=redis_subscriber_loop, daemon=True).start()

# Called at module level (not inside if __name__) so the schema is ensured
# whether the app is run directly or served by a WSGI host (gunicorn, etc.).
ensure_schema()


# ─── Settings helpers ────────────────────────────────────────────────────────

def bootstrap_settings() -> None:
    """Seed the settings table from environment variables on first startup.

    Each entry in ``_SETTINGS_CATALOGUE`` is inserted only if the key is not
    already present in the database, so subsequent restarts never overwrite
    values that were changed via the UI.
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            for key, default, category, description in _SETTINGS_CATALOGUE:
                cur.execute(
                    """INSERT INTO settings (key, value, category, description)
                       VALUES (%s, %s, %s, %s)
                       ON CONFLICT (key) DO NOTHING""",
                    (key, default, category, description),
                )
        conn.commit()
        log.info("settings_bootstrapped")
    finally:
        conn.close()


def get_setting(key: str, default: str = "") -> str:
    """Return the current value for *key* from the database.

    Falls back to *default* when the key is absent (which should only happen
    on a freshly deployed instance before ``bootstrap_settings`` has run).
    Opens and closes its own connection so callers don't need to pass one in.
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


def _load_runtime_settings() -> None:
    """Override module-level Pi-hole vars from the database.

    Called once at startup *after* ``bootstrap_settings``.  This ensures that
    any values updated via the UI survive service restarts, overriding the
    original environment variables.
    """
    global PIHOLE_URL, PIHOLE_PASSWORD
    db_url = get_setting("PIHOLE_URL", PIHOLE_URL).rstrip("/")
    db_pw  = get_setting("PIHOLE_PASSWORD", PIHOLE_PASSWORD)
    if db_url:
        PIHOLE_URL = db_url
    if db_pw:
        PIHOLE_PASSWORD = db_pw


bootstrap_settings()
_load_runtime_settings()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def rows_to_list(conn, query: str, params=None) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(query, params or ())
        return [dict(r) for r in cur.fetchall()]


def serialize(obj):
    """JSON-serialise datetime objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serialisable")


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# --- API: Devices ---

@app.route("/api/devices")
def api_devices():
    conn = get_db()
    rows = rows_to_list(
        conn,
        """
        SELECT d.*, u.username AS owner_username, u.display_name AS owner_display_name,
               COALESCE(
                   json_agg(json_build_object('id', g.id, 'name', g.name, 'pihole_group_name', g.pihole_group_name))
                   FILTER (WHERE g.id IS NOT NULL), '[]'
               ) AS groups
        FROM devices d
        LEFT JOIN users u ON u.id = d.owner_id
        LEFT JOIN device_groups dg ON dg.device_id = d.id
        LEFT JOIN groups g ON g.id = dg.group_id
        GROUP BY d.id, u.username, u.display_name
        ORDER BY d.last_seen DESC
        """,
    )
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/devices/<int:device_id>", methods=["GET"])
def api_device(device_id: int):
    conn = get_db()
    rows = rows_to_list(
        conn,
        """
        SELECT d.*, u.username AS owner_username, u.display_name AS owner_display_name
        FROM devices d
        LEFT JOIN users u ON u.id = d.owner_id
        WHERE d.id=%s
        """,
        (device_id,),
    )
    conn.close()
    if not rows:
        return jsonify({"error": "not found"}), 404
    return Response(json.dumps(rows[0], default=serialize), mimetype="application/json")


@app.route("/api/devices/<int:device_id>/status", methods=["PUT"])
def api_set_device_status(device_id: int):
    """Allow the UI to trust / quarantine / block / promote-to-IoT a device.

    When a device is set to ``iot`` for the *first time* (no prior learning
    session exists) the status is changed to ``iot_learning`` instead and an
    ``iot_learning_start_requested`` event is published so the discovery
    service can create the Pi-hole learning group and record the session.

    Devices that have already completed learning are moved to ``iot`` directly.
    """
    body = request.get_json(force=True)
    new_status = body.get("status")
    if new_status not in ("trusted", "quarantined", "blocked", "iot"):
        return jsonify({"error": "invalid status"}), 400

    conn = get_db()

    # Fetch the device in one query — needed for owner check, IP, and MAC.
    rows = rows_to_list(
        conn,
        "SELECT id, owner_id, status, ip_address, mac_address FROM devices WHERE id=%s",
        (device_id,),
    )
    if not rows:
        conn.close()
        return jsonify({"error": "not found"}), 404
    device = rows[0]

    # Enforce: devices can only become 'trusted' when they have an owner assigned
    if new_status == "trusted" and device["owner_id"] is None:
        conn.close()
        return jsonify({"error": "device must be assigned to a user before it can be trusted"}), 422

    # ── IoT first-time promotion: start learning period instead ──────────────
    if new_status == "iot":
        session_rows = rows_to_list(
            conn,
            "SELECT id FROM iot_learning_sessions WHERE device_id=%s",
            (device_id,),
        )
        if not session_rows:
            # No prior learning session — set status to iot_learning immediately
            # and let the discovery service handle Pi-hole setup asynchronously.
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE devices SET status='iot_learning' WHERE id=%s",
                    (device_id,),
                )
            conn.commit()
            conn.close()

            rdb = get_redis()
            rdb.publish(
                "thebox:events",
                json.dumps({
                    "type": "iot_learning_start_requested",
                    "device_id": device_id,
                    "ip": device["ip_address"],
                    "mac": device["mac_address"],
                }),
            )
            return jsonify({"ok": True, "learning": True})
        # else: device already has/had a learning session — apply iot directly

    with conn.cursor() as cur:
        cur.execute("UPDATE devices SET status=%s WHERE id=%s RETURNING id", (new_status, device_id))
        if cur.rowcount == 0:
            conn.close()
            return jsonify({"error": "not found"}), 404
    conn.commit()
    conn.close()

    # Publish so guardian picks it up immediately
    rdb = get_redis()
    rdb.publish(
        "thebox:events",
        json.dumps({"type": "device_status_changed", "device_id": device_id, "status": new_status}),
    )
    return jsonify({"ok": True})


@app.route("/api/devices/<int:device_id>/iot-allowlist", methods=["GET"])
def api_iot_allowlist(device_id: int):
    conn = get_db()
    rows = rows_to_list(conn, "SELECT * FROM iot_allowlist WHERE device_id=%s ORDER BY fqdn", (device_id,))
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/devices/<int:device_id>/iot-allowlist", methods=["POST"])
def api_iot_allowlist_add(device_id: int):
    body = request.get_json(force=True)
    fqdn = (body.get("fqdn") or "").strip()
    if not fqdn:
        return jsonify({"error": "fqdn required"}), 400
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO iot_allowlist (device_id, fqdn) VALUES (%s,%s) ON CONFLICT DO NOTHING",
            (device_id, fqdn),
        )
    conn.commit()
    conn.close()
    return jsonify({"ok": True}), 201


@app.route("/api/devices/<int:device_id>/iot-allowlist/<int:entry_id>", methods=["DELETE"])
def api_iot_allowlist_remove(device_id: int, entry_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM iot_allowlist WHERE id=%s AND device_id=%s", (entry_id, device_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/devices/<int:device_id>/owner", methods=["PUT"])
def api_set_device_owner(device_id: int):
    """Assign or unassign a user as the owner of a device."""
    body = request.get_json(force=True)
    user_id = body.get("user_id")  # None / null to unassign

    conn = get_db()

    if user_id is not None:
        # Verify user exists
        rows = rows_to_list(conn, "SELECT id FROM users WHERE id=%s", (user_id,))
        if not rows:
            conn.close()
            return jsonify({"error": "user not found"}), 404

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE devices SET owner_id=%s WHERE id=%s RETURNING id",
            (user_id, device_id),
        )
        if cur.rowcount == 0:
            conn.close()
            return jsonify({"error": "device not found"}), 404
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# --- API: Users ---

@app.route("/api/users")
def api_users():
    conn = get_db()
    rows = rows_to_list(
        conn,
        """
        SELECT u.*, COUNT(DISTINCT d.id) AS device_count,
               COALESCE(
                   json_agg(json_build_object('id', g.id, 'name', g.name))
                   FILTER (WHERE g.id IS NOT NULL), '[]'
               ) AS groups
        FROM users u
        LEFT JOIN devices d ON d.owner_id = u.id
        LEFT JOIN user_groups ug ON ug.user_id = u.id
        LEFT JOIN groups g ON g.id = ug.group_id
        GROUP BY u.id
        ORDER BY u.username
        """,
    )
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/users/<int:user_id>", methods=["GET"])
def api_user(user_id: int):
    conn = get_db()
    rows = rows_to_list(conn, "SELECT * FROM users WHERE id=%s", (user_id,))
    conn.close()
    if not rows:
        return jsonify({"error": "not found"}), 404
    return Response(json.dumps(rows[0], default=serialize), mimetype="application/json")


@app.route("/api/users", methods=["POST"])
def api_create_user():
    body = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    display_name = (body.get("display_name") or "").strip() or None
    email = (body.get("email") or "").strip() or None

    if not username:
        return jsonify({"error": "username required"}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, display_name, email) VALUES (%s,%s,%s) RETURNING id",
                (username, display_name, email),
            )
            new_id = cur.fetchone()["id"]
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "username already exists"}), 409
    finally:
        conn.close()
    return jsonify({"ok": True, "id": new_id}), 201


@app.route("/api/users/<int:user_id>", methods=["PUT"])
def api_update_user(user_id: int):
    body = request.get_json(force=True)
    display_name = (body.get("display_name") or "").strip() or None
    email = (body.get("email") or "").strip() or None

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET display_name=%s, email=%s, updated_at=NOW() WHERE id=%s RETURNING id",
            (display_name, email, user_id),
        )
        if cur.rowcount == 0:
            conn.close()
            return jsonify({"error": "not found"}), 404
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def api_delete_user(user_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM users WHERE id=%s RETURNING id", (user_id,))
        if cur.rowcount == 0:
            conn.close()
            return jsonify({"error": "not found"}), 404
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# --- API: Groups ---

@app.route("/api/groups")
def api_groups():
    conn = get_db()
    rows = rows_to_list(
        conn,
        """
        SELECT g.*,
               COUNT(DISTINCT ug.user_id)   AS user_count,
               COUNT(DISTINCT dg.device_id) AS device_count
        FROM groups g
        LEFT JOIN user_groups  ug ON ug.group_id = g.id
        LEFT JOIN device_groups dg ON dg.group_id = g.id
        GROUP BY g.id
        ORDER BY g.name
        """,
    )
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/groups/<int:group_id>", methods=["GET"])
def api_group(group_id: int):
    conn = get_db()
    rows = rows_to_list(conn, "SELECT * FROM groups WHERE id=%s", (group_id,))
    conn.close()
    if not rows:
        return jsonify({"error": "not found"}), 404
    return Response(json.dumps(rows[0], default=serialize), mimetype="application/json")


@app.route("/api/groups", methods=["POST"])
def api_create_group():
    body = request.get_json(force=True)
    name = (body.get("name") or "").strip()
    description = (body.get("description") or "").strip() or None
    pihole_group_name = (body.get("pihole_group_name") or "").strip() or None

    if not name:
        return jsonify({"error": "name required"}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO groups (name, description, pihole_group_name) VALUES (%s,%s,%s) RETURNING id",
                (name, description, pihole_group_name),
            )
            new_id = cur.fetchone()["id"]
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "group name already exists"}), 409
    finally:
        conn.close()
    return jsonify({"ok": True, "id": new_id}), 201


@app.route("/api/groups/<int:group_id>", methods=["PUT"])
def api_update_group(group_id: int):
    body = request.get_json(force=True)
    description = (body.get("description") or "").strip() or None
    pihole_group_name = (body.get("pihole_group_name") or "").strip() or None

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE groups SET description=%s, pihole_group_name=%s, updated_at=NOW() WHERE id=%s RETURNING id",
            (description, pihole_group_name, group_id),
        )
        if cur.rowcount == 0:
            conn.close()
            return jsonify({"error": "not found"}), 404
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>", methods=["DELETE"])
def api_delete_group(group_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM groups WHERE id=%s RETURNING id", (group_id,))
        if cur.rowcount == 0:
            conn.close()
            return jsonify({"error": "not found"}), 404
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/users", methods=["GET"])
def api_group_users(group_id: int):
    conn = get_db()
    rows = rows_to_list(
        conn,
        """
        SELECT u.* FROM users u
        JOIN user_groups ug ON ug.user_id = u.id
        WHERE ug.group_id = %s
        ORDER BY u.username
        """,
        (group_id,),
    )
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/groups/<int:group_id>/users/<int:user_id>", methods=["PUT"])
def api_group_add_user(group_id: int, user_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO user_groups (user_id, group_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", (user_id, group_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/users/<int:user_id>", methods=["DELETE"])
def api_group_remove_user(group_id: int, user_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM user_groups WHERE user_id=%s AND group_id=%s", (user_id, group_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/devices", methods=["GET"])
def api_group_devices(group_id: int):
    conn = get_db()
    rows = rows_to_list(
        conn,
        """
        SELECT d.* FROM devices d
        JOIN device_groups dg ON dg.device_id = d.id
        WHERE dg.group_id = %s
        ORDER BY d.ip_address
        """,
        (group_id,),
    )
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/groups/<int:group_id>/devices/<int:device_id>", methods=["PUT"])
def api_group_add_device(group_id: int, device_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO device_groups (device_id, group_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", (device_id, group_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/devices/<int:device_id>", methods=["DELETE"])
def api_group_remove_device(group_id: int, device_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM device_groups WHERE device_id=%s AND group_id=%s", (device_id, group_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# --- API: Alerts ---

@app.route("/api/alerts")
def api_alerts():
    conn = get_db()
    rows = rows_to_list(
        conn,
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200",
    )
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["PUT"])
def api_ack_alert(alert_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE alerts SET acknowledged=TRUE WHERE id=%s", (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# --- API: Honeypot events ---

@app.route("/api/honeypot")
def api_honeypot():
    conn = get_db()
    rows = rows_to_list(
        conn,
        "SELECT * FROM honeypot_events ORDER BY created_at DESC LIMIT 200",
    )
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


# --- IoT allow-list plaintext feed ---

@app.route("/iot-allowlist.txt")
def iot_allowlist_txt():
    """Serve the IoT allow-list as plain text — one FQDN per line.

    Pi-hole should be configured to fetch this URL as an ``allow`` type adlist
    for the IoT group.  The list contains every FQDN stored in the
    ``iot_allowlist`` table (both globally-shared entries with ``device_id IS
    NULL`` and any per-device entries added manually), deduplicated and sorted
    alphabetically so Pi-hole's gravity update sees a stable, diff-friendly file.

    The endpoint requires no authentication because Pi-hole must be able to
    fetch it internally without credentials.  It is not reachable from outside
    the ``thebox_internal`` Docker network.
    """
    conn = get_db()
    rows = rows_to_list(conn, "SELECT DISTINCT fqdn FROM iot_allowlist ORDER BY fqdn")
    conn.close()
    text = "\n".join(r["fqdn"] for r in rows)
    return Response(text, mimetype="text/plain")
  
@app.route("/api/honeypot/<int:event_id>")
def api_honeypot_event(event_id: int):
    conn = get_db()
    rows = rows_to_list(
        conn,
        "SELECT * FROM honeypot_events WHERE id=%s",
        (event_id,),
    )
    conn.close()
    if not rows:
        return jsonify({"error": "not found"}), 404
    return Response(json.dumps(rows[0], default=serialize), mimetype="application/json")


# --- Pi-hole helpers ---------------------------------------------------------

# Module-level SID cache: (sid, acquired_at_monotonic)
_pihole_sid_cache: tuple[str, float] | None = None
_pihole_sid_lock = threading.Lock()
# Pi-hole v6 sessions last 300 s by default; refresh 60 s before expiry.
# Tunable via the PIHOLE_SID_TTL setting in the database (seeded from env var).
_PIHOLE_SID_TTL = float(os.environ.get("PIHOLE_SID_TTL", "240.0"))


def _pihole_authenticate() -> str | None:
    """Return a cached Pi-hole v6 session ID, refreshing it when stale.

    Caches the SID for ``_PIHOLE_SID_TTL`` seconds so that frequent calls to
    ``get_pihole_stats()`` do not hammer the Pi-hole auth endpoint and trigger
    429 Too Many Requests responses.

    Returns ``None`` when Pi-hole is not configured, the password is empty, or
    authentication fails.
    """
    global _pihole_sid_cache

    if not PIHOLE_URL or not PIHOLE_PASSWORD:
        return None

    with _pihole_sid_lock:
        now = time.monotonic()
        if _pihole_sid_cache is not None:
            sid, acquired = _pihole_sid_cache
            if now - acquired < _PIHOLE_SID_TTL:
                return sid
            # Session expired — clear cache and re-authenticate
            _pihole_sid_cache = None

        try:
            resp = requests.post(
                f"{PIHOLE_URL}/api/auth",
                json={"password": PIHOLE_PASSWORD},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
            sid = data.get("session", {}).get("sid")
            if not sid:
                log.warning("pihole_auth_no_sid", response=data)
                return None
            _pihole_sid_cache = (sid, time.monotonic())
            return sid
        except Exception as exc:
            log.warning("pihole_auth_failed", error=str(exc))
            return None


def get_pihole_stats() -> dict:
    """Fetch summary statistics from the Pi-hole v6 API.

    Returns a dict with DNS query counts, blocking ratio, gravity list size,
    and client counts.  Returns an empty dict when Pi-hole is unreachable or
    not configured.
    """
    if not PIHOLE_URL:
        return {}

    sid = _pihole_authenticate()
    params = {"sid": sid} if sid else {}
    try:
        resp = requests.get(
            f"{PIHOLE_URL}/api/stats/summary",
            params=params,
            timeout=10,
        )
        if resp.status_code == 401:
            # Cached session may have been invalidated server-side; force refresh.
            with _pihole_sid_lock:
                _pihole_sid_cache = None
            log.warning("pihole_stats_failed", error="401 Unauthorized -- session invalidated, will re-authenticate on next request")
            return {}
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.warning("pihole_stats_failed", error=str(exc))
        return {}

    queries = data.get("queries", {})
    gravity = data.get("gravity", {})
    clients = data.get("clients", {})

    return {
        "queries_total": queries.get("total", 0),
        "queries_blocked": queries.get("blocked", 0),
        "percent_blocked": round(queries.get("percent_blocked", 0.0), 1),
        "domains_blocked": gravity.get("domains_being_blocked", 0),
        "clients_active": clients.get("active", 0),
        "clients_total": clients.get("total", 0),
        "status": data.get("status", "unknown"),
    }


# --- API: Pi-hole statistics ---

@app.route("/api/pihole")
def api_pihole():
    stats = get_pihole_stats()
    if not stats:
        return jsonify({"error": "Pi-hole unavailable or not configured"}), 503
    return jsonify(stats)


# --- API: Stats summary ---

@app.route("/api/stats")
def api_stats():
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE status='trusted')     AS trusted,
                COUNT(*) FILTER (WHERE status='quarantined') AS quarantined,
                COUNT(*) FILTER (WHERE status='blocked')     AS blocked,
                COUNT(*) FILTER (WHERE status='iot')         AS iot,
                COUNT(*) FILTER (WHERE status='new')         AS new_devices,
                COUNT(*)                                     AS total
            FROM devices
            """
        )
        device_stats = dict(cur.fetchone())

        cur.execute("SELECT COUNT(*) AS total FROM honeypot_events")
        hp_total = cur.fetchone()["total"]

        cur.execute(
            "SELECT COUNT(*) AS unacked FROM alerts WHERE acknowledged=FALSE AND level IN ('warning','critical')"
        )
        unacked = cur.fetchone()["unacked"]

    conn.close()
    return jsonify(
        {
            "devices": device_stats,
            "honeypot_hits": hp_total,
            "unacked_alerts": unacked,
        }
    )


# --- API: Settings ---

# Build a quick-lookup set of valid setting keys from the catalogue.
_VALID_SETTING_KEYS = {entry[0] for entry in _SETTINGS_CATALOGUE}


@app.route("/api/settings")
def api_settings():
    """Return all settings grouped by category."""
    conn = get_db()
    rows = rows_to_list(conn, "SELECT key, value, category, description, updated_at FROM settings ORDER BY category, key")
    conn.close()
    # Group by category for the UI
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        cat = row["category"]
        grouped.setdefault(cat, []).append(row)
    return Response(json.dumps(grouped, default=serialize), mimetype="application/json")


@app.route("/api/settings/<key>", methods=["PUT"])
def api_update_setting(key: str):
    """Update a single setting value."""
    if key not in _VALID_SETTING_KEYS:
        return jsonify({"error": f"Unknown setting key: {key}"}), 400
    data = request.get_json(silent=True) or {}
    if "value" not in data:
        return jsonify({"error": "Missing 'value' field"}), 400
    value = str(data["value"])
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE settings SET value = %s, updated_at = NOW()
                   WHERE key = %s""",
                (value, key),
            )
            if cur.rowcount == 0:
                conn.close()
                return jsonify({"error": f"Setting '{key}' not found"}), 404
        conn.commit()
    finally:
        conn.close()
    # Apply Pi-hole credentials immediately so the current process benefits.
    if key in ("PIHOLE_URL", "PIHOLE_PASSWORD"):
        _load_runtime_settings()
        # Invalidate the cached Pi-hole session so it re-authenticates.
        global _pihole_sid_cache
        with _pihole_sid_lock:
            _pihole_sid_cache = None
    return jsonify({"ok": True, "key": key, "value": value})


@app.route("/api/settings", methods=["PUT"])
def api_update_settings_bulk():
    """Update multiple settings at once.  Body: {key: value, ...}"""
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "Empty request body"}), 400
    unknown = [k for k in data if k not in _VALID_SETTING_KEYS]
    if unknown:
        return jsonify({"error": f"Unknown setting keys: {', '.join(unknown)}"}), 400
    conn = get_db()
    try:
        with conn.cursor() as cur:
            for k, v in data.items():
                cur.execute(
                    "UPDATE settings SET value = %s, updated_at = NOW() WHERE key = %s",
                    (str(v), k),
                )
        conn.commit()
    finally:
        conn.close()
    if any(k in ("PIHOLE_URL", "PIHOLE_PASSWORD") for k in data):
        _load_runtime_settings()
        global _pihole_sid_cache
        with _pihole_sid_lock:
            _pihole_sid_cache = None
    return jsonify({"ok": True, "updated": list(data.keys())})


# --- SSE stream ---

@app.route("/api/events")
def sse_stream():
    """Server-Sent Events endpoint for live updates."""
    q: queue.Queue = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_subscribers.append(q)

    def generate():
        try:
            yield "data: {\"type\":\"connected\"}\n\n"
            while True:
                try:
                    payload = q.get(timeout=30)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    # Send keep-alive comment
                    yield ": keep-alive\n\n"
        finally:
            with _sse_lock:
                try:
                    _sse_subscribers.remove(q)
                except ValueError:
                    pass

    return Response(generate(), mimetype="text/event-stream")


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, threaded=True)
