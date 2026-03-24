"""
TheBox — Web Dashboard
========================
Flask application that provides the unified management UI for all TheBox
services.  Uses Server-Sent Events (SSE) to push live alerts to the browser
and exposes a REST API for the front-end JavaScript.
"""

import functools
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
from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# ─── Configuration ───────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
SECRET_KEY = os.environ.get("SECRET_KEY", "")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
PIHOLE_URL = os.environ.get("PIHOLE_URL", "").rstrip("/")
PIHOLE_PASSWORD = os.environ.get("PIHOLE_PASSWORD", "")

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
    ``user_groups``, ``device_groups``, ``alerts``, ``honeypot_events``,
    ``scan_runs``.
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
        # scan_runs — discovery scan history, dashboard provides read-only view
        """CREATE TABLE IF NOT EXISTS scan_runs (
            id              SERIAL PRIMARY KEY,
            started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            finished_at     TIMESTAMPTZ,
            network_range   VARCHAR(64) NOT NULL,
            devices_found   INTEGER NOT NULL DEFAULT 0,
            new_devices     INTEGER NOT NULL DEFAULT 0,
            status          VARCHAR(32) NOT NULL DEFAULT 'running'
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
        # Migration: add password_hash for dashboard login
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255)",
        # scan_runs — populated by discovery after each nmap scan cycle
        """CREATE TABLE IF NOT EXISTS scan_runs (
            id              SERIAL PRIMARY KEY,
            started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            finished_at     TIMESTAMPTZ,
            network_range   VARCHAR(64) NOT NULL,
            devices_found   INTEGER NOT NULL DEFAULT 0,
            new_devices     INTEGER NOT NULL DEFAULT 0,
            status          VARCHAR(32) NOT NULL DEFAULT 'running'
        )""",
        "CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at)",
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


def login_required(f):
    """Decorator that enforces an active session.

    API routes (path starts with /api/) receive a JSON 401 response.
    Browser routes are redirected to /login.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        conn = get_db()
        rows = rows_to_list(
            conn,
            "SELECT id, username, display_name, password_hash FROM users WHERE username=%s",
            (username,),
        )
        conn.close()
        if rows and rows[0].get("password_hash") and check_password_hash(rows[0]["password_hash"], password):
            session.clear()
            session["user_id"] = rows[0]["id"]
            session["username"] = rows[0]["username"]
            session["display_name"] = rows[0]["display_name"] or rows[0]["username"]
            next_url = request.form.get("next") or request.args.get("next") or ""
            # Guard against open-redirect: only allow relative paths on this host.
            if not next_url or not next_url.startswith("/") or next_url.startswith("//"):
                next_url = url_for("index")
            return redirect(next_url)
        error = "Invalid username or password."
    return render_template("login.html", error=error, next=request.args.get("next", ""))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


# --- API: Devices ---

_VALID_DEVICE_STATUSES = frozenset(
    {"new", "trusted", "quarantined", "blocked", "iot", "iot_learning"}
)


@app.route("/api/devices")
@login_required
def api_devices():
    status_filter = request.args.get("status", "").strip()
    if status_filter and status_filter not in _VALID_DEVICE_STATUSES:
        return jsonify({"error": f"invalid status filter: {status_filter}"}), 400

    query = """
        SELECT d.*, u.username AS owner_username, u.display_name AS owner_display_name,
               COALESCE(
                   json_agg(json_build_object('id', g.id, 'name', g.name, 'pihole_group_name', g.pihole_group_name))
                   FILTER (WHERE g.id IS NOT NULL), '[]'
               ) AS groups
        FROM devices d
        LEFT JOIN users u ON u.id = d.owner_id
        LEFT JOIN device_groups dg ON dg.device_id = d.id
        LEFT JOIN groups g ON g.id = dg.group_id
        {where}
        GROUP BY d.id, u.username, u.display_name
        ORDER BY d.last_seen DESC
    """
    conn = get_db()
    if status_filter:
        rows = rows_to_list(
            conn,
            query.format(where="WHERE d.status = %s"),
            (status_filter,),
        )
    else:
        rows = rows_to_list(conn, query.format(where=""))
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/devices/<int:device_id>", methods=["GET"])
@login_required
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
@login_required
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
@login_required
def api_iot_allowlist(device_id: int):
    conn = get_db()
    rows = rows_to_list(conn, "SELECT * FROM iot_allowlist WHERE device_id=%s ORDER BY fqdn", (device_id,))
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/devices/<int:device_id>/iot-allowlist", methods=["POST"])
@login_required
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
@login_required
def api_iot_allowlist_remove(device_id: int, entry_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM iot_allowlist WHERE id=%s AND device_id=%s", (entry_id, device_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/devices/<int:device_id>/notes", methods=["PUT"])
@login_required
def api_set_device_notes(device_id: int):
    """Update the free-text notes field for a device."""
    body = request.get_json(force=True)
    notes = body.get("notes")  # None / null clears the notes field

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE devices SET notes=%s WHERE id=%s RETURNING id",
            (notes, device_id),
        )
        if cur.rowcount == 0:
            conn.close()
            return jsonify({"error": "device not found"}), 404
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/devices/<int:device_id>/owner", methods=["PUT"])
@login_required
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


@app.route("/api/devices/<int:device_id>", methods=["PATCH"])
def api_patch_device(device_id: int):
    """Update editable device fields (currently: notes)."""
    body = request.get_json(force=True)
    notes = body.get("notes", "")
    if notes is None:
        notes = ""

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE devices SET notes=%s WHERE id=%s RETURNING id",
            (None if not notes else notes, device_id),
        )
        if cur.rowcount == 0:
            conn.close()
            return jsonify({"error": "device not found"}), 404
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# --- API: Users ---

@app.route("/api/users")
@login_required
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
@login_required
def api_user(user_id: int):
    conn = get_db()
    rows = rows_to_list(conn, "SELECT * FROM users WHERE id=%s", (user_id,))
    conn.close()
    if not rows:
        return jsonify({"error": "not found"}), 404
    return Response(json.dumps(rows[0], default=serialize), mimetype="application/json")


@app.route("/api/users", methods=["POST"])
@login_required
def api_create_user():
    body = request.get_json(force=True)
    username = (body.get("username") or "").strip()
    display_name = (body.get("display_name") or "").strip() or None
    email = (body.get("email") or "").strip() or None
    password = (body.get("password") or "").strip()
    password_hash = generate_password_hash(password) if password else None

    if not username:
        return jsonify({"error": "username required"}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, display_name, email, password_hash) VALUES (%s,%s,%s,%s) RETURNING id",
                (username, display_name, email, password_hash),
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
@login_required
def api_update_user(user_id: int):
    body = request.get_json(force=True)
    display_name = (body.get("display_name") or "").strip() or None
    email = (body.get("email") or "").strip() or None
    password = (body.get("password") or "").strip()

    conn = get_db()
    with conn.cursor() as cur:
        if password:
            cur.execute(
                "UPDATE users SET display_name=%s, email=%s, password_hash=%s, updated_at=NOW() WHERE id=%s RETURNING id",
                (display_name, email, generate_password_hash(password), user_id),
            )
        else:
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
@login_required
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
@login_required
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
@login_required
def api_group(group_id: int):
    conn = get_db()
    rows = rows_to_list(conn, "SELECT * FROM groups WHERE id=%s", (group_id,))
    conn.close()
    if not rows:
        return jsonify({"error": "not found"}), 404
    return Response(json.dumps(rows[0], default=serialize), mimetype="application/json")


@app.route("/api/groups", methods=["POST"])
@login_required
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
@login_required
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
@login_required
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
@login_required
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
@login_required
def api_group_add_user(group_id: int, user_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO user_groups (user_id, group_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", (user_id, group_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/users/<int:user_id>", methods=["DELETE"])
@login_required
def api_group_remove_user(group_id: int, user_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM user_groups WHERE user_id=%s AND group_id=%s", (user_id, group_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/devices", methods=["GET"])
@login_required
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
@login_required
def api_group_add_device(group_id: int, device_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO device_groups (device_id, group_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", (device_id, group_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/groups/<int:group_id>/devices/<int:device_id>", methods=["DELETE"])
@login_required
def api_group_remove_device(group_id: int, device_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM device_groups WHERE device_id=%s AND group_id=%s", (device_id, group_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# --- API: Alerts ---

@app.route("/api/alerts")
@login_required
def api_alerts():
    conn = get_db()
    rows = rows_to_list(
        conn,
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200",
    )
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["PUT"])
@login_required
def api_ack_alert(alert_id: int):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE alerts SET acknowledged=TRUE WHERE id=%s", (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/alerts/acknowledge-all", methods=["PUT"])
def api_ack_all_alerts():
    """Acknowledge every outstanding warning/critical alert in one request."""
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE alerts SET acknowledged=TRUE WHERE acknowledged=FALSE AND level IN ('warning','critical')"
        )
        updated = cur.rowcount
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "acknowledged": updated})


# --- API: Honeypot events ---

@app.route("/api/honeypot")
@login_required
def api_honeypot():
    conn = get_db()
    rows = rows_to_list(
        conn,
        "SELECT * FROM honeypot_events ORDER BY created_at DESC LIMIT 200",
    )
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


# --- API: Scan runs ---

@app.route("/api/scan-runs")
def api_scan_runs():
    conn = get_db()
    rows = rows_to_list(
        conn,
        """SELECT id, started_at, finished_at, network_range,
                  devices_found, new_devices, status
           FROM scan_runs ORDER BY started_at DESC LIMIT 100""",
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
@login_required
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


@app.route("/api/devices/<int:device_id>/honeypot")
def api_device_honeypot(device_id: int):
    """Return honeypot events associated with a specific device."""
    conn = get_db()
    # Verify the device exists
    device_rows = rows_to_list(conn, "SELECT id FROM devices WHERE id=%s", (device_id,))
    if not device_rows:
        conn.close()
        return jsonify({"error": "not found"}), 404
    rows = rows_to_list(
        conn,
        "SELECT * FROM honeypot_events WHERE device_id=%s ORDER BY created_at DESC LIMIT 200",
        (device_id,),
    )
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


# --- Pi-hole helpers ---------------------------------------------------------

# Module-level SID cache: (sid, acquired_at_monotonic)
_pihole_sid_cache: tuple[str, float] | None = None
_pihole_sid_lock = threading.Lock()
# Pi-hole v6 sessions last 300 s by default; refresh 60 s before expiry.
# Tunable via PIHOLE_SID_TTL env var (seconds).
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
@login_required
def api_pihole():
    stats = get_pihole_stats()
    if not stats:
        return jsonify({"error": "Pi-hole unavailable or not configured"}), 503
    return jsonify(stats)


# --- API: Stats summary ---

@app.route("/api/stats")
@login_required
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


# --- API: Health check ---

@app.route("/api/health")
def api_health():
    """Return service health including database and Redis connectivity."""
    checks: dict[str, str] = {}
    ok = True

    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        conn.close()
        checks["database"] = "ok"
    except Exception as exc:  # pylint: disable=broad-except
        checks["database"] = f"error: {exc}"
        ok = False

    try:
        rdb = get_redis()
        rdb.ping()
        checks["redis"] = "ok"
    except Exception as exc:  # pylint: disable=broad-except
        checks["redis"] = f"error: {exc}"
        ok = False

    status_code = 200 if ok else 503
    return jsonify({"status": "ok" if ok else "degraded", "checks": checks}), status_code


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
