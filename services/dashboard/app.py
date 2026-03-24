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
import re
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

# ─── Dynamic settings catalogue (sourced from .env.example) ──────────────────
# Paths inside the container.  Both files are bind-mounted read-only from the
# repo root by docker-compose.yml so the parser always sees the latest version.
_ENV_EXAMPLE_PATH = os.environ.get("ENV_EXAMPLE_PATH", "/app/.env.example")
_ENV_PATH         = os.environ.get("ENV_PATH",         "/app/.env")

# Keys present in .env.example that must NOT appear in the runtime settings
# table because they are infrastructure-level or security-critical values that
# must be set at deploy time and cannot be safely changed via the UI.
_ENV_EXAMPLE_SKIP_KEYS: frozenset[str] = frozenset({
    "TZ",
    "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD",
    "PIHOLE_DNS_PORT", "PIHOLE_WEB_PORT",
    "DASHBOARD_PORT",
    "SECRET_KEY",
})

# Regex that matches section-header comments like:  # ─── Name ─────────────
# The ─ characters are U+2500 BOX DRAWINGS LIGHT HORIZONTAL.
_SECTION_HEADER_RE = re.compile(r"^#\s*─+\s+(.+?)\s+─+")


def _section_to_category(section_name: str) -> str:
    """Map a .env.example section header text to an internal category slug."""
    s = section_name.lower()
    if "postgresql" in s:
        return "general"        # all keys in this section are skipped anyway
    if "pi-hole" in s or "pihole" in s:
        return "pihole"
    if "dashboard" in s:
        return "pihole"         # only PIHOLE_SID_TTL lives in this section
    if "discovery" in s:
        return "discovery"
    if "guardian" in s:
        return "guardian"
    if "iot" in s:
        return "iot"
    if any(w in s for w in ("honeypot", "sweep", "protocol interaction", "severity")):
        return "honeypot"
    if "redirector" in s:
        return "redirector"
    if "logging" in s:
        return "general"
    return "general"


def _parse_env_example() -> list[tuple[str, str, str, str]]:
    """Parse .env.example and return ``(key, value, category, description)`` tuples.

    The ``value`` in each tuple is the raw default taken from the ``.env.example``
    file.  Callers should override this with values from ``os.environ`` or the
    ``.env`` file before writing to the database.

    * Section-header lines (``# ─── Name ───``) set the current category.
    * Consecutive comment lines directly above a ``KEY=value`` line are joined
      into the description for that key.
    * An empty line resets the accumulated description.
    * Keys in ``_ENV_EXAMPLE_SKIP_KEYS`` are omitted from the output.

    Returns an empty list when the file cannot be found (fails silently so that
    a missing mount does not crash the dashboard on startup).
    """
    entries: list[tuple[str, str, str, str]] = []
    if not os.path.exists(_ENV_EXAMPLE_PATH):
        return entries

    current_category = "general"
    pending_comments: list[str] = []

    with open(_ENV_EXAMPLE_PATH, encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")

            # ── Section header?
            m = _SECTION_HEADER_RE.match(line)
            if m:
                current_category = _section_to_category(m.group(1).strip())
                pending_comments = []
                continue

            # ── Empty line → reset pending description
            if not line.strip():
                pending_comments = []
                continue

            # ── Comment line (not a section header)
            if line.startswith("#"):
                text = line.lstrip("#").strip()
                if text:
                    pending_comments.append(text)
                continue

            # ── KEY=value line
            if "=" in line:
                key, _, raw_val = line.partition("=")
                key = key.strip()
                if key and key not in _ENV_EXAMPLE_SKIP_KEYS:
                    description = " ".join(pending_comments)
                    entries.append((key, raw_val.strip(), current_category, description))
                pending_comments = []

    return entries


def _read_env_file() -> dict[str, str]:
    """Read ``KEY=value`` pairs from the ``.env`` file.

    Returns an empty dict when the file does not exist (e.g. on a fresh install
    before the user has created it) or cannot be read.  Shell-style quoting is
    not evaluated — values are returned exactly as written in the file.
    """
    env: dict[str, str] = {}
    if not os.path.exists(_ENV_PATH):
        return env
    try:
        with open(_ENV_PATH, encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
    except OSError as exc:
        # Log at warning level; the DB will already have correct values from a
        # previous successful bootstrap so this is non-fatal.
        logging.getLogger(__name__).warning("env_file_read_failed path=%s error=%s", _ENV_PATH, exc)
    return env


# Valid setting keys — populated from .env.example by bootstrap_settings().
# Used to reject unknown keys in the PUT /api/settings endpoints.
_VALID_SETTING_KEYS: frozenset[str] = frozenset()

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

_MIGRATIONS_DIR = "/app/migrations"
REQUIRED_MIGRATIONS = ["0001", "0002", "0003", "0004", "0005"]


def apply_migrations(required_versions):
    """Apply all required migrations that have not yet been recorded.

    Reads SQL from ``_MIGRATIONS_DIR``/NNNN_*.sql files and applies each
    version in ascending order, skipping any already recorded in
    schema_migrations.
    """
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version     VARCHAR(16) NOT NULL PRIMARY KEY,
                    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
        conn.commit()
        for version in sorted(required_versions):
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = %s",
                    (version,)
                )
                if cur.fetchone():
                    continue
                sql_file = None
                for name in sorted(os.listdir(_MIGRATIONS_DIR)):
                    if name.startswith(f"{version}_") and name.endswith(".sql"):
                        sql_file = os.path.join(_MIGRATIONS_DIR, name)
                        break
                if sql_file is None:
                    raise RuntimeError(
                        f"Migration {version} not found in {_MIGRATIONS_DIR}"
                    )
                with open(sql_file) as fh:
                    sql = fh.read()
                cur.execute(sql)
                cur.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)"
                    " ON CONFLICT (version) DO NOTHING",
                    (version,)
                )
                conn.commit()
                log.info("migration_applied", version=version, file=os.path.basename(sql_file))
    finally:
        conn.close()
    log.info("migrations_complete")


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

# Called at module level (not inside if __name__) so migrations are applied
# whether the app is run directly or served by a WSGI host (gunicorn, etc.).
apply_migrations(REQUIRED_MIGRATIONS)


# ─── Settings helpers ────────────────────────────────────────────────────────

def bootstrap_settings() -> None:
    """Seed the settings table from ``.env.example`` (and ``.env``) on every startup.

    How new keys are handled
    ------------------------
    On *every* dashboard restart the catalogue is re-read from ``.env.example``.
    Keys that are **missing** from the ``settings`` table are inserted using the
    best available value:

      1. ``os.environ[key]``  — set by docker-compose from ``.env`` (highest priority)
      2. ``.env`` file value  — for vars not forwarded to this container's env
      3. ``.env.example`` default — absolute fallback

    Keys that **already exist** in the table keep their current ``value`` so that
    any changes made through the UI survive restarts.  Only ``category`` and
    ``description`` are refreshed from ``.env.example`` so that documentation
    improvements are always picked up.

    Effect
    ------
    Newly added variables in ``.env.example`` are automatically inserted into
    the DB on the next dashboard restart without any manual migration.

    The global ``_VALID_SETTING_KEYS`` is also updated so that the API
    immediately accepts the new keys.
    """
    global _VALID_SETTING_KEYS

    catalogue = _parse_env_example()
    if not catalogue:
        log.warning("settings_catalogue_empty",
                    msg=".env.example not found or empty; settings table may be incomplete",
                    path=_ENV_EXAMPLE_PATH)
        return

    env_file = _read_env_file()

    conn = get_db()
    try:
        with conn.cursor() as cur:
            for key, example_default, category, description in catalogue:
                # Value priority: process env (docker-compose) → .env file
                # (for vars not forwarded to this container) → .env.example default.
                value = os.environ.get(key) or env_file.get(key) or example_default
                cur.execute(
                    """INSERT INTO settings (key, value, category, description)
                       VALUES (%s, %s, %s, %s)
                       ON CONFLICT (key) DO UPDATE SET
                         category    = EXCLUDED.category,
                         description = EXCLUDED.description""",
                    (key, value, category, description),
                )
        conn.commit()
        log.info("settings_bootstrapped", count=len(catalogue))
    finally:
        conn.close()

    # Refresh valid-key set so the PUT /api/settings endpoints accept any key
    # that was just added to .env.example.
    _VALID_SETTING_KEYS = frozenset(key for key, _, _, _ in catalogue)


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
    return render_template("index.html", active_page="dashboard")


@app.route("/honeypot")
@login_required
def honeypot_page():
    return render_template("honeypot.html", active_page="honeypot")


@app.route("/scans")
@login_required
def scans_page():
    return render_template("scans.html", active_page="scans")


@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html", active_page="settings")


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
                COUNT(*) FILTER (WHERE status='trusted')      AS trusted,
                COUNT(*) FILTER (WHERE status='quarantined')  AS quarantined,
                COUNT(*) FILTER (WHERE status='blocked')      AS blocked,
                COUNT(*) FILTER (WHERE status='iot')          AS iot,
                COUNT(*) FILTER (WHERE status='iot_learning') AS iot_learning,
                COUNT(*) FILTER (WHERE status='new')          AS new_devices,
                COUNT(*)                                      AS total
            FROM devices
            """
        )
        device_stats = dict(cur.fetchone())

        cur.execute("SELECT COUNT(*) AS total FROM honeypot_events")
        hp_total = cur.fetchone()["total"]

        cur.execute(
            "SELECT COUNT(*) AS critical FROM honeypot_events WHERE severity IN ('critical','high')"
        )
        hp_critical = cur.fetchone()["critical"]

        cur.execute(
            "SELECT COUNT(*) AS unacked FROM alerts WHERE acknowledged=FALSE AND level IN ('warning','critical')"
        )
        unacked = cur.fetchone()["unacked"]

        cur.execute("SELECT COUNT(*) AS total FROM scan_runs")
        scan_runs = cur.fetchone()["total"]

    conn.close()
    return jsonify(
        {
            "devices": device_stats,
            "honeypot_hits": hp_total,
            "honeypot_critical": hp_critical,
            "unacked_alerts": unacked,
            "scan_runs": scan_runs,
        }
    )


# --- API: Settings ---

# _VALID_SETTING_KEYS is populated by bootstrap_settings() which runs at
# module load time.  It contains every key parsed from .env.example.


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
                return jsonify({"error": f"Unknown setting: {key}"}), 404
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
    # Validate against known keys.  If _VALID_SETTING_KEYS is empty (e.g.
    # .env.example was not found at startup) skip the check and rely on the
    # DB UPDATE's rowcount to detect unknown keys below.
    if _VALID_SETTING_KEYS:
        unknown = [k for k in data if k not in _VALID_SETTING_KEYS]
        if unknown:
            return jsonify({"error": f"Unknown setting keys: {', '.join(unknown)}"}), 400
    conn = get_db()
    updated: list[str] = []
    not_found: list[str] = []
    try:
        with conn.cursor() as cur:
            for k, v in data.items():
                cur.execute(
                    "UPDATE settings SET value = %s, updated_at = NOW() WHERE key = %s",
                    (str(v), k),
                )
                if cur.rowcount:
                    updated.append(k)
                else:
                    not_found.append(k)
        conn.commit()
    finally:
        conn.close()
    if not updated:
        return jsonify({"error": f"No settings updated; unknown keys: {', '.join(not_found)}"}), 404
    if any(k in ("PIHOLE_URL", "PIHOLE_PASSWORD") for k in updated):
        _load_runtime_settings()
        global _pihole_sid_cache
        with _pihole_sid_lock:
            _pihole_sid_cache = None
    result: dict = {"ok": True, "updated": updated}
    if not_found:
        result["not_found"] = not_found
    return jsonify(result)
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
