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
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
import redis
import structlog
from flask import Flask, Response, jsonify, render_template, request

# ─── Configuration ───────────────────────────────────────────────────────────
DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
SECRET_KEY = os.environ.get("SECRET_KEY", "")
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

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
    """Allow the UI to trust / quarantine / block a device.

    Devices leaving quarantine must be assigned as IoT or have an owner assigned.
    """
    body = request.get_json(force=True)
    new_status = body.get("status")
    if new_status not in ("trusted", "quarantined", "blocked", "iot"):
        return jsonify({"error": "invalid status"}), 400

    conn = get_db()

    # Enforce: devices can only become 'trusted' when they have an owner assigned
    if new_status == "trusted":
        rows = rows_to_list(conn, "SELECT owner_id, status FROM devices WHERE id=%s", (device_id,))
        if not rows:
            conn.close()
            return jsonify({"error": "not found"}), 404
        if rows[0]["owner_id"] is None:
            conn.close()
            return jsonify({"error": "device must be assigned to a user before it can be trusted"}), 422

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
