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
    rows = rows_to_list(conn, "SELECT * FROM devices ORDER BY last_seen DESC")
    conn.close()
    return Response(json.dumps(rows, default=serialize), mimetype="application/json")


@app.route("/api/devices/<int:device_id>", methods=["GET"])
def api_device(device_id: int):
    conn = get_db()
    rows = rows_to_list(conn, "SELECT * FROM devices WHERE id=%s", (device_id,))
    conn.close()
    if not rows:
        return jsonify({"error": "not found"}), 404
    return Response(json.dumps(rows[0], default=serialize), mimetype="application/json")


@app.route("/api/devices/<int:device_id>/status", methods=["PUT"])
def api_set_device_status(device_id: int):
    """Allow the UI to trust / quarantine / block a device."""
    body = request.get_json(force=True)
    new_status = body.get("status")
    if new_status not in ("trusted", "quarantined", "blocked", "iot"):
        return jsonify({"error": "invalid status"}), 400

    conn = get_db()
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
