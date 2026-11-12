"""LLM Deception Toolkit - Flask app.

Trap endpoints (public, meant to be hit by bots and agents):
  POST /honeypot                 rate-based bot detection
  GET  /c/<token>                canary callback URL
  GET  /api/v1/keys/verify?key=  canary fake-key "validation"

Dashboard (protect with DASHBOARD_PASSWORD):
  /, /analytics, /canaries, /canary/<file>, /honeypot_logs, /honeypot/<ip>

IOC feeds (protect with FEED_TOKEN):
  /feeds/stix.json, /feeds/misp/manifest.json, /feeds/misp/<uuid>.json, /feeds/iocs.csv
"""
import hmac
import logging
import os
import threading
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, Response, abort, jsonify, render_template, request
from flask_socketio import SocketIO
from werkzeug.security import safe_join

import analytics
import canaries
import config
import enrichment
import iocs
from alerts import SlackAlerter

log = logging.getLogger("llm_deception")
DESCENDING = -1  # same value as pymongo.DESCENDING


def _now():
    return datetime.now(timezone.utc)


def _client_info():
    return {
        "user_ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
        "referer": request.headers.get("Referer", ""),
        "path": request.full_path.rstrip("?"),
        "method": request.method,
    }


def _reputation_label(result):
    if result is None:
        return "pending"
    if not result:
        return ""
    status = result.get("status")
    if status == enrichment.STATUS_CHECKED:
        return "known malicious" if result.get("known_malicious") else "not reported"
    return {"private": "internal", "disabled": "", "error": "lookup failed"}.get(status, "")


def _ts(value):
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if hasattr(value, "strftime") else str(value)


class HoneypotTracker:
    """Sliding-window request counter per client IP (thread-safe, bounded)."""

    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits = defaultdict(list)
        self._lock = threading.Lock()

    def record(self, ip, now):
        """Record a hit. Returns (count_in_window, newly_flagged)."""
        with self._lock:
            hits = [t for t in self._hits[ip] if (now - t).total_seconds() <= self.window]
            hits.append(now)
            self._hits[ip] = hits
            # Prune idle IPs so memory doesn't grow forever.
            if len(self._hits) > 10_000:
                for other in [k for k, v in self._hits.items()
                              if (now - v[-1]).total_seconds() > self.window]:
                    del self._hits[other]
            count = len(hits)
            return count, count == self.max_requests + 1


def create_app(db=None, alerter=None, enricher=None, start_background=True):
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY

    if config.TRUSTED_PROXIES:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=config.TRUSTED_PROXIES)

    if db is None:
        from pymongo import MongoClient
        db = MongoClient(config.MONGO_URI)[config.DB_NAME]
    interactions = db[config.COLLECTION_INTERACTIONS]
    canary_logs = db[config.COLLECTION_CANARY]
    registry = db[config.COLLECTION_CANARY_REGISTRY]
    reputation = db[config.COLLECTION_IP_REPUTATION]

    alerter = alerter or SlackAlerter(config.SLACK_TOKEN, config.SLACK_CHANNEL)
    enricher = enricher or enrichment.Enricher(
        enrichment.providers_from_config(config), reputation, config.ENRICH_CACHE_HOURS)
    tracker = HoneypotTracker(config.HONEYPOT_MAX_REQUESTS, config.HONEYPOT_TIME_WINDOW)
    # Same-origin only for the dashboard websocket.
    socketio = SocketIO(app, async_mode="threading")

    app.extensions["llm_deception"] = {
        "db": db, "registry": registry, "socketio": socketio, "alerter": alerter,
        "enricher": enricher,
    }

    # ---------------- Auth ----------------
    def _authorised():
        if not config.DASHBOARD_PASSWORD:
            return True
        auth = request.authorization
        return bool(
            auth
            and hmac.compare_digest(auth.username or "", config.DASHBOARD_USER)
            and hmac.compare_digest(auth.password or "", config.DASHBOARD_PASSWORD)
        )

    def require_auth(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not _authorised():
                return Response("Authentication required", 401,
                                {"WWW-Authenticate": 'Basic realm="LLM Deception"'})
            return view(*args, **kwargs)
        return wrapped

    @socketio.on("connect")
    def on_connect(auth=None):
        if not _authorised():
            return False

    # ---------------- Data helpers ----------------
    def recent_honeypot(limit=10):
        return [
            {"user_ip": h.get("user_ip"), "timestamp": _ts(h.get("timestamp")),
             "user_agent": h.get("user_agent", ""), "flagged": h.get("flagged", False)}
            for h in interactions.find().sort("timestamp", DESCENDING).limit(limit)
        ]

    def recent_canary(limit=10):
        return [
            {"file": c.get("file"), "trigger": c.get("trigger"), "user_ip": c.get("user_ip"),
             "user_agent": c.get("user_agent", ""), "timestamp": _ts(c.get("timestamp")),
             "reputation": _reputation_label(c.get("enrichment", {}))}
            for c in canary_logs.find().sort("timestamp", DESCENDING).limit(limit)
        ]

    def push_update():
        socketio.emit("update_dashboard",
                      {"honeypot": recent_honeypot(), "canary": recent_canary()})

    def enrich_and_alert(collection, event_id, ip, message):
        """Look up the IP's reputation, store it on the event, then alert.

        Runs in the background so the trap responds instantly.
        """
        def done(result):
            collection.update_one({"_id": event_id}, {"$set": {"enrichment": result}})
            alerter.send(f"{message}\nReputation: {enrichment.describe(result)}")
            push_update()

        if enricher.enabled:
            enricher.submit(ip, done)
        else:
            alerter.send(message)

    # ---------------- Trap: honeypot ----------------
    @app.route("/honeypot", methods=["POST"])
    def honeypot():
        now = _now()
        info = _client_info()
        count, newly_flagged = tracker.record(info["user_ip"], now)
        flagged = count > config.HONEYPOT_MAX_REQUESTS
        event_id = interactions.insert_one(
            {**info, "timestamp": now, "flagged": flagged}).inserted_id
        if newly_flagged:
            enrich_and_alert(
                interactions, event_id, info["user_ip"],
                f":rotating_light: Honeypot: {info['user_ip']} made {count} requests in "
                f"{config.HONEYPOT_TIME_WINDOW}s (UA: {info['user_agent'][:120]})",
            )
        push_update()
        if flagged:
            return "Bot Detected! Multiple rapid interactions.", 429
        return "Honeypot Accessed!"

    # ---------------- Trap: canaries ----------------
    def record_canary_trigger(token, trigger):
        record = registry.find_one({"token": token}) if token else None
        if not record:
            return False
        info = _client_info()
        event = {**info, "token": token, "file": record["file"],
                 "trigger": trigger, "timestamp": _now(),
                 "enrichment": None if enricher.enabled else {"status": "disabled"}}
        event_id = canary_logs.insert_one(event).inserted_id
        enrich_and_alert(
            canary_logs, event_id, info["user_ip"],
            f":bird: Canary triggered ({trigger}) - file `{record['file']}` "
            f"from {info['user_ip']} (UA: {info['user_agent'][:120]})",
        )
        push_update()
        return True

    @app.route("/c/<token>")
    def canary_callback(token):
        if not record_canary_trigger(token, "callback_url"):
            abort(404)
        # Plausible response so the agent carries on normally.
        return jsonify({"status": "ok", "access": "granted"})

    @app.route("/api/v1/keys/verify")
    def canary_key_verify():
        key = request.args.get("key", "")
        if not record_canary_trigger(canaries.token_from_key(key), "api_key"):
            return jsonify({"valid": False}), 401
        return jsonify({"valid": True, "scopes": ["read"]})

    # ---------------- Dashboard ----------------
    @app.route("/")
    @require_auth
    def dashboard():
        return render_template("dashboard.html", honeypot=recent_honeypot(),
                               canary=recent_canary())

    @app.route("/canaries")
    @require_auth
    def canary_files():
        rows = []
        for r in registry.find().sort("created_at", DESCENDING):
            rows.append({
                "file": r["file"],
                "created_at": _ts(r.get("created_at")),
                "triggers": canary_logs.count_documents({"token": r["token"]}),
            })
        return render_template("canaries.html", files=rows)

    @app.route("/canary/<path:filename>")
    @require_auth
    def canary_detail(filename):
        path = safe_join(config.CANARY_FOLDER, filename)
        if not path or not os.path.isfile(path):
            abort(404)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        record = registry.find_one({"file": filename}) or {}
        token = record.get("token", "")
        triggers = [
            {**c, "timestamp": _ts(c.get("timestamp"))}
            for c in canary_logs.find({"token": token}).sort("timestamp", DESCENDING).limit(50)
        ] if token else []
        return render_template("canary_detail.html", filename=filename, content=content,
                               token=token, triggers=triggers)

    @app.route("/honeypot_logs")
    @require_auth
    def honeypot_logs():
        return render_template("honeypot_logs.html", logs=recent_honeypot(50))

    @app.route("/honeypot/<user_ip>")
    @require_auth
    def honeypot_detail(user_ip):
        hits = [
            {**h, "timestamp": _ts(h.get("timestamp"))}
            for h in interactions.find({"user_ip": user_ip}).sort("timestamp", 1)
        ]
        return render_template("honeypot_detail.html", user_ip=user_ip, hits=hits)

    # ---------------- Analytics ----------------
    def _days(default):
        try:
            return max(1, min(int(request.args.get("days", default)), 365))
        except ValueError:
            return default

    @app.route("/analytics")
    @require_auth
    def analytics_page():
        return render_template("analytics.html",
                               enrichment_enabled=enricher.enabled,
                               feed_token_set=bool(config.FEED_TOKEN))

    @app.route("/api/analytics")
    @require_auth
    def analytics_data():
        return jsonify(analytics.compute(db, config, days=_days(30)))

    # ---------------- IOC feeds ----------------
    def require_feed_auth(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if config.FEED_TOKEN:
                supplied = request.args.get("token", "")
                header = request.headers.get("Authorization", "")
                if header.lower().startswith("bearer "):
                    supplied = header[7:].strip()
                if not hmac.compare_digest(supplied, config.FEED_TOKEN):
                    return Response("Invalid feed token", 401)
                return view(*args, **kwargs)
            return require_auth(view)(*args, **kwargs)
        return wrapped

    def current_iocs():
        return iocs.collect(db, config, days=_days(config.FEED_DAYS),
                            include_private=config.FEED_INCLUDE_PRIVATE)

    def json_response(obj, mimetype="application/json"):
        return Response(iocs.dumps(obj), mimetype=mimetype)

    @app.route("/feeds/stix.json")
    @require_feed_auth
    def feed_stix():
        return json_response(iocs.to_stix(current_iocs(), config.ORG_NAME),
                             "application/stix+json;version=2.1")

    @app.route("/feeds/misp/manifest.json")
    @require_feed_auth
    def feed_misp_manifest():
        return json_response(iocs.to_misp_manifest(iocs.to_misp_event(current_iocs(), config)))

    @app.route("/feeds/misp/<event_uuid>.json")
    @require_feed_auth
    def feed_misp_event(event_uuid):
        if event_uuid != iocs.misp_event_uuid(config):
            abort(404)
        return json_response(iocs.to_misp_event(current_iocs(), config))

    @app.route("/feeds/iocs.csv")
    @require_feed_auth
    def feed_csv():
        return Response(iocs.to_csv(current_iocs()), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=iocs.csv"})

    # Periodic refresh as a fallback to the push updates above.
    if start_background:
        def updater():
            while True:
                socketio.sleep(10)
                try:
                    push_update()
                except Exception as exc:
                    log.warning("Dashboard update failed: %s", exc)
        socketio.start_background_task(updater)

    return app, socketio


def main():
    logging.basicConfig(level=logging.INFO)
    if not config.DASHBOARD_PASSWORD and config.HOST not in ("127.0.0.1", "localhost"):
        raise SystemExit("Refusing to expose the dashboard without DASHBOARD_PASSWORD set.")
    app, socketio = create_app()
    created = canaries.ensure_canaries(
        app.extensions["llm_deception"]["registry"], config.CANARY_FOLDER,
        config.CANARY_BASE_URL, config.CANARY_COUNT,
    )
    if created:
        log.info("Generated %d canary file(s) in '%s'", len(created), config.CANARY_FOLDER)
    if not app.extensions["llm_deception"]["alerter"].enabled:
        log.info("Slack alerts disabled (set SLACK_TOKEN and SLACK_CHANNEL to enable)")
    providers = [p.name for p in app.extensions["llm_deception"]["enricher"].providers]
    log.info("IP reputation providers: %s", ", ".join(providers) or "none configured")
    # Werkzeug is fine for a local/lab deployment; use gunicorn for anything bigger.
    socketio.run(app, host=config.HOST, port=config.PORT, debug=config.DEBUG,
                 allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
