"""IOC collection and export (STIX 2.1, MISP feed, CSV).

IOCs come from the toolkit's own detections:

* source IPs of canary triggers and of flagged honeypot clients
* user agents seen on those events
* canary callback URLs that were actually triggered

IDs are deterministic (UUIDv5 of the value), so re-exporting updates the same
objects in a consuming platform instead of creating duplicates.
"""
import csv
import io
import json
import uuid
from datetime import datetime, timedelta, timezone

from enrichment import is_public_ip

NAMESPACE = uuid.UUID("5d0c2f0e-6a8b-4b8e-9d3a-0e1f5b6c7d8e")
STIX_SPEC = "2.1"


def _uuid(*parts):
    return str(uuid.uuid5(NAMESPACE, "|".join(str(p) for p in parts)))


def _aware(value):
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _stix_time(dt):
    return _aware(dt).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------- collection
def collect(db, cfg, days=30, include_private=False, now=None):
    """Aggregate IOCs from the last ``days`` days. Returns a dict of lists."""
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    registry = {r["token"]: r for r in db[cfg.COLLECTION_CANARY_REGISTRY].find({})}
    reputation = {r["ip"]: r for r in db[cfg.COLLECTION_IP_REPUTATION].find({})}

    events = []
    for c in db[cfg.COLLECTION_CANARY].find({}):
        events.append((c, f"canary:{c.get('trigger', 'unknown')}"))
    for h in db[cfg.COLLECTION_INTERACTIONS].find({"flagged": True}):
        events.append((h, "honeypot"))

    ips, agents, urls = {}, {}, {}

    def bump(table, key, ev, source, extra=None):
        ts = _aware(ev.get("timestamp"))
        row = table.setdefault(key, {"value": key, "first_seen": ts, "last_seen": ts,
                                     "hits": 0, "sources": set(), "files": set()})
        row["hits"] += 1
        row["first_seen"] = min(row["first_seen"], ts)
        row["last_seen"] = max(row["last_seen"], ts)
        row["sources"].add(source)
        if ev.get("file"):
            row["files"].add(ev["file"])
        if extra:
            row.update(extra)

    for ev, source in events:
        ts = _aware(ev.get("timestamp"))
        if not isinstance(ts, datetime) or ts < since:
            continue
        ip = ev.get("user_ip")
        if ip and (include_private or is_public_ip(ip)):
            rep = reputation.get(ip, {})
            bump(ips, ip, ev, source, {"known_malicious": rep.get("known_malicious")})
        ua = ev.get("user_agent")
        if ua and (include_private or not ip or is_public_ip(ip)):
            bump(agents, ua, ev, source)
        token = ev.get("token")
        if token and token in registry:
            base = registry[token].get("base_url", cfg.CANARY_BASE_URL)
            bump(urls, f"{base}/c/{token}", ev, source, {"token": token})

    def done(table):
        rows = sorted(table.values(), key=lambda r: r["last_seen"], reverse=True)
        for r in rows:
            r["sources"] = sorted(r["sources"])
            r["files"] = sorted(r["files"])
        return rows

    return {"ips": done(ips), "user_agents": done(agents), "canary_urls": done(urls),
            "generated_at": now, "days": days}


def _confidence(row):
    if row.get("known_malicious"):
        return 90
    return 80 if any(s.startswith("canary:") for s in row["sources"]) else 50


def _describe(row, kind):
    return (f"{kind} observed by LLM Deception Toolkit: {row['hits']} hit(s) "
            f"via {', '.join(row['sources'])}"
            + (f"; canary files: {', '.join(row['files'])}" if row["files"] else ""))


# ---------------------------------------------------------------- STIX 2.1
def _stix_str(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


def to_stix(iocs, org_name):
    identity_id = f"identity--{_uuid('identity', org_name)}"
    created = _stix_time(iocs["generated_at"])
    objects = [{
        "type": "identity", "spec_version": STIX_SPEC, "id": identity_id,
        "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
        "name": org_name, "identity_class": "system",
    }]

    def indicator(kind, row, pattern, name):
        known = row.get("known_malicious")
        objects.append({
            "type": "indicator", "spec_version": STIX_SPEC,
            "id": f"indicator--{_uuid(kind, row['value'])}",
            "created_by_ref": identity_id,
            "created": _stix_time(row["first_seen"]),
            "modified": _stix_time(row["last_seen"]),
            "name": name,
            "description": _describe(row, kind),
            "indicator_types": ["malicious-activity"] if known else ["anomalous-activity"],
            "pattern": pattern, "pattern_type": "stix",
            "valid_from": _stix_time(row["first_seen"]),
            "confidence": _confidence(row),
            "labels": ["llm-deception", *row["sources"]],
            "x_llm_deception_hits": row["hits"],
            "x_llm_deception_known_malicious": known,
        })

    for row in iocs["ips"]:
        kind = "ipv6-addr" if ":" in row["value"] else "ipv4-addr"
        indicator("ip", row, f"[{kind}:value = '{_stix_str(row['value'])}']",
                  f"Deception hit from {row['value']}")
    for row in iocs["user_agents"]:
        indicator("user-agent", row,
                  "[network-traffic:extensions.'http-request-ext'.request_header."
                  f"'User-Agent' = '{_stix_str(row['value'])}']",
                  f"User agent seen on deception hit: {row['value'][:80]}")
    for row in iocs["canary_urls"]:
        indicator("url", row, f"[url:value = '{_stix_str(row['value'])}']",
                  "Triggered LLM canary URL")

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects,
            "x_generated": created}


# ---------------------------------------------------------------- MISP feed
def misp_event_uuid(cfg):
    return _uuid("misp-event", cfg.CANARY_BASE_URL)


def to_misp_event(iocs, cfg):
    org = {"name": cfg.ORG_NAME, "uuid": _uuid("org", cfg.ORG_NAME)}
    attributes = []

    def add(row, mtype, to_ids):
        attributes.append({
            "uuid": _uuid("misp-attr", mtype, row["value"]),
            "type": mtype, "category": "Network activity",
            "value": row["value"], "to_ids": to_ids,
            "comment": _describe(row, mtype)[:255],
            "timestamp": str(int(_aware(row["last_seen"]).timestamp())),
            "first_seen": _stix_time(row["first_seen"]),
            "last_seen": _stix_time(row["last_seen"]),
            "Tag": [{"name": "llm-deception"}]
                   + ([{"name": "known-malicious"}] if row.get("known_malicious") else []),
        })

    for row in iocs["ips"]:
        add(row, "ip-src", True)
    for row in iocs["user_agents"]:
        add(row, "user-agent", False)  # UAs are shared widely; context only
    for row in iocs["canary_urls"]:
        add(row, "url", True)

    latest = max([int(a["timestamp"]) for a in attributes],
                 default=int(iocs["generated_at"].timestamp()))
    return {"Event": {
        "uuid": misp_event_uuid(cfg),
        "info": f"{cfg.ORG_NAME}: LLM agent and bot deception hits",
        "date": iocs["generated_at"].strftime("%Y-%m-%d"),
        "timestamp": str(latest),
        "published": True,
        "analysis": "2",
        "threat_level_id": "3",
        "distribution": "0",
        "Orgc": org,
        "Tag": [{"name": "tlp:green"}, {"name": "llm-deception"}],
        "Attribute": attributes,
    }}


def to_misp_manifest(event):
    e = event["Event"]
    return {e["uuid"]: {
        "info": e["info"], "date": e["date"], "timestamp": e["timestamp"],
        "analysis": e["analysis"], "threat_level_id": e["threat_level_id"],
        "Orgc": e["Orgc"], "Tag": e["Tag"],
    }}


# ---------------------------------------------------------------- CSV
def to_csv(iocs):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["type", "value", "first_seen", "last_seen", "hits", "sources",
                "known_malicious", "files"])
    for kind, key in (("ip", "ips"), ("user-agent", "user_agents"), ("url", "canary_urls")):
        for r in iocs[key]:
            km = r.get("known_malicious")
            w.writerow([kind, r["value"], _stix_time(r["first_seen"]), _stix_time(r["last_seen"]),
                        r["hits"], ";".join(r["sources"]),
                        "" if km is None else str(km).lower(), ";".join(r["files"])])
    return out.getvalue()


def dumps(obj):
    return json.dumps(obj, indent=2, default=str)
