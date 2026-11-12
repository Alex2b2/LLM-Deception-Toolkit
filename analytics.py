"""Analytics over canary and honeypot events for the /analytics dashboard."""
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from enrichment import is_public_ip

CANARY_TYPES = {
    ".md": "Onboarding doc (prompt injection)",
    ".py": "Settings file (fake API key)",
    ".txt": "Credentials backup",
}
TRIGGER_LABELS = {"callback_url": "Followed callback URL", "api_key": "Tried fake API key"}

# Ordered: first match wins. Heuristic - user agents can be spoofed.
AGENT_PATTERNS = [
    (r"ChatGPT-User", "OpenAI ChatGPT-User"),
    (r"OAI-SearchBot", "OpenAI OAI-SearchBot"),
    (r"GPTBot", "OpenAI GPTBot"),
    (r"Claude-User", "Anthropic Claude-User"),
    (r"Claude-SearchBot", "Anthropic Claude-SearchBot"),
    (r"ClaudeBot|anthropic-ai", "Anthropic ClaudeBot"),
    (r"Perplexity-User", "Perplexity-User"),
    (r"PerplexityBot", "PerplexityBot"),
    (r"Bytespider", "ByteDance Bytespider"),
    (r"CCBot", "Common Crawl CCBot"),
    (r"meta-externalagent|FacebookBot", "Meta crawler"),
    (r"Amazonbot", "Amazonbot"),
    (r"Google-Extended|Googlebot", "Googlebot"),
    (r"HeadlessChrome|Playwright|Puppeteer", "Headless browser"),
    (r"python-requests", "Python requests"),
    (r"python-httpx|httpx", "Python httpx"),
    (r"aiohttp", "Python aiohttp"),
    (r"Python-urllib", "Python urllib"),
    (r"^curl/", "curl"),
    (r"Wget", "Wget"),
    (r"Go-http-client", "Go net/http"),
    (r"node-fetch|axios|undici|node", "Node.js client"),
    (r"Mozilla/", "Browser"),
]
_COMPILED = [(re.compile(p, re.I), name) for p, name in AGENT_PATTERNS]


def classify_agent(user_agent):
    if not user_agent:
        return "Empty user agent"
    for rx, name in _COMPILED:
        if rx.search(user_agent):
            return name
    return "Other"


def _aware(value):
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def compute(db, cfg, days=30, now=None):
    now = now or datetime.now(timezone.utc)
    start_day = (now - timedelta(days=days - 1)).date()
    since = datetime.combine(start_day, datetime.min.time(), tzinfo=timezone.utc)

    registry = {r["token"]: r for r in db[cfg.COLLECTION_CANARY_REGISTRY].find({})}
    reputation = {r["ip"]: r for r in db[cfg.COLLECTION_IP_REPUTATION].find({})}

    def in_window(ev):
        ts = _aware(ev.get("timestamp"))
        return isinstance(ts, datetime) and ts >= since

    canary = [c for c in db[cfg.COLLECTION_CANARY].find({}) if in_window(c)]
    flagged = [h for h in db[cfg.COLLECTION_INTERACTIONS].find({"flagged": True}) if in_window(h)]

    # Triggers over time
    day_keys = [(start_day + timedelta(days=i)).isoformat() for i in range(days)]
    canary_by_day = Counter(_aware(c["timestamp"]).date().isoformat() for c in canary)
    honeypot_by_day = Counter(_aware(h["timestamp"]).date().isoformat() for h in flagged)
    timeline = {
        "days": day_keys,
        "canary": [canary_by_day.get(d, 0) for d in day_keys],
        "honeypot": [honeypot_by_day.get(d, 0) for d in day_keys],
    }

    # Canary type x trigger type
    by_type = defaultdict(Counter)
    agent_types = defaultdict(lambda: {"hits": 0, "canary_types": Counter(), "ips": set(),
                                       "triggers": Counter()})
    ua_rows = {}
    for c in canary:
        ctype = CANARY_TYPES.get(registry.get(c.get("token"), {}).get("template"), "Unknown")
        trig = c.get("trigger", "unknown")
        by_type[ctype][trig] += 1
        fam = classify_agent(c.get("user_agent"))
        a = agent_types[fam]
        a["hits"] += 1
        a["canary_types"][ctype] += 1
        a["triggers"][trig] += 1
        a["ips"].add(c.get("user_ip"))
        ua = c.get("user_agent") or ""
        row = ua_rows.setdefault(ua, {"user_agent": ua, "family": fam, "hits": 0,
                                      "last_seen": _aware(c["timestamp"])})
        row["hits"] += 1
        row["last_seen"] = max(row["last_seen"], _aware(c["timestamp"]))

    canary_types = [{"type": t, **{k: by_type.get(t, {}).get(k, 0) for k in TRIGGER_LABELS}}
                    for t in list(CANARY_TYPES.values()) + (["Unknown"] if "Unknown" in by_type else [])]

    agents = sorted(
        ({"family": fam, "hits": a["hits"], "unique_ips": len(a["ips"]),
          "canary_types": dict(a["canary_types"]), "triggers": dict(a["triggers"])}
         for fam, a in agent_types.items()),
        key=lambda r: r["hits"], reverse=True)

    top_uas = sorted(ua_rows.values(), key=lambda r: r["hits"], reverse=True)[:15]
    for r in top_uas:
        r["last_seen"] = r["last_seen"].strftime("%Y-%m-%d %H:%M UTC")

    # Known vs new attackers (unique source IPs)
    attackers = {}
    for ev, source in [(c, "canary") for c in canary] + [(h, "honeypot") for h in flagged]:
        ip = ev.get("user_ip")
        if not ip:
            continue
        row = attackers.setdefault(ip, {"ip": ip, "hits": 0, "sources": set(),
                                        "last_seen": _aware(ev["timestamp"])})
        row["hits"] += 1
        row["sources"].add(source)
        row["last_seen"] = max(row["last_seen"], _aware(ev["timestamp"]))

    counts = Counter()
    for ip, row in attackers.items():
        rep = reputation.get(ip)
        if not is_public_ip(ip):
            status = "private"
        elif rep and rep.get("known_malicious") is True:
            status = "known"
        elif rep and rep.get("known_malicious") is False:
            status = "new"
        else:
            status = "unchecked"
        row["status"] = status
        src = (rep or {}).get("sources", {})
        row["abuseipdb_score"] = src.get("abuseipdb", {}).get("score")
        row["otx_pulses"] = src.get("otx", {}).get("pulses")
        row["threatfox_matches"] = src.get("threatfox", {}).get("matches")
        counts[status] += 1

    attacker_rows = sorted(attackers.values(), key=lambda r: r["hits"], reverse=True)[:25]
    for r in attacker_rows:
        r["sources"] = sorted(r["sources"])
        r["last_seen"] = r["last_seen"].strftime("%Y-%m-%d %H:%M UTC")

    return {
        "days": days,
        "totals": {
            "canary_triggers": len(canary),
            "honeypot_flags": len(flagged),
            "unique_ips": len(attackers),
            "known": counts["known"],
            "new": counts["new"],
            "unchecked": counts["unchecked"] + counts["private"],
        },
        "timeline": timeline,
        "canary_types": canary_types,
        "trigger_labels": TRIGGER_LABELS,
        "agents": agents,
        "top_user_agents": top_uas,
        "attackers": attacker_rows,
    }
