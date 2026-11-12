"""IP reputation enrichment.

When a canary fires or the honeypot flags a client, the source IP is checked
against public threat-intelligence services to record whether it was already
known as malicious:

* AbuseIPDB  - abuse confidence score and report count
* ThreatFox  - abuse.ch IOC database (malware C2 and similar)
* AlienVault OTX - number of community "pulses" that mention the IP

Each provider is optional and only used if its API key is configured. Results
are cached per IP so repeated hits don't burn API quota. Private, loopback and
reserved addresses are never sent to third parties.
"""
import ipaddress
import json
import logging
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)

STATUS_CHECKED = "checked"
STATUS_PRIVATE = "private"
STATUS_DISABLED = "disabled"
STATUS_ERROR = "error"


def http_json(method, url, headers=None, body=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/json",
        "User-Agent": "LLM-Deception-Toolkit",
        **({"Content-Type": "application/json"} if data else {}),
        **(headers or {}),
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return False
    return addr.is_global


# ---------------------------------------------------------------- providers
class AbuseIPDB:
    name = "abuseipdb"
    URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key, min_score=50, max_age_days=90, http=http_json):
        self.api_key, self.min_score, self.max_age_days, self.http = (
            api_key, min_score, max_age_days, http)

    def lookup(self, ip):
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": self.max_age_days})
        data = self.http("GET", f"{self.URL}?{query}", {"Key": self.api_key}).get("data", {})
        score = data.get("abuseConfidenceScore") or 0
        return {
            "malicious": score >= self.min_score,
            "score": score,
            "reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor"),
        }


class ThreatFox:
    name = "threatfox"
    URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, auth_key, http=http_json):
        self.auth_key, self.http = auth_key, http

    def lookup(self, ip):
        # ThreatFox stores most IP IOCs as "ip:port", so search by wildcard and
        # keep only entries for this exact IP.
        resp = self.http("POST", self.URL, {"Auth-Key": self.auth_key},
                         {"query": "search_ioc", "search_term": ip, "exact_match": False})
        rows = resp.get("data") if resp.get("query_status") == "ok" else []
        rows = [r for r in (rows or []) if isinstance(r, dict) and _ioc_host(r.get("ioc")) == ip]
        return {
            "malicious": bool(rows),
            "matches": len(rows),
            "malware": sorted({r.get("malware_printable") for r in rows if r.get("malware_printable")}),
            "threat_types": sorted({r.get("threat_type") for r in rows if r.get("threat_type")}),
        }


class OTX:
    name = "otx"
    URL = "https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}/general"

    def __init__(self, api_key, min_pulses=1, http=http_json):
        self.api_key, self.min_pulses, self.http = api_key, min_pulses, http

    def lookup(self, ip):
        kind = "IPv6" if ":" in ip else "IPv4"
        url = self.URL.format(kind=kind, ip=urllib.parse.quote(ip, safe=""))
        info = self.http("GET", url, {"X-OTX-API-KEY": self.api_key}).get("pulse_info", {})
        count = info.get("count", 0) or 0
        return {
            "malicious": count >= self.min_pulses,
            "pulses": count,
            "pulse_names": [p.get("name") for p in (info.get("pulses") or [])[:5]],
        }


def providers_from_config(cfg):
    providers = []
    if cfg.ABUSEIPDB_API_KEY:
        providers.append(AbuseIPDB(cfg.ABUSEIPDB_API_KEY, cfg.ABUSEIPDB_MIN_SCORE,
                                   cfg.ABUSEIPDB_MAX_AGE_DAYS))
    if cfg.ABUSECH_AUTH_KEY:
        providers.append(ThreatFox(cfg.ABUSECH_AUTH_KEY))
    if cfg.OTX_API_KEY:
        providers.append(OTX(cfg.OTX_API_KEY, cfg.OTX_MIN_PULSES))
    return providers


# ---------------------------------------------------------------- enricher
class Enricher:
    """Looks up IPs across providers, with a per-IP cache in MongoDB."""

    def __init__(self, providers, cache, ttl_hours=24, max_workers=4, synchronous=False):
        self.providers = list(providers)
        self.cache = cache
        self.ttl = timedelta(hours=ttl_hours)
        self.synchronous = synchronous
        self._pool = None if synchronous else ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="enrich")

    @property
    def enabled(self):
        return bool(self.providers)

    def enrich(self, ip):
        now = datetime.now(timezone.utc)
        if not is_public_ip(ip):
            return {"status": STATUS_PRIVATE, "known_malicious": None, "checked_at": now}
        if not self.providers:
            return {"status": STATUS_DISABLED, "known_malicious": None, "checked_at": now}

        cached = self.cache.find_one({"ip": ip})
        if cached and _aware(cached.get("checked_at")) and now - _aware(cached["checked_at"]) < self.ttl:
            return {k: cached[k] for k in ("status", "known_malicious", "sources", "checked_at")
                    if k in cached}

        sources, verdicts = {}, []
        for provider in self.providers:
            try:
                result = provider.lookup(ip)
                sources[provider.name] = result
                verdicts.append(result["malicious"])
            except Exception as exc:
                log.warning("%s lookup failed for %s: %s", provider.name, ip, exc)
                sources[provider.name] = {"error": str(exc)[:200]}

        result = {
            "status": STATUS_CHECKED if verdicts else STATUS_ERROR,
            "known_malicious": any(verdicts) if verdicts else None,
            "sources": sources,
            "checked_at": now,
        }
        if verdicts:  # don't cache total failures, retry next time
            self.cache.replace_one({"ip": ip}, {"ip": ip, **result}, upsert=True)
        return result

    def submit(self, ip, callback):
        """Enrich in the background and call ``callback(result)`` when done."""
        def run():
            try:
                callback(self.enrich(ip))
            except Exception as exc:
                log.warning("Enrichment failed for %s: %s", ip, exc)

        if self.synchronous:
            run()
        else:
            self._pool.submit(run)


def describe(result):
    """One-line human summary of an enrichment result (used in Slack alerts)."""
    status = result.get("status")
    if status == STATUS_PRIVATE:
        return "private/internal address (not checked)"
    if status == STATUS_DISABLED:
        return "reputation lookups disabled"
    if status == STATUS_ERROR:
        return "reputation lookup failed"
    parts = []
    src = result.get("sources", {})
    if "abuseipdb" in src and "score" in src["abuseipdb"]:
        parts.append(f"AbuseIPDB {src['abuseipdb']['score']}%")
    if "threatfox" in src and "matches" in src["threatfox"]:
        parts.append(f"ThreatFox {src['threatfox']['matches']} IOC(s)")
    if "otx" in src and "pulses" in src["otx"]:
        parts.append(f"OTX {src['otx']['pulses']} pulse(s)")
    verdict = "KNOWN MALICIOUS" if result.get("known_malicious") else "not previously reported"
    return f"{verdict} ({', '.join(parts)})" if parts else verdict


def _ioc_host(ioc):
    """'1.2.3.4:443' -> '1.2.3.4', '[2001:db8::1]:443' -> '2001:db8::1'."""
    s = str(ioc or "")
    if s.startswith("[") and "]" in s:
        return s[1:s.index("]")]
    if s.count(":") == 1:
        return s.split(":", 1)[0]
    return s


def _aware(value):
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value
