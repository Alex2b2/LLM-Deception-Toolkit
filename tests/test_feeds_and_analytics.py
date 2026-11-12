import csv
import io
import re

import analytics
import canaries
import iocs
from conftest import public_client

GPT_UA = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"


def _canary(env, ext=".md"):
    registry = env.app.extensions["llm_deception"]["registry"]
    return canaries.generate_canary(registry, env.config.CANARY_FOLDER,
                                    env.config.CANARY_BASE_URL, ext)


def _seed(env):
    md, py = _canary(env, ".md"), _canary(env, ".py")
    env.client.get(f"/c/{md['token']}", **public_client(env, "185.220.101.1", GPT_UA))
    env.client.get(f"/c/{md['token']}", **public_client(env, "8.8.8.8", "python-requests/2.32"))
    env.client.get("/api/v1/keys/verify", query_string={"key": f"sk-live-{py['token']}"},
                   **public_client(env, "8.8.8.8", "python-requests/2.32"))
    env.client.get(f"/c/{md['token']}", **public_client(env, "127.0.0.1", "curl/8.0"))
    for _ in range(5):  # max 3 -> flagged on 4th and 5th
        env.client.post("/honeypot", **public_client(env, "1.1.1.1", "Go-http-client/1.1"))
    return md, py


# ---------------------------------------------------------------- enrichment in the app
def test_canary_events_are_enriched_and_alert_includes_reputation(env):
    _seed(env)
    logs = env.db[env.config.COLLECTION_CANARY].docs
    by_ip = {d["user_ip"]: d for d in logs}
    assert by_ip["185.220.101.1"]["enrichment"]["known_malicious"] is True
    assert by_ip["8.8.8.8"]["enrichment"]["known_malicious"] is False
    assert by_ip["127.0.0.1"]["enrichment"]["status"] == "private"
    assert "127.0.0.1" not in env.provider.calls
    assert any("KNOWN MALICIOUS" in m and "185.220.101.1" in m for m in env.alerter.messages)


def test_honeypot_enriches_only_when_flagged(env):
    _seed(env)
    hits = env.db[env.config.COLLECTION_INTERACTIONS].docs
    enriched = [h for h in hits if "enrichment" in h]
    assert len(enriched) == 1 and enriched[0]["flagged"] is True
    assert env.provider.calls.count("1.1.1.1") == 1


# ---------------------------------------------------------------- IOC export
def test_collect_excludes_private_ips_by_default(env):
    _seed(env)
    data = iocs.collect(env.db, env.config)
    ips = {r["value"]: r for r in data["ips"]}
    assert set(ips) == {"185.220.101.1", "8.8.8.8", "1.1.1.1"}
    assert ips["185.220.101.1"]["known_malicious"] is True
    assert ips["8.8.8.8"]["hits"] == 2
    assert ips["8.8.8.8"]["sources"] == ["canary:api_key", "canary:callback_url"]
    assert ips["1.1.1.1"]["sources"] == ["honeypot"]
    assert {r["value"] for r in data["user_agents"]} == {GPT_UA, "python-requests/2.32",
                                                        "Go-http-client/1.1"}
    assert len(data["canary_urls"]) == 2


def test_stix_bundle_is_valid_shape_and_ids_are_stable(env):
    _seed(env)
    data = iocs.collect(env.db, env.config)
    b1, b2 = iocs.to_stix(data, "Test Org"), iocs.to_stix(data, "Test Org")
    assert b1["type"] == "bundle"
    ind = [o for o in b1["objects"] if o["type"] == "indicator"]
    assert {o["id"] for o in ind} == {o["id"] for o in b2["objects"] if o["type"] == "indicator"}
    id_re = re.compile(r"^(indicator|identity)--[0-9a-f-]{36}$")
    ts_re = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
    for o in b1["objects"]:
        assert id_re.match(o["id"]) and o["spec_version"] == "2.1"
        assert ts_re.match(o["created"]) and ts_re.match(o["modified"])
    patterns = {o["pattern"] for o in ind}
    assert "[ipv4-addr:value = '185.220.101.1']" in patterns
    known = next(o for o in ind if "185.220.101.1" in o["pattern"])
    assert known["indicator_types"] == ["malicious-activity"] and known["confidence"] == 90


def test_stix_escapes_quotes_in_user_agents(env):
    md = _canary(env)
    env.client.get(f"/c/{md['token']}", **public_client(env, "8.8.8.8", "evil'agent\\x"))
    bundle = iocs.to_stix(iocs.collect(env.db, env.config), "Org")
    ua = next(o for o in bundle["objects"] if "User-Agent" in o.get("pattern", ""))
    assert ua["pattern"].endswith("= 'evil\\'agent\\\\x']")


def test_misp_manifest_and_event(env):
    _seed(env)
    event = iocs.to_misp_event(iocs.collect(env.db, env.config), env.config)
    e = event["Event"]
    manifest = iocs.to_misp_manifest(event)
    assert list(manifest) == [e["uuid"]]
    types = {(a["type"], a["value"]) for a in e["Attribute"]}
    assert ("ip-src", "185.220.101.1") in types and ("user-agent", "python-requests/2.32") in types
    known = next(a for a in e["Attribute"] if a["value"] == "185.220.101.1")
    assert {"name": "known-malicious"} in known["Tag"] and known["to_ids"] is True


def test_csv_export(env):
    _seed(env)
    rows = list(csv.DictReader(io.StringIO(iocs.to_csv(iocs.collect(env.db, env.config)))))
    ip_rows = {r["value"]: r for r in rows if r["type"] == "ip"}
    assert ip_rows["185.220.101.1"]["known_malicious"] == "true"
    assert ip_rows["8.8.8.8"]["known_malicious"] == "false"


def test_feed_endpoints_require_token_when_set(env, monkeypatch):
    _seed(env)
    monkeypatch.setattr(env.config, "FEED_TOKEN", "feedsecret")
    assert env.client.get("/feeds/stix.json").status_code == 401
    ok = env.client.get("/feeds/stix.json", headers={"Authorization": "Bearer feedsecret"})
    assert ok.status_code == 200 and ok.json["type"] == "bundle"
    assert env.client.get("/feeds/iocs.csv?token=feedsecret").status_code == 200
    manifest = env.client.get("/feeds/misp/manifest.json?token=feedsecret").json
    uuid = next(iter(manifest))
    assert env.client.get(f"/feeds/misp/{uuid}.json?token=feedsecret").status_code == 200
    assert env.client.get("/feeds/misp/00000000-0000-0000-0000-000000000000.json"
                          "?token=feedsecret").status_code == 404


def test_feeds_fall_back_to_dashboard_auth(env, monkeypatch):
    monkeypatch.setattr(env.config, "FEED_TOKEN", None)
    monkeypatch.setattr(env.config, "DASHBOARD_PASSWORD", "pw")
    assert env.client.get("/feeds/stix.json").status_code == 401
    assert env.client.get("/feeds/stix.json", auth=("admin", "pw")).status_code == 200


# ---------------------------------------------------------------- analytics
def test_classify_agent():
    assert analytics.classify_agent(GPT_UA) == "OpenAI ChatGPT-User"
    assert analytics.classify_agent("Mozilla/5.0 (compatible; ClaudeBot/1.0)") == "Anthropic ClaudeBot"
    assert analytics.classify_agent("python-requests/2.32") == "Python requests"
    assert analytics.classify_agent("curl/8.4.0") == "curl"
    assert analytics.classify_agent("Mozilla/5.0 (Macintosh) Safari/605") == "Browser"
    assert analytics.classify_agent("") == "Empty user agent"
    assert analytics.classify_agent("weird-thing") == "Other"


def test_analytics_compute(env):
    _seed(env)
    data = analytics.compute(env.db, env.config, days=7)
    t = data["totals"]
    assert t["canary_triggers"] == 4 and t["honeypot_flags"] == 2
    assert t["unique_ips"] == 4
    assert (t["known"], t["new"], t["unchecked"]) == (1, 2, 1)
    assert sum(data["timeline"]["canary"]) == 4 and len(data["timeline"]["days"]) == 7
    types = {r["type"]: r for r in data["canary_types"]}
    assert types[analytics.CANARY_TYPES[".md"]]["callback_url"] == 3
    assert types[analytics.CANARY_TYPES[".py"]]["api_key"] == 1
    fams = {a["family"]: a for a in data["agents"]}
    assert fams["Python requests"]["hits"] == 2 and fams["Python requests"]["unique_ips"] == 1
    assert "OpenAI ChatGPT-User" in fams


def test_analytics_page_and_api(env):
    _seed(env)
    assert env.client.get("/analytics").status_code == 200
    resp = env.client.get("/api/analytics?days=30")
    assert resp.status_code == 200 and resp.json["days"] == 30
    assert env.client.get("/api/analytics?days=abc").json["days"] == 30


def test_dashboard_shows_reputation(env):
    _seed(env)
    html = env.client.get("/").get_data(as_text=True)
    assert "known malicious" in html and "not reported" in html
