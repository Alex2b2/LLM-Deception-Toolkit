from datetime import datetime, timedelta, timezone

import pytest

import enrichment
from conftest import FakeCollection, FakeProvider


def fake_http(responses, calls):
    def http(method, url, headers=None, body=None, timeout=10):
        calls.append({"method": method, "url": url, "headers": headers, "body": body})
        return responses
    return http


def test_abuseipdb_parses_score():
    calls = []
    p = enrichment.AbuseIPDB("k", min_score=50, http=fake_http(
        {"data": {"abuseConfidenceScore": 87, "totalReports": 12, "countryCode": "NL",
                  "isp": "Example", "usageType": "Data Center", "isTor": False}}, calls))
    r = p.lookup("8.8.4.4")
    assert r["malicious"] is True and r["score"] == 87 and r["reports"] == 12
    assert calls[0]["headers"] == {"Key": "k"}
    assert "ipAddress=8.8.4.4" in calls[0]["url"] and "maxAgeInDays=90" in calls[0]["url"]


def test_abuseipdb_below_threshold_is_not_malicious():
    p = enrichment.AbuseIPDB("k", min_score=50, http=fake_http(
        {"data": {"abuseConfidenceScore": 10}}, []))
    assert p.lookup("8.8.4.4")["malicious"] is False


def test_threatfox_matches_ip_port_iocs_only_for_exact_ip():
    calls = []
    p = enrichment.ThreatFox("auth", http=fake_http({"query_status": "ok", "data": [
        {"ioc": "1.2.3.4:443", "malware_printable": "Cobalt Strike", "threat_type": "botnet_cc"},
        {"ioc": "1.2.3.45:80", "malware_printable": "Other"},
    ]}, calls))
    r = p.lookup("1.2.3.4")
    assert r == {"malicious": True, "matches": 1, "malware": ["Cobalt Strike"],
                 "threat_types": ["botnet_cc"]}
    assert calls[0]["headers"] == {"Auth-Key": "auth"}
    assert calls[0]["body"]["query"] == "search_ioc"


def test_threatfox_no_result():
    p = enrichment.ThreatFox("a", http=fake_http({"query_status": "no_result", "data": "x"}, []))
    assert p.lookup("1.2.3.4")["malicious"] is False


def test_otx_counts_pulses_and_uses_ipv6_path():
    calls = []
    p = enrichment.OTX("key", min_pulses=2, http=fake_http(
        {"pulse_info": {"count": 3, "pulses": [{"name": "Scanner list"}]}}, calls))
    r = p.lookup("2001:4860::8888")
    assert r["malicious"] is True and r["pulses"] == 3 and r["pulse_names"] == ["Scanner list"]
    assert "/indicators/IPv6/" in calls[0]["url"]
    assert calls[0]["headers"] == {"X-OTX-API-KEY": "key"}


def test_private_ips_are_never_sent_to_providers():
    provider = FakeProvider()
    e = enrichment.Enricher([provider], FakeCollection(), synchronous=True)
    for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.1", "203.0.113.9", "not-an-ip"]:
        assert e.enrich(ip)["status"] == enrichment.STATUS_PRIVATE
    assert provider.calls == []


def test_disabled_without_providers():
    e = enrichment.Enricher([], FakeCollection(), synchronous=True)
    assert not e.enabled
    assert e.enrich("8.8.8.8")["status"] == enrichment.STATUS_DISABLED


def test_results_are_cached_until_ttl():
    provider, cache = FakeProvider(), FakeCollection()
    e = enrichment.Enricher([provider], cache, ttl_hours=24, synchronous=True)
    assert e.enrich("185.220.101.1")["known_malicious"] is True
    assert e.enrich("185.220.101.1")["known_malicious"] is True
    assert provider.calls == ["185.220.101.1"]
    cache.docs[0]["checked_at"] = datetime.now(timezone.utc) - timedelta(hours=25)
    e.enrich("185.220.101.1")
    assert len(provider.calls) == 2


def test_provider_errors_are_recorded_not_raised():
    class Broken:
        name = "broken"

        def lookup(self, ip):
            raise OSError("timeout")

    cache = FakeCollection()
    e = enrichment.Enricher([Broken(), FakeProvider()], cache, synchronous=True)
    r = e.enrich("8.8.8.8")
    assert r["status"] == "checked" and r["known_malicious"] is False
    assert "error" in r["sources"]["broken"]

    only_broken = enrichment.Enricher([Broken()], FakeCollection(), synchronous=True)
    r = only_broken.enrich("8.8.8.8")
    assert r["status"] == "error" and r["known_malicious"] is None
    assert only_broken.cache.docs == []  # failures are not cached


@pytest.mark.parametrize("result,expected", [
    ({"status": "private"}, "private/internal"),
    ({"status": "checked", "known_malicious": True,
      "sources": {"abuseipdb": {"score": 90}, "otx": {"pulses": 4}}}, "KNOWN MALICIOUS (AbuseIPDB 90%, OTX 4 pulse(s))"),
    ({"status": "checked", "known_malicious": False, "sources": {}}, "not previously reported"),
])
def test_describe(result, expected):
    assert expected in enrichment.describe(result)


def test_providers_from_config():
    class Cfg:
        ABUSEIPDB_API_KEY = "a"
        ABUSEIPDB_MIN_SCORE = 50
        ABUSEIPDB_MAX_AGE_DAYS = 90
        ABUSECH_AUTH_KEY = None
        OTX_API_KEY = "o"
        OTX_MIN_PULSES = 1

    assert [p.name for p in enrichment.providers_from_config(Cfg)] == ["abuseipdb", "otx"]
