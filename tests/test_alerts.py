import io
import json

import alerts


def test_disabled_without_config(monkeypatch):
    called = []
    monkeypatch.setattr(alerts.urllib.request, "urlopen", lambda *a, **k: called.append(1))
    alerts.SlackAlerter(None, None).send("hi", background=False)
    assert called == []


def test_posts_to_slack(monkeypatch):
    sent = {}

    def fake_urlopen(req, timeout):
        sent["url"] = req.full_url
        sent["auth"] = req.headers["Authorization"]
        sent["body"] = json.loads(req.data)
        return io.BytesIO(b'{"ok": true}')

    monkeypatch.setattr(alerts.urllib.request, "urlopen", fake_urlopen)
    alerts.SlackAlerter("xoxb-test", "C123").send("canary!", background=False)
    assert sent["url"] == alerts.SLACK_POST_URL
    assert sent["auth"] == "Bearer xoxb-test"
    assert sent["body"] == {"channel": "C123", "text": "canary!"}


def test_network_errors_do_not_raise(monkeypatch):
    def boom(*a, **k):
        raise OSError("network down")

    monkeypatch.setattr(alerts.urllib.request, "urlopen", boom)
    alerts.SlackAlerter("t", "c").send("x", background=False)
