import canaries


def _make_canary(env, ext=".md"):
    registry = env.app.extensions["llm_deception"]["registry"]
    return canaries.generate_canary(registry, env.config.CANARY_FOLDER,
                                    env.config.CANARY_BASE_URL, ext)


def test_callback_url_triggers_canary(env):
    rec = _make_canary(env)
    resp = env.client.get(f"/c/{rec['token']}", headers={"User-Agent": "TestAgent/1.0"})
    assert resp.status_code == 200
    logs = env.db[env.config.COLLECTION_CANARY].docs
    assert len(logs) == 1
    assert logs[0]["file"] == rec["file"]
    assert logs[0]["trigger"] == "callback_url"
    assert logs[0]["user_agent"] == "TestAgent/1.0"
    assert any(rec["file"] in m for m in env.alerter.messages)


def test_fake_key_triggers_canary(env):
    rec = _make_canary(env, ".py")
    resp = env.client.get("/api/v1/keys/verify",
                          query_string={"key": f"sk-live-{rec['token']}"})
    assert resp.status_code == 200 and resp.json["valid"] is True
    assert env.db[env.config.COLLECTION_CANARY].docs[0]["trigger"] == "api_key"


def test_unknown_tokens_are_not_logged(env):
    assert env.client.get("/c/notarealtoken").status_code == 404
    assert env.client.get("/api/v1/keys/verify?key=sk-live-nope").status_code == 401
    assert env.db[env.config.COLLECTION_CANARY].docs == []
    assert env.alerter.messages == []


def test_honeypot_flags_and_alerts_once(env):
    codes = [env.client.post("/honeypot").status_code for _ in range(6)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3:] == [429, 429, 429]
    hits = env.db[env.config.COLLECTION_INTERACTIONS].docs
    assert len(hits) == 6 and hits[-1]["flagged"] is True
    assert len(env.alerter.messages) == 1  # alert on first flag only


def test_dashboard_pages_render(env):
    rec = _make_canary(env)
    env.client.get(f"/c/{rec['token']}")
    env.client.post("/honeypot")
    for path in ["/", "/canaries", f"/canary/{rec['file']}", "/honeypot_logs",
                 "/honeypot/127.0.0.1"]:
        resp = env.client.get(path)
        assert resp.status_code == 200, path
    detail = env.client.get(f"/canary/{rec['file']}").get_data(as_text=True)
    assert "semantic-trap" in detail and "callback_url" in detail


def test_canary_detail_blocks_path_traversal(env):
    assert env.client.get("/canary/../config.py").status_code == 404
    assert env.client.get("/canary/..%2Fconfig.py").status_code == 404


def test_dashboard_requires_auth_when_password_set(env, monkeypatch):
    monkeypatch.setattr(env.config, "DASHBOARD_PASSWORD", "s3cret")
    assert env.client.get("/").status_code == 401
    ok = env.client.get("/", auth=("admin", "s3cret"))
    assert ok.status_code == 200
    # Trap endpoints stay public.
    assert env.client.post("/honeypot").status_code == 200
