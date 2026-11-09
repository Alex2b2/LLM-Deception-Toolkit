import os

import canaries
from conftest import FakeCollection


def test_each_template_embeds_token_in_traps(tmp_path):
    registry = FakeCollection()
    for ext in canaries.TEMPLATES:
        rec = canaries.generate_canary(registry, str(tmp_path), "http://trap.test", ext)
        content = (tmp_path / rec["file"]).read_text()
        assert f"http://trap.test/c/{rec['token']}" in content or \
            f"{canaries.KEY_PREFIX}{rec['token']}" in content
        assert rec["file"].endswith(ext)
    assert len(registry.docs) == len(canaries.TEMPLATES)


def test_tokens_are_unique(tmp_path):
    registry = FakeCollection()
    tokens = {canaries.generate_canary(registry, str(tmp_path), "http://x")["token"]
              for _ in range(50)}
    assert len(tokens) == 50


def test_ensure_canaries_tops_up_without_regenerating(tmp_path):
    registry = FakeCollection()
    first = canaries.ensure_canaries(registry, str(tmp_path), "http://x", 3)
    assert len(first) == 3
    again = canaries.ensure_canaries(registry, str(tmp_path), "http://x", 3)
    assert again == []
    os.remove(tmp_path / first[0]["file"])
    refill = canaries.ensure_canaries(registry, str(tmp_path), "http://x", 3)
    assert len(refill) == 1


def test_token_from_key():
    assert canaries.token_from_key("sk-live-abc123") == "abc123"
    assert canaries.token_from_key("sk-test-abc123") is None
    assert canaries.token_from_key("") is None
