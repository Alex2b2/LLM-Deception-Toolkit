import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Allow running the tests without Flask-SocketIO installed (CI installs the real one).
try:
    import flask_socketio  # noqa: F401
except ImportError:  # pragma: no cover
    stub = types.ModuleType("flask_socketio")

    class SocketIO:
        def __init__(self, app=None, **kwargs):
            self.emitted = []

        def on(self, event):
            return lambda f: f

        def emit(self, event, data=None, **kwargs):
            self.emitted.append((event, data))

        def start_background_task(self, target, *args, **kwargs):
            pass

        def sleep(self, seconds):
            pass

    stub.SocketIO = SocketIO
    sys.modules["flask_socketio"] = stub


# ---------------- Minimal in-memory MongoDB stand-in ----------------
class FakeCursor:
    def __init__(self, docs):
        self._docs = list(docs)

    def sort(self, key, direction=1):
        self._docs.sort(key=lambda d: d.get(key), reverse=direction < 0)
        return self

    def limit(self, n):
        self._docs = self._docs[:n]
        return self

    def __iter__(self):
        return iter([dict(d) for d in self._docs])


class FakeCollection:
    def __init__(self):
        self.docs = []

    @staticmethod
    def _match(doc, flt):
        return all(doc.get(k) == v for k, v in (flt or {}).items())

    def insert_one(self, doc):
        doc = dict(doc)
        doc.setdefault("_id", len(self.docs) + 1)
        self.docs.append(doc)

    def find(self, flt=None):
        return FakeCursor(d for d in self.docs if self._match(d, flt))

    def find_one(self, flt=None):
        return next((dict(d) for d in self.docs if self._match(d, flt)), None)

    def count_documents(self, flt):
        return sum(1 for d in self.docs if self._match(d, flt))


class FakeDB(dict):
    def __missing__(self, name):
        self[name] = FakeCollection()
        return self[name]


class RecordingAlerter:
    enabled = True

    def __init__(self):
        self.messages = []

    def send(self, text, background=True):
        self.messages.append(text)


@pytest.fixture
def env(tmp_path, monkeypatch):
    import config

    monkeypatch.setattr(config, "CANARY_FOLDER", str(tmp_path / "canaries"))
    monkeypatch.setattr(config, "CANARY_BASE_URL", "http://trap.test")
    monkeypatch.setattr(config, "DASHBOARD_PASSWORD", None)
    monkeypatch.setattr(config, "HONEYPOT_MAX_REQUESTS", 3)

    import app as app_module

    db = FakeDB()
    alerter = RecordingAlerter()
    flask_app, socketio = app_module.create_app(db=db, alerter=alerter, start_background=False)
    flask_app.testing = True
    return types.SimpleNamespace(
        app=flask_app, client=flask_app.test_client(), db=db, alerter=alerter, config=config,
    )
