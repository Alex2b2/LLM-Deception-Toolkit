"""Slack alerting via the Slack Web API (no extra dependency needed)."""
import json
import logging
import threading
import urllib.request

log = logging.getLogger(__name__)

SLACK_POST_URL = "https://slack.com/api/chat.postMessage"


class SlackAlerter:
    def __init__(self, token=None, channel=None, timeout=5):
        self.token = token
        self.channel = channel
        self.timeout = timeout

    @property
    def enabled(self):
        return bool(self.token and self.channel)

    def send(self, text, background=True):
        """Send an alert. Does nothing if Slack is not configured."""
        if not self.enabled:
            return
        if background:
            threading.Thread(target=self._post, args=(text,), daemon=True).start()
        else:
            self._post(text)

    def _post(self, text):
        body = json.dumps({"channel": self.channel, "text": text}).encode()
        req = urllib.request.Request(
            SLACK_POST_URL,
            data=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Authorization": f"Bearer {self.token}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read() or b"{}")
            if not result.get("ok"):
                log.warning("Slack alert failed: %s", result.get("error"))
        except Exception as exc:  # never let alerting break detection
            log.warning("Slack alert failed: %s", exc)
