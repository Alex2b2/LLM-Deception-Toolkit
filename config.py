"""Configuration. Every setting can be overridden with an environment variable.

Secrets (Slack token, dashboard password, secret key) must only ever come from
the environment or a local .env file, never from this file.
"""
import os

try:  # Load a local .env file if python-dotenv is installed.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def _int(name, default):
    return int(os.environ.get(name, default))


def _bool(name, default=False):
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


# MongoDB
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.environ.get("DB_NAME", "llm_deception")
COLLECTION_INTERACTIONS = os.environ.get("COLLECTION_INTERACTIONS", "interactions")
COLLECTION_CANARY = os.environ.get("COLLECTION_CANARY", "canary_logs")
COLLECTION_CANARY_REGISTRY = os.environ.get("COLLECTION_CANARY_REGISTRY", "canaries")

# Honeypot thresholds
HONEYPOT_MAX_REQUESTS = _int("HONEYPOT_MAX_REQUESTS", 5)  # max requests in window
HONEYPOT_TIME_WINDOW = _int("HONEYPOT_TIME_WINDOW", 30)  # seconds

# Canaries
# Public base URL that canary files point back to. Set this to an address the
# monitored agents can reach (e.g. https://docs.example.internal).
CANARY_BASE_URL = os.environ.get("CANARY_BASE_URL", "http://127.0.0.1:5000").rstrip("/")
CANARY_FOLDER = os.environ.get("CANARY_FOLDER", "canaries")
CANARY_COUNT = _int("CANARY_COUNT", 5)  # canaries to keep on disk

COLLECTION_IP_REPUTATION = os.environ.get("COLLECTION_IP_REPUTATION", "ip_reputation")

# IP reputation enrichment (each provider is optional; leave the key empty to skip it)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
ABUSEIPDB_MIN_SCORE = _int("ABUSEIPDB_MIN_SCORE", 50)  # confidence % treated as malicious
ABUSEIPDB_MAX_AGE_DAYS = _int("ABUSEIPDB_MAX_AGE_DAYS", 90)
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY")  # ThreatFox
OTX_API_KEY = os.environ.get("OTX_API_KEY")
OTX_MIN_PULSES = _int("OTX_MIN_PULSES", 1)
ENRICH_CACHE_HOURS = _int("ENRICH_CACHE_HOURS", 24)

# IOC feeds (/feeds/...). If FEED_TOKEN is set, consumers must send it as a
# bearer token (or ?token=); otherwise the dashboard login protects the feeds.
FEED_TOKEN = os.environ.get("FEED_TOKEN")
FEED_DAYS = _int("FEED_DAYS", 30)
FEED_INCLUDE_PRIVATE = _bool("FEED_INCLUDE_PRIVATE", False)
ORG_NAME = os.environ.get("ORG_NAME", "LLM Deception Toolkit")

# Slack alerts (optional)
SLACK_TOKEN = os.environ.get("SLACK_TOKEN")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL")

# Dashboard
# If DASHBOARD_PASSWORD is set, the dashboard requires HTTP Basic auth.
DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD")
SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = _int("PORT", 5000)
DEBUG = _bool("FLASK_DEBUG", False)
# Number of reverse proxies in front of the app (for correct client IPs).
TRUSTED_PROXIES = _int("TRUSTED_PROXIES", 0)
