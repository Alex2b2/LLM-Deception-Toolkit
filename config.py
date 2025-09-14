# MongoDB configuration
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "llm_deception"
COLLECTION_INTERACTIONS = "interactions"
COLLECTION_CANARY = "canary_logs"

# Honeypot thresholds
HONEYPOT_MAX_REQUESTS = 5  # Max requests in window
HONEYPOT_TIME_WINDOW = 30  # seconds

# Alerts (Slack example)
SLACK_TOKEN = "xoxb-9510210090195-9510222395843-ccM77l4vceV4JzBVpsTkj1L7"
SLACK_CHANNEL = "C09FHDEP2RX"