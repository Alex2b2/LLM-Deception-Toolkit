# LLM Deception Toolkit

![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![tests](https://github.com/Alex2b2/LLM-Deception-Toolkit/actions/workflows/tests.yml/badge.svg)

A web application that uses **honeypots** and **LLM-aware canaries** to detect, log and alert on automated and AI-agent activity. It records suspicious interactions in MongoDB, shows them on a real-time dashboard, and can send alerts to Slack.

![Dashboard](assets/Dashboard.png)

## Table of Contents

- [Why this exists](#why-this-exists)
- [Key features](#key-features)
- [How it works](#how-it-works)
- [Screenshots](#screenshots)
- [Installation and setup](#installation-and-setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [IP reputation enrichment](#ip-reputation-enrichment)
- [IOC feeds](#ioc-feeds)
- [Analytics dashboard](#analytics-dashboard)
- [Project structure](#project-structure)
- [Threat model and limitations](#threat-model-and-limitations)
- [Security notes](#security-notes)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Why this exists

AI agents and LLM-powered tools increasingly browse, read files and call endpoints on their own. Traditional bot detection looks at request patterns, but it says little about whether the client is an LLM-driven agent following instructions it found in content.

This project explores a deception-based approach: place traps where an automated client or an AI agent is likely to touch them, then log and alert when it does.

## Key features

- **Honeypot detection**: flags clients that make multiple rapid requests within a configurable time window.
- **LLM-aware canaries**: semantic traps placed in files, designed to be picked up and acted on by AI-based agents, so a trigger is evidence of agent behaviour.
- **Real-time dashboard**: live view of honeypot hits and canary triggers.
- **MongoDB logging**: every interaction is stored for later review and investigation.
- **Slack alerts**: optional real-time notifications when a canary fires or suspicious activity is detected.
- **IP reputation enrichment**: every canary trigger and honeypot flag is checked against AbuseIPDB, abuse.ch ThreatFox and AlienVault OTX, recording whether the source was already known as malicious.
- **IOC feeds**: source IPs, user agents and triggered canary URLs published as a STIX 2.1 bundle, a MISP feed and CSV.
- **Analytics**: triggers over time, which agents hit which canary types, and how many attackers were already known versus new.

## How it works

1. A Flask app serves trap endpoints and a private dashboard.
2. **Honeypot:** every `POST /honeypot` request is logged to MongoDB with the client IP and user agent. A client that exceeds the threshold inside the time window (default: 5 requests in 30 seconds) is flagged as a bot, gets HTTP 429, and triggers one Slack alert.
3. **Canaries:** on start-up the app generates realistic decoy files (onboarding notes, a production settings file, a credentials backup). Each file carries a unique token in two traps:
   - a callback URL (`/c/<token>`) with an embedded instruction telling AI assistants to fetch it, which catches agents that follow indirect prompt injection;
   - a fake API key (`sk-live-<token>`) with a "validation" endpoint (`/api/v1/keys/verify`), which catches agents or scripts that harvest and try credentials.
4. When either trap is hit, the app looks up the token, records which file it came from plus the IP, user agent and trigger type, and returns a plausible response so the agent carries on normally.
5. Flask-SocketIO pushes new events to the dashboard in real time, and Slack alerts go to your chosen channel if configured.

A human reading a canary file has no reason to call either trap, so a hit is strong evidence of automated or agent behaviour.

## Screenshots

| Honeypot logs | Canary events |
| --- | --- |
| ![Honeypot](assets/Honeypot_logs.png) | ![Canary](assets/Canary.png) |

![Canary details](assets/CanaryDetails.png)

## Installation and setup

### Prerequisites

- Python 3.10 or newer
- MongoDB (local install or a hosted instance such as MongoDB Atlas)
- A Slack app with a bot token (optional, for alerts)

### 1. Clone the repository

```bash
git clone https://github.com/Alex2b2/LLM-Deception-Toolkit.git
cd LLM-Deception-Toolkit
```

### 2. Create a virtual environment and install dependencies

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Set environment variables

Copy `.env.example` to `.env` (loaded automatically), or export the variables in your shell:

```bash
export MONGO_URI="mongodb://localhost:27017/"
export SLACK_TOKEN="your-slack-bot-token"      # optional
export SLACK_CHANNEL="your-slack-channel-id"   # optional
```

Do not commit real tokens. See [Security notes](#security-notes).

### 4. Start MongoDB

Make sure MongoDB is running and reachable at the URI you set.

### 5. Run the app

```bash
python app.py
```

Then open http://localhost:5000 to see the dashboard. Canary files are generated in `canaries/` on first start, and existing ones are kept across restarts.

### 6. Run the tests

```bash
pip install -r requirements-dev.txt
pytest
```


## Configuration

All settings are read from environment variables (or `.env`). Defaults live in `config.py`; secrets have no default.

| Setting | Default | Description |
| --- | --- | --- |
| `MONGO_URI` | `mongodb://localhost:27017/` | MongoDB connection string |
| `DB_NAME` | `llm_deception` | Database name |
| `CANARY_BASE_URL` | `http://127.0.0.1:5000` | URL canary files point back to. Must be reachable by the agents you monitor |
| `CANARY_COUNT` | `5` | Number of canary files to keep in `canaries/` |
| `HONEYPOT_MAX_REQUESTS` | `5` | Requests allowed inside the time window before a client is flagged |
| `HONEYPOT_TIME_WINDOW` | `30` | Time window in seconds |
| `SLACK_TOKEN` / `SLACK_CHANNEL` | none | Slack bot token and channel ID. Alerts are off if unset |
| `ABUSEIPDB_API_KEY` | none | Enables AbuseIPDB lookups |
| `ABUSEIPDB_MIN_SCORE` | `50` | AbuseIPDB confidence score (%) treated as malicious |
| `ABUSECH_AUTH_KEY` | none | Enables abuse.ch ThreatFox lookups |
| `OTX_API_KEY` | none | Enables AlienVault OTX lookups |
| `OTX_MIN_PULSES` | `1` | OTX pulse count treated as malicious |
| `ENRICH_CACHE_HOURS` | `24` | How long a reputation result is reused before re-checking |
| `FEED_TOKEN` | none | Bearer token for the IOC feeds. If unset, feeds use the dashboard login |
| `FEED_DAYS` | `30` | Default look-back window for feeds (override with `?days=`) |
| `FEED_INCLUDE_PRIVATE` | `false` | Include private/internal IPs in feeds |
| `ORG_NAME` | `LLM Deception Toolkit` | Producer name in STIX and MISP output |
| `DASHBOARD_USER` / `DASHBOARD_PASSWORD` | `admin` / none | HTTP Basic auth for the dashboard. Required if `HOST` is not `127.0.0.1` |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Bind address |
| `TRUSTED_PROXIES` | `0` | Number of reverse proxies in front of the app, for correct client IPs |
| `FLASK_DEBUG` | `false` | Never enable on an exposed deployment |

## Usage

1. Start the app and open the dashboard.
2. Place or expose the honeypot endpoints and canary files in an environment you own and control.
3. Watch the dashboard for hits. Each event includes the interaction details stored in MongoDB.
4. Review events in MongoDB, or use Slack alerts to be notified as they happen.

Only deploy this on systems you own or are explicitly authorised to monitor.

## IP reputation enrichment

When a canary fires, or the honeypot first flags a client, the source IP is looked up in every provider you have a key for. All three offer free API keys:

| Provider | What it checks | Treated as malicious when | Get a key |
| --- | --- | --- | --- |
| AbuseIPDB | Abuse confidence score and report count | score >= `ABUSEIPDB_MIN_SCORE` | abuseipdb.com/register |
| abuse.ch ThreatFox | Malware IOC database (C2 servers and similar) | any IOC for this IP | auth.abuse.ch |
| AlienVault OTX | Community threat "pulses" mentioning the IP | pulses >= `OTX_MIN_PULSES` | otx.alienvault.com |

- The lookup runs in the background, so the trap still responds instantly. The result is stored on the event and added to the Slack alert.
- Results are cached per IP (`ip_reputation` collection) for `ENRICH_CACHE_HOURS` to save API quota.
- Private, loopback and reserved addresses are never sent to third parties.
- An IP is **known** if any provider says malicious, **new** if all providers that answered say clean.

## IOC feeds

| Endpoint | Format | Use it with |
| --- | --- | --- |
| `/feeds/stix.json` | STIX 2.1 bundle | OpenCTI, Sentinel, any STIX-aware tool |
| `/feeds/misp/manifest.json` | MISP feed | MISP (Sync Actions > Feeds > Add feed, type "MISP Feed", URL `https://<host>/feeds/misp`) |
| `/feeds/iocs.csv` | CSV | Spreadsheets, SIEM lookups, blocklists |

Each feed contains the source IPs of canary triggers and flagged honeypot clients, the user agents seen, and the canary URLs that were triggered. IDs are deterministic, so re-importing updates existing indicators instead of duplicating them. Indicators from IPs already reported elsewhere are marked `malicious-activity` (STIX) / tagged `known-malicious` (MISP); the rest are `anomalous-activity`. User agents are exported for context only (`to_ids: false` in MISP), because they are easy to spoof and widely shared.

Set `FEED_TOKEN` and have consumers send `Authorization: Bearer <token>` (MISP lets you add this as a custom header on the feed), or append `?token=<token>`. Use `?days=7` to narrow the window. This is a plain HTTPS feed, not a TAXII server.

## Analytics dashboard

`/analytics` shows, for the last 7, 30 or 90 days:

- headline counts: canary triggers, honeypot flags, unique source IPs, and new vs already-known attackers
- triggers over time (daily)
- triggers per canary type, split by what the agent did (followed the callback URL or tried the fake API key)
- agents behind the triggers, grouped into families from the user agent (for example OpenAI ChatGPT-User, Anthropic ClaudeBot, Python requests, headless browsers)
- every source IP with its reputation scores, and the top user agents

The page refreshes when new events arrive. Agent families are a heuristic based on the user agent, which clients can fake.

## Project structure

```
LLM-Deception-Toolkit/
├── app.py              # Flask app: trap endpoints, dashboard, real-time updates
├── canaries.py         # Canary templates, token generation and registry
├── alerts.py           # Slack alerting
├── enrichment.py       # AbuseIPDB / ThreatFox / OTX lookups with caching
├── iocs.py             # IOC collection and STIX / MISP / CSV export
├── analytics.py        # Aggregations and agent classification for /analytics
├── config.py           # Configuration from environment variables
├── canaries/           # Generated canary files (git-ignored)
├── templates/          # Dashboard HTML templates
├── tests/              # pytest suite (runs without MongoDB)
├── assets/             # Screenshots used in this README
├── .env.example
├── requirements.txt
├── requirements-dev.txt
├── CONTRIBUTING.md
└── LICENSE
```

## Threat model and limitations

**What it is designed to detect**

- Automated clients that hit honeypot endpoints at a high rate.
- AI agents that read canary content and act on the embedded instructions.

**What it does not do**

- It does not block or rate-limit traffic. It observes, logs and alerts.
- A slow or low-volume client can stay under the request threshold, so rate-based detection can be evaded.
- Legitimate crawlers or monitoring tools can trigger the honeypot and cause false positives.
- A canary only fires if an agent reads it and acts on it (fetches the callback URL or tries the fake key). Agents that ignore embedded instructions will not trigger it.
- Canary files must be placed where agents will find them (a docs site, a shared drive, a repo you control) and `CANARY_BASE_URL` must be reachable from there.
- It has not been evaluated against a broad set of real-world agents, so detection rates are not yet known.
- The dashboard should not be exposed to the public internet. Set `DASHBOARD_PASSWORD` and run it behind HTTPS if it is reachable from other machines.

## Security notes

- Keep all credentials out of the repository. Use environment variables or a `.env` file, which is listed in `.gitignore`.
- If you ever commit a token by accident, revoke it immediately. Deleting it from the file is not enough, because it remains in git history.
- Treat everything logged to MongoDB as untrusted input when viewing or processing it.
- To report a vulnerability, open a GitHub issue without sensitive details, or contact the maintainer through their GitHub profile.

## Roadmap

- [x] Tests and CI
- [ ] Docker and one-command setup
- [ ] Map canary and honeypot events to the OWASP Top 10 for LLM Applications and MITRE ATLAS
- [x] Authentication for the dashboard
- [x] Token-based canary triggers with file attribution
- [x] IP reputation enrichment (AbuseIPDB, ThreatFox, OTX)
- [x] IOC export as STIX 2.1, MISP feed and CSV
- [x] Analytics dashboard
- [ ] TAXII 2.1 server for the STIX feed
- [ ] Tagged releases and a demo write-up with test results

## Contributing

Contributions, issues and ideas are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Released under the [GPL-3.0 license](LICENSE).
