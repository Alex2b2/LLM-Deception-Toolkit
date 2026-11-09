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

## Project structure

```
LLM-Deception-Toolkit/
├── app.py              # Flask app: trap endpoints, dashboard, real-time updates
├── canaries.py         # Canary templates, token generation and registry
├── alerts.py           # Slack alerting
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
- [ ] Tagged releases and a demo write-up with test results

## Contributing

Contributions, issues and ideas are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Released under the [GPL-3.0 license](LICENSE).
