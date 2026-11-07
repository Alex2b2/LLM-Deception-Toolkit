# LLM Deception Toolkit

![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)

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

1. A Flask app serves honeypot endpoints and hosts canary content.
2. Each request is logged to MongoDB. If a client exceeds the request threshold inside the time window (default: 5 requests in 30 seconds), it is flagged as a honeypot hit.
3. When a canary is touched or acted on, a canary event is recorded with its details.
4. Flask-SocketIO pushes new events to the dashboard in real time.
5. If Slack is configured, an alert is sent to your chosen channel.

<!-- VERIFY: confirm the flow above matches app.py, especially how canary triggers are detected. -->

## Screenshots

| Honeypot logs | Canary events |
| --- | --- |
| ![Honeypot](assets/Honeypot_logs.png) | ![Canary](assets/Canary.png) |

![Canary details](assets/CanaryDetails.png)

## Installation and setup

### Prerequisites

- Python 3.9 or newer
- MongoDB (local install or a hosted instance such as MongoDB Atlas)
- A Slack app with a bot token (optional, for alerts)

### 1. Clone the repository

bash
git clone https://github.com/Alex2b2/LLM-Deception-Toolkit.git
cd LLM-Deception-Toolkit


### 2. Create a virtual environment and install dependencies

bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt


### 3. Set environment variables

Copy `.env.example` to `.env`, or export the variables in your shell:

bash
export MONGO_URI="mongodb://localhost:27017/"
export SLACK_TOKEN="your-slack-bot-token"      # optional
export SLACK_CHANNEL="your-slack-channel-id"   # optional


### 4. Start MongoDB

Make sure MongoDB is running and reachable at the URI you set.

### 5. Run the app

bash
python app.py


Then open http://localhost:5000 to see the dashboard.

<!-- VERIFY: confirm the port, and whether app.py loads .env (needs python-dotenv) or relies on exported variables. -->

## Configuration

Settings live in `config.py`. Secrets are read from environment variables.

| Setting | Default | Description |
| --- | --- | --- |
| `MONGO_URI` | `mongodb://localhost:27017/` | MongoDB connection string |
| `DB_NAME` | `llm_deception` | Database name |
| `COLLECTION_INTERACTIONS` | `interactions` | Collection for honeypot and request logs |
| `COLLECTION_CANARY` | `canary_logs` | Collection for canary events |
| `HONEYPOT_MAX_REQUESTS` | `5` | Requests allowed inside the time window before a client is flagged |
| `HONEYPOT_TIME_WINDOW` | `30` | Time window in seconds |
| `SLACK_TOKEN` | none | Slack bot token (environment variable) |
| `SLACK_CHANNEL` | none | Slack channel ID (environment variable) |

If `SLACK_TOKEN` is not set, the app should run without sending Slack alerts.

<!-- VERIFY: confirm app.py handles a missing SLACK_TOKEN without crashing. -->

## Usage

1. Start the app and open the dashboard.
2. Place or expose the honeypot endpoints and canary files in an environment you own and control.
3. Watch the dashboard for hits. Each event includes the interaction details stored in MongoDB.
4. Review events in MongoDB, or use Slack alerts to be notified as they happen.

Only deploy this on systems you own or are explicitly authorised to monitor.

## Project structure

LLM-Deception-Toolkit/
├── app.py              # Flask application, routes and real-time events
├── config.py           # Configuration and thresholds
├── canaries/           # Canary files containing semantic traps
├── templates/          # HTML templates for the dashboard
├── assets/             # Screenshots used in this README
├── Scripts/            # Helper scripts
├── requirements.txt    # Python dependencies
├── CONTRIBUTING.md
└── LICENSE


## Threat model and limitations

**What it is designed to detect**

- Automated clients that hit honeypot endpoints at a high rate.
- AI agents that read canary content and act on the embedded instructions.

**What it does not do**

- It does not block or rate-limit traffic. It observes, logs and alerts.
- A slow or low-volume client can stay under the request threshold, so rate-based detection can be evaded.
- Legitimate crawlers or monitoring tools can trigger the honeypot and cause false positives.
- A canary only fires if an agent reads it and acts on it. Agents that ignore embedded instructions will not trigger it.
- It has not been evaluated against a broad set of real-world agents, so detection rates are not yet known.
- The dashboard should not be exposed to the public internet. Run it on a private network or behind authentication.

## Security notes

- Keep all credentials out of the repository. Use environment variables or a `.env` file, which is listed in `.gitignore`.
- If you ever commit a token by accident, revoke it immediately. Deleting it from the file is not enough, because it remains in git history.
- Treat everything logged to MongoDB as untrusted input when viewing or processing it.
- To report a vulnerability, open a GitHub issue without sensitive details, or contact the maintainer through their GitHub profile.

## Roadmap

- [ ] Tests and CI
- [ ] Docker and one-command setup
- [ ] Map canary and honeypot events to the OWASP Top 10 for LLM Applications and MITRE ATLAS
- [ ] Authentication for the dashboard
- [ ] Tagged releases and a demo write-up with test results

## Contributing

Contributions, issues and ideas are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Released under the [GPL-3.0 license](LICENSE).
