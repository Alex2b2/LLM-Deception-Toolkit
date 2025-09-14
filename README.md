# LLM Deception Toolkit

**LLM Deception Toolkit** is a powerful web application that leverages **honeypot detection** and **LLM-aware canaries** to identify and track malicious interactions. The application logs interactions, detects rapid requests, and provides real-time updates via a dashboard. 

## Key Features
- **Honeypot Detection**: Detects bots or automated systems making multiple rapid requests within a specified time window.
- **LLM-Aware Canaries**: Identifies interactions with semantic traps inserted into various files to detect AI-based agents.
- **Real-Time Dashboard**: Displays live updates on honeypot hits and canary triggers.
- **MongoDB Integration**: Logs all interactions in MongoDB, making it easy to track and review activity.
- **Slack Integration**: Alerts you in real-time via Slack whenever a canary is triggered or suspicious activity is detected.

---

## 🛠️ Technologies Used

- **Flask**: Lightweight web framework to serve the app.
- **Flask-SocketIO**: For real-time communication between the server and the front-end.
- **MongoDB**: Stores logs of honeypot interactions and canary triggers.
- **Bootstrap**: Responsive front-end design for a polished user interface.
- **FontAwesome**: Icons used for better UI components.
- **Slack API**: For real-time alerts to Slack channels.

---

## 🚀 Installation & Setup

### 1. Clone the repository:

```bash
git clone https://github.com/your-username/llm-deception-toolkit.git
cd llm-deception-toolkit
