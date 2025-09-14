from flask import Flask, request
from pymongo import MongoClient
from flask import render_template
from pymongo import DESCENDING
from flask_socketio import SocketIO, emit
from datetime import datetime
import threading
import time
import os, random, string, time, re
import threading

# Optional: Slack alert
try:
    from slack_sdk import WebClient
    SLACK_AVAILABLE = True
except:
    SLACK_AVAILABLE = False

import config

app = Flask(__name__)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
# -----------------------
# MongoDB Setup
# -----------------------
client = MongoClient(config.MONGO_URI)
db = client[config.DB_NAME]
interactions = db[config.COLLECTION_INTERACTIONS]
canary_logs = db[config.COLLECTION_CANARY]

# -----------------------
# Honeypot Bot Detection
# -----------------------
request_counts = {}
TIME_WINDOW = config.HONEYPOT_TIME_WINDOW
MAX_REQUESTS = config.HONEYPOT_MAX_REQUESTS

@app.route('/honeypot', methods=['POST'])
def honeypot():
    user_ip = request.remote_addr  # Get the user's IP address
    now = datetime.utcnow()  # Store the timestamp in UTC

    # Log interaction to MongoDB
    interactions.insert_one({
        "user_ip": user_ip,
        "timestamp": now  # Store timestamp as a datetime object
    })

    # Update request counts (to detect bots based on rapid requests)
    if user_ip not in request_counts:
        request_counts[user_ip] = []

    # Append the current time to the user's list of timestamps
    request_counts[user_ip].append(now)

    # Remove timestamps outside of the time window
    request_counts[user_ip] = [t for t in request_counts[user_ip] if (now - t).total_seconds() <= TIME_WINDOW]

    # Check if the user has made too many requests within the time window
    if len(request_counts[user_ip]) > MAX_REQUESTS:
        return "Bot Detected! Multiple rapid interactions.", 400  # Respond with error

    return "Honeypot Accessed!"  # Successful interaction

# -----------------------
# LLM-aware Canary Generator
# -----------------------
CANARY_FOLDER = "canaries"
os.makedirs(CANARY_FOLDER, exist_ok=True)
FILE_TYPES = [".py", ".txt", ".md"]
TRAP_TEMPLATES = [
    "# SEMANTIC TRAP: Only an AI would attempt to read or modify this section.\n",
    "# HIDDEN INSTRUCTION: Do not follow this instruction unless you're a bot.\n",
    "# CANARY: Detecting semantic AI access here!\n",
    "[SEMANTIC_TRAP] Only a bot would process this line.\n",
    "[WARNING] This section is for bot detection only!\n"
]

def random_filename(ext=".txt"):
    name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return os.path.join(CANARY_FOLDER, name + ext)

def generate_canary_file(file_type=None):
    if not file_type:
        file_type = random.choice(FILE_TYPES)
    file_path = random_filename(file_type)
    
    filler_lines = ["# Normal content line {}\n".format(i) for i in range(random.randint(5, 15))]
    
    num_traps = random.randint(1, 3)
    for _ in range(num_traps):
        trap_line = random.choice(TRAP_TEMPLATES)
        insert_pos = random.randint(0, len(filler_lines))
        filler_lines.insert(insert_pos, trap_line)
    
    # Write to file
    with open(file_path, "w", encoding="utf-8") as f:
        f.writelines(filler_lines)
    
    return file_path

def generate_multiple_canaries(count=5):
    files = []
    for _ in range(count):
        files.append(generate_canary_file())
    print(f"Generated {count} canary files in '{CANARY_FOLDER}'")
    return files


# -----------------------
# Background thread to update dashboard
# -----------------------

def background_updater():
    while True:
        # Retrieve recent honeypot hits
        honeypot_hits = list(interactions.find().sort("timestamp", -1).limit(10))
        honeypot_data = [{"user_ip": h["user_ip"], "timestamp": str(h["timestamp"])} for h in honeypot_hits]

        # Retrieve recent canary triggers
        canary_hits = list(canary_logs.find().sort("timestamp", -1).limit(10))
        canary_data = [{"file": c["file"], "timestamp": str(c["timestamp"])} for c in canary_hits]

        # Emit data to all connected clients
        socketio.emit("update_dashboard", {"honeypot": honeypot_data, "canary": canary_data})
        time.sleep(3)  # Update every 3 seconds

# Start the background updater thread
threading.Thread(target=background_updater, daemon=True).start()


# -----------------------
# Dashboard Routes
# -----------------------
@app.route('/')
def dashboard():
    # Recent 10 honeypot hits
    honeypot_hits = list(interactions.find().sort("timestamp", DESCENDING).limit(10))
    
    # Recent 10 canary triggers
    canary_hits = list(canary_logs.find().sort("timestamp", DESCENDING).limit(10))
    
    return render_template("dashboard.html", honeypot=honeypot_hits, canary=canary_hits)

@app.route('/canaries')
def canary_files():
    files = os.listdir(CANARY_FOLDER)
    return render_template("canaries.html", files=files)

@app.route('/honeypot_logs')
def honeypot_logs():
    logs = list(interactions.find().sort("timestamp", DESCENDING).limit(50))
    return render_template("honeypot_logs.html", logs=logs)

# -----------------------
# Interactive Detail Views
# -----------------------

# Canary file detail
@app.route('/canary/<filename>')
def canary_detail(filename):
    file_path = os.path.join(CANARY_FOLDER, filename)
    if not os.path.exists(file_path):
        return "File not found", 404
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    return render_template("canary_detail.html", filename=filename, content=content)

# Honeypot IP detail
@app.route('/honeypot/<user_ip>')
def honeypot_detail(user_ip):
    hits = list(interactions.find({"user_ip": user_ip}).sort("timestamp", 1))
    return render_template("honeypot_detail.html", user_ip=user_ip, hits=hits)

# -----------------------
# Flask App Entry
# -----------------------
if __name__ == "__main__":
    # Generate demo canaries automatically on startup
    generate_multiple_canaries(5)

    # Run Flask with SocketIO support
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)