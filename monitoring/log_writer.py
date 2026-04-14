# monitoring/log_writer.py

import json
import os
from datetime import datetime
from monitoring.risk_manager import update_risk_score

LOG_FILE = "event_logs.json"


def write_log(message, score):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = {
        "timestamp": timestamp,
        "message": message,
        "score": score
    }

    # Read existing logs safely
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                logs = json.load(f)
            except:
                logs = []
    else:
        logs = []

    logs.append(entry)

    # Save updated logs
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

    # Update RISK SCORE
    update_risk_score(score)


def get_recent_logs():
    """Return the latest logs safely"""
    if not os.path.exists(LOG_FILE):
        return []

    try:
        with open(LOG_FILE, "r") as f:
            return json.load(f)
    except:
        return []
