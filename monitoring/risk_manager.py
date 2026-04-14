import json
import os
import smtplib
from email.mime.text import MIMEText

RISK_FILE = "risk_score.json"


# -----------------------------------------------------
# LOAD RISK DATA
# -----------------------------------------------------
def load_risk_data():
    if os.path.exists(RISK_FILE):
        try:
            with open(RISK_FILE, "r") as f:
                return json.load(f)
        except:
            print("Risk file corrupted. Resetting...")
            pass

    # fallback default
    return {"score": 0, "level": "Safe"}


# -----------------------------------------------------
# SAVE RISK DATA
# -----------------------------------------------------
def save_risk_data(data):
    with open(RISK_FILE, "w") as f:
        json.dump(data, f, indent=4)


# -----------------------------------------------------
# SEND EMAIL ALERT WHEN CRITICAL
# -----------------------------------------------------
def send_email_alert(score, level):
    sender = "ssmahadevambadi@gmail.com"
    password = "kgsf hyfg hako ykzg"  # Gmail App Password
    receiver = "mahadev.ambadi@btech.christuniversity.in"

    msg = MIMEText(
        f"""
⚠️ CRITICAL THREAT DETECTED!

Risk Score: {score}
Level: {level}

Immediate attention required!
"""
    )

    msg["Subject"] = "⚠️ CRITICAL THREAT ALERT DETECTED"
    msg["From"] = sender
    msg["To"] = receiver

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()
        print("EMAIL ALERT SENT!")
    except Exception as e:
        print("Email send error:", e)


# -----------------------------------------------------
# UPDATE RISK SCORE + TRIGGER EMAIL ALERT
# -----------------------------------------------------
def update_risk_score(amount):
    data = load_risk_data()
    data["score"] += amount

    # clamp score
    data["score"] = max(0, min(100, data["score"]))

    # LEVEL CALCULATION
    if data["score"] < 20:
        data["level"] = "Safe"
    elif data["score"] < 40:
        data["level"] = "Low"
    elif data["score"] < 60:
        data["level"] = "Medium"
    elif data["score"] < 80:
        data["level"] = "High"
    else:
        data["level"] = "Critical"

    # SAVE UPDATED SCORE
    save_risk_data(data)

    # ONLY SEND EMAIL WHEN ENTERING CRITICAL ZONE
    if data["level"] == "Critical":
        send_email_alert(data["score"], data["level"])


# -----------------------------------------------------
# RESET RISK SCORE
# -----------------------------------------------------
def reset_risk_score():
    data = {"score": 0, "level": "Safe"}
    save_risk_data(data)
    return data
