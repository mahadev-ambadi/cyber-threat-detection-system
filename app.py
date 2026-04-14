from flask import Flask, render_template, jsonify, request
from monitoring.log_writer import get_recent_logs
from monitoring.risk_manager import load_risk_data
import threading
import os
import psutil

from monitoring.file_monitor import start_monitoring, stop_monitoring

app = Flask(__name__)

monitor_thread = None
monitor_running = False

# Store last network counters for speed calculation
last_net = psutil.net_io_counters()


# ---------------------------------------
# DASHBOARD PAGE
# ---------------------------------------
@app.route("/")
def home():
    return render_template("dashboard.html")


# ---------------------------------------
# SYSTEM HEALTH API
# ---------------------------------------
@app.route("/api/system_health")
def system_health():
    try:
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent

        # Get total bytes sent + received
        net = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv

        return jsonify({
            "cpu": cpu,
            "ram": ram,
            "network": net
        })

    except Exception as e:
        print("SYSTEM HEALTH ERROR:", e)
        return jsonify({"error": str(e)}), 500




# ---------------------------------------
# RISK + LOG APIs
# ---------------------------------------
@app.route("/api/logs")
def api_logs():
    return jsonify(get_recent_logs())


@app.route("/api/risk")
def api_risk():
    return jsonify(load_risk_data())


@app.route("/api/reset_risk", methods=["POST"])
def api_reset_risk():
    try:
        from monitoring.risk_manager import reset_risk_score
        data = reset_risk_score()
        return jsonify({"status": "reset", "data": data}), 200
    except Exception as e:
        print("RESET ERROR:", e)
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------
# START MONITOR
# ---------------------------------------
@app.route("/api/start_monitor", methods=["POST"])
def api_start_monitor():
    global monitor_thread, monitor_running

    if monitor_running:
        return jsonify({"status": "already_running"})

    watch_path = os.getcwd()

    monitor_thread = threading.Thread(
        target=start_monitoring,
        args=(watch_path,),
        daemon=True
    )
    monitor_thread.start()

    monitor_running = True
    return jsonify({"status": "started"})


# ---------------------------------------
# STOP MONITOR
# ---------------------------------------
@app.route("/api/stop_monitor", methods=["POST"])
def api_stop_monitor():
    global monitor_running

    if not monitor_running:
        return jsonify({"status": "already_stopped"})

    stop_monitoring()
    monitor_running = False

    return jsonify({"status": "stopped"})


# ---------------------------------------
# MONITOR STATUS
# ---------------------------------------
@app.route("/api/monitor_status")
def api_monitor_status():
    return jsonify({"running": monitor_running})


# ---------------------------------------
# RUN FLASK
# ---------------------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
