from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import math

from monitoring.log_writer import write_log
from monitoring.risk_manager import update_risk_score


stop_flag = False


def stop_monitoring():
    """Stop monitoring loop"""
    global stop_flag
    stop_flag = True
    print("STOP FLAG RECEIVED – Monitor will stop.")


# ---------------------------------------------------
# Entropy Detection
# ---------------------------------------------------
def calculate_entropy(file_path):
    if not os.path.isfile(file_path):
        return None

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return 0

        counts = [0] * 256
        for b in data:
            counts[b] += 1

        entropy = 0
        for c in counts:
            if c > 0:
                p = c / len(data)
                entropy -= p * math.log2(p)

        return entropy

    except Exception as e:
        print("Entropy error:", e)
        return None


# ---------------------------------------------------
# Event Monitor Class
# ---------------------------------------------------
class SimpleFileMonitor(FileSystemEventHandler):

    # Suspicious ransomware extensions
    SUSPICIOUS_EXTENSIONS = [
        ".encrypted", ".locked", ".enc", ".crypt", ".r4nsom", ".pay"


    def __init__(self):
        self.recent_events = []
        self.time_window = 5
        self.threshold = 10

    def should_ignore(self, path):
        filename = os.path.basename(path)

        ignore_list = [
            "event_logs.json",
            "risk_score.json",
            "__pycache__"
        ]

        if filename in ignore_list:
            return True
        if ".venv" in path or ".vscode" in path:
            return True
        if filename.startswith("~") or filename.startswith("."):
            return True

        return False

    # Core event logger
    def _record_event(self, message, score, file_path=None):
        print(message)
        write_log(message, score)
        update_risk_score(score)

        # -------------------------------
        # BURST DETECTION
        # -------------------------------
        now = time.time()
        self.recent_events.append(now)
        self.recent_events = [t for t in self.recent_events if now - t <= self.time_window]

        if len(self.recent_events) >= self.threshold:
            burst_msg = f"Suspicious burst detected! {len(self.recent_events)} events in {self.time_window}s"
            print(burst_msg)
            write_log(burst_msg, 30)
            update_risk_score(30)

        # -------------------------------
        # ENTROPY DETECTION
        # -------------------------------
        if file_path and os.path.isfile(file_path):
            entropy = calculate_entropy(file_path)
            if entropy and entropy > 8.5:
                alert = f"High entropy detected ({entropy:.2f}) - Possible ransomware activity: {file_path}"
                print(alert)
                write_log(alert, 50)
                update_risk_score(50)

    # -------------------------------
    # EVENT HANDLERS
    # -------------------------------
    def on_modified(self, event):
        if self.should_ignore(event.src_path):
            return

        ext = os.path.splitext(event.src_path)[1].lower()

        # RANSOMWARE EXTENSION CHECK
        if ext in self.SUSPICIOUS_EXTENSIONS:
            alert = f"⚠ Ransomware Signature Detected: {event.src_path}"
            print(alert)
            write_log(alert, 70)
            update_risk_score(70)

        self._record_event(f"File Modified: {event.src_path}", 5, event.src_path)

    def on_created(self, event):
        if self.should_ignore(event.src_path):
            return

        ext = os.path.splitext(event.src_path)[1].lower()

        # RANSOMWARE EXTENSION CHECK
        if ext in self.SUSPICIOUS_EXTENSIONS:
            alert = f"⚠ Ransomware Signature Detected: {event.src_path}"
            print(alert)
            write_log(alert, 70)
            update_risk_score(70)

        self._record_event(f"File Created: {event.src_path}", 8, event.src_path)

    def on_deleted(self, event):
        if self.should_ignore(event.src_path):
            return

        self._record_event(f"File Deleted: {event.src_path}", 8, None)

    #on_moved 
    def on_moved(self, event):
        if self.should_ignore(event.dest_path):
            return

        ext = os.path.splitext(event.dest_path)[1].lower()

        if ext in self.SSUSPICIOUS_EXTENSION:
            alert = f"⚠ Ransomware Signature Detected: {event.dest_path}"
            print(alert)
            write_log(alert, 70)
            update_risk_score(70)

        self._record_event(f"File Renamed: {event.src_path} → {event.dest_path}", 5, event.dest_path)
# ---------------------------------------------------
# MAIN LOOP
# ---------------------------------------------------
def start_monitoring(path_to_watch):
    global stop_flag
    stop_flag = False

    handler = SimpleFileMonitor()
    observer = Observer()
    observer.schedule(handler, path_to_watch, recursive=True)
    observer.start()

    print(f"Monitoring started on: {path_to_watch}")

    try:
        while not stop_flag:
            time.sleep(1)

    finally:
        observer.stop()
        observer.join()
        print("Monitoring stopped cleanly.")
