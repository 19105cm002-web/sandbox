import os
import json
import hashlib
import datetime

LOG_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(LOG_DIR, "sandbox_log.txt")
REPORT_FILE = os.path.join(LOG_DIR, "security_report.json")

SESSION_STATS = {
    "allowed": 0,
    "blocked": 0,
    "errors": 0,
    "high_risk": 0,
    "session_start": datetime.datetime.now().isoformat()
}

def log_event(status: str, command: str, message: str, risk: str = "LOW") -> None:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cmd_hash = hashlib.sha256(command.encode()).hexdigest()[:12]

    entry = (
        f"[{timestamp}] | STATUS={status:<8} | RISK={risk:<8} | "
        f"HASH={cmd_hash} | CMD=\"{command}\" | {message}\n"
    )

    with open(LOG_FILE, "a") as f:
        f.write(entry)

    if risk == "HIGH":
        print(f"\n{'='*60}")
        print(f"  [!] HIGH RISK ALERT GENERATED")
        print(f"  [!] Command: {command}")
        print(f"  [!] Reason : {message}")
        print(f"  [!] Time   : {timestamp}")
        print(f"{'='*60}\n")

def save_report() -> None:
    SESSION_STATS["session_end"] = datetime.datetime.now().isoformat()
    with open(REPORT_FILE, "w") as f:
        json.dump(SESSION_STATS, f, indent=4)
    print(f"[+] Security report saved: {REPORT_FILE}")

def get_stats() -> dict:
    return SESSION_STATS

def update_stat(key: str, increment: int = 1):
    if key in SESSION_STATS:
        SESSION_STATS[key] += increment

def get_log_file_path() -> str:
    return LOG_FILE
