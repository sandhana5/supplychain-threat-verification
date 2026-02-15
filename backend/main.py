# backend/main.py - COMPLETE & WORKING VERSION with polling
from fastapi import FastAPI
import pandas as pd
import os
import time
import threading
from src.decision_engine import final_decision

app = FastAPI(title="ChainGuard Backend")

# Paths
LIVE_LOG_PATH = "data/live_logs.csv"
ATTACKS_DIR = "data/attacks"

# Initialize live log file with headers if missing or empty
def init_live_log():
    os.makedirs("data", exist_ok=True)
    os.makedirs(ATTACKS_DIR, exist_ok=True)

    if not os.path.exists(LIVE_LOG_PATH) or os.path.getsize(LIVE_LOG_PATH) == 0:
        columns = [
            "timestamp", "src_ip", "dst_ip", "process_name", "file_hash",
            "signature_status", "outbound_conn_5min", "dns_query", "log_line",
            "jndi_present", "entropy", "label",
            "anomaly_score", "verdict", "reason"
        ]
        pd.DataFrame(columns=columns).to_csv(LIVE_LOG_PATH, index=False)
        print("[INIT] Created fresh live_logs.csv with headers")

init_live_log()

# Polling function - reliable file change detection on Windows
def poll_for_changes():
    print("[POLLING STARTED] Monitoring live_logs.csv every 1 second")
    last_size = os.path.getsize(LIVE_LOG_PATH) if os.path.exists(LIVE_LOG_PATH) else 0

    while True:
        time.sleep(1)
        try:
            current_size = os.path.getsize(LIVE_LOG_PATH)
            if current_size > last_size:
                print(f"[POLLING] File size increased ({last_size} → {current_size} bytes) - running detection")
                process_new_logs()
                last_size = current_size
        except Exception as e:
            print(f"[POLLING ERROR] {e}")

# Start polling in background thread
threading.Thread(target=poll_for_changes, daemon=True).start()

# Detection function
def process_new_logs():
    print("[DETECTION TRIGGERED] Processing latest row in live_logs.csv")
    try:
        df = pd.read_csv(LIVE_LOG_PATH)

        if len(df) == 0:
            print("[DETECTION] File is empty - skipping")
            return

        # Ensure result columns exist
        for col in ["anomaly_score", "verdict", "reason"]:
            if col not in df.columns:
                df[col] = 0 if col == "anomaly_score" else "N/A"

        # Get last row
        last_index = len(df) - 1
        log_dict = df.iloc[last_index].to_dict()

        # DEBUG: Show current state of last row
        print(f"[DEBUG LAST ROW] anomaly_score={log_dict.get('anomaly_score')}, verdict={log_dict.get('verdict')}, reason={log_dict.get('reason')}")

        # Skip only if clearly already processed (score >0 AND verdict is BLOCK or ALERT)
        if log_dict.get("anomaly_score", 0) > 0 and log_dict.get("verdict") in ["BLOCK", "ALERT"]:
            print("[DETECTION] Row already processed with BLOCK/ALERT - skipping")
            return

        print("[DETECTION] Processing new row (not previously scored)")

        print(f"[DETECTION] Processing: {log_dict.get('process_name', 'unknown')} - {log_dict.get('label', 'normal')}")

        # Run full detection
        result = final_decision(log_dict.copy())

        # Update last row
        df.at[last_index, "anomaly_score"] = result.get("anomaly_score", 0)
        df.at[last_index, "verdict"] = result.get("verdict", "NORMAL")
        df.at[last_index, "reason"] = result.get("reason", "N/A")

        # Save back
        df.to_csv(LIVE_LOG_PATH, index=False)
        print("[DETECTION] Updated CSV with results")

    except Exception as e:
        print(f"[DETECTION ERROR] {e}")

# Routes
@app.get("/")
def home():
    return {"status": "ChainGuard backend running"}

@app.get("/inject/{attack_type}")
def inject_attack(attack_type: str):
    attacks = {
        "kaseya": "kaseya.csv",
        "log4j": "log4j.csv",
        "solarwinds": "solarwinds.csv",
        "xz": "xz.csv"
    }

    if attack_type not in attacks:
        return {"error": "Invalid attack type"}

    try:
        attack_path = os.path.join(ATTACKS_DIR, attacks[attack_type])
        attack_df = pd.read_csv(attack_path)
        sample = attack_df.sample(1).iloc[0].to_dict()

        # Append safely
        header = not os.path.exists(LIVE_LOG_PATH) or os.path.getsize(LIVE_LOG_PATH) == 0
        pd.DataFrame([sample]).to_csv(LIVE_LOG_PATH, mode='a', header=header, index=False)

        print(f"[INJECTED] {attack_type.upper()} attack injected - process: {sample.get('process_name')}")

        return {
            "status": "injected",
            "attack": attack_type,
            "message": "Attack injected! Detection should follow..."
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/current_status")
def get_status():
    try:
        if not os.path.exists(LIVE_LOG_PATH) or os.path.getsize(LIVE_LOG_PATH) == 0:
            return {"threat_level": "LOW", "anomaly_score": 0, "verdict": "NORMAL"}

        df = pd.read_csv(LIVE_LOG_PATH)
        df.fillna({"anomaly_score": 0, "verdict": "NORMAL", "reason": "N/A", "process_name": "Unknown"}, inplace=True)

        latest = df.iloc[-1]
        score = int(latest["anomaly_score"])
        verdict = str(latest["verdict"])
        level = "CRITICAL" if "BLOCK" in verdict.upper() else "LOW"

        return {
            "threat_level": level,
            "anomaly_score": score,
            "verdict": verdict,
            "process": str(latest["process_name"]),
            "reason": str(latest["reason"])
        }
    except Exception as e:
        print(f"[STATUS ERROR] {e}")
        return {"threat_level": "LOW", "anomaly_score": 0, "verdict": "NORMAL"}