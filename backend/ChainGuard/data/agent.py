import psutil
import time
import requests
from collections import defaultdict, deque
from datetime import datetime, timedelta

# ================= CONFIG =================
BACKEND_URL = "http://127.0.0.1:8000/analyze"
INTERVAL_SEC = 6
WINDOW_MIN = 5
CONN_THRESHOLD = 3        # Low for demo
COOLDOWN_SEC = 90
# =========================================


conn_history = defaultdict(lambda: deque(maxlen=1000))
last_sent = defaultdict(float)

# ---------- Helpers ----------
def normalize(name: str) -> str:
    name = name.lower().strip()
    name = name.replace(" ", "")
    if not name.endswith(".exe") and "." not in name:
        name += ".exe"
    return name


def count_outbound(pid, minutes=WINDOW_MIN):
    now = datetime.now()
    cutoff = now - timedelta(minutes=minutes)
    recent = [ip for ip, ts in conn_history[pid] if ts >= cutoff]
    return len(set(recent))


def send_to_backend(payload):
    try:
        r = requests.post(BACKEND_URL, json=payload, timeout=5)
        result = r.json()
        print(f"📤 Sent | {payload['process_name']} | Score={result.get('anomaly_score')} | Verdict={result.get('verdict')}")
    except Exception as e:
        print(f"[SEND ERROR] {e}")


# ---------- MAIN LOOP ----------

def main():
    print("🛡️  ChainGuard Agent started")
    print(f"📡 Backend: {BACKEND_URL}")
    print("Press Ctrl+C to stop\n")

    while True:
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    raw_name = proc.info['name']
                    if not raw_name:
                        continue

                    name = normalize(raw_name)

                    # --- Allowlist skip ---
                    if name in ALLOWLIST:
                        continue

                    pid = proc.info['pid']

                    # --- Track network ---
                    try:
                        conns = proc.net_connections(kind='inet')
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        conns = []

                    for c in conns:
                        if c.raddr:
                            conn_history[pid].append((c.raddr.ip, datetime.now()))

                    outbound_5min = count_outbound(pid)

                    # --- Detection logic ---
                    is_risky = name in RISKY_PROCESSES
                    is_suspicious = outbound_5min >= CONN_THRESHOLD

                    if not (is_risky or is_suspicious):
                        continue

                    now = time.time()
                    if now - last_sent[name] < COOLDOWN_SEC:
                        continue

                    last_sent[name] = now

                    print(f"🚨 DETECTED: {name} | outbound_5min={outbound_5min}")

                    payload = {
                        "timestamp": datetime.now().isoformat(),
                        "process_name": name,
                        "outbound_conn_5min": outbound_5min,
                        "src_ip": "192.168.1.100",
                        "dst_ip": "unknown",
                        "file_hash": "unknown",
                        "signature_status": "unknown",
                        "dns_query": "unknown",
                        "log_line": f"Suspicious activity from {name}",
                        "jndi_present": 1 if "java" in name else 0,
                        "entropy": 4.7,
                        "label": "suspicious"
                    }

                    send_to_backend(payload)

                except Exception:
                    continue

            time.sleep(INTERVAL_SEC)

        except KeyboardInterrupt:
            print("\nAgent stopped.")
            break


if __name__ == "__main__":
    main()
