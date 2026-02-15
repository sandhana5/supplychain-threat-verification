# src/responder.py
import winsound
import datetime
import os

def auto_respond(log_row):
    """
    Simulates real EDR response: alert sound + terminal message + log entry
    """
    # Play Windows alert sound
    winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS)
    
    verdict = log_row.get("verdict", "BLOCK")
    process = log_row.get("process_name", "unknown")
    attack_type = log_row.get("label", "unknown_attack")
    
    print("\n" + "="*60)
    print(f"🚨 CHAIN GUARD ALERT @ {datetime.datetime.now().strftime('%H:%M:%S')}")
    print(f"   VERDICT      : {verdict}")
    print(f"   PROCESS      : {process}")
    print(f"   ATTACK TYPE  : {attack_type}")
    print(f"   ANOMALY SCORE: {log_row.get('anomaly_score', 'N/A')}/100")
    print(f"   REASON       : {log_row.get('reason', 'N/A')}")
    print("   → SIMULATED ACTION: Process terminated + IP blocked")
    print("="*60)
    
    # Log to file
    os.makedirs("logs", exist_ok=True)
    with open("logs/alerts.log", "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().isoformat()
        f.write(f"{timestamp} | {verdict} | {attack_type} | {process} | Score: {log_row.get('anomaly_score')} | {log_row.get('reason')}\n")