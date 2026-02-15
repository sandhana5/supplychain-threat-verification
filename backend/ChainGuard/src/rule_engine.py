# src/rule_engine.py
def apply_rules(log):
    score = 0
    alerts = []

    # Log4j / JNDI
    if log.get("jndi_present", 0) == 1:
        score += 100
        alerts.append("JNDI lookup detected – Log4Shell")

    # Kaseya / high outbound (your data has 60–300)
    if log.get("outbound_conn_5min", 0) > 40:
        score += 90
        alerts.append("High outbound connections – possible C2")

    # Unsigned / invalid signature (common in Kaseya)
    sig = str(log.get("signature_status", "")).lower()
    if "unsigned" in sig or "invalid" in sig or "compromised" in sig:
        score += 80
        alerts.append("Unsigned or suspicious signature")

    # High entropy (Kaseya ~7.3–7.8)
    if log.get("entropy", 0) > 6.5:
        score += 70
        alerts.append("High entropy payload – possible backdoor")

    # Suspicious process names from your attack CSVs
    proc = str(log.get("process_name", "")).lower()
    if "agent.exe" in proc or "gcc" in proc or "sshd" in proc or "java.exe" in proc or "solarwinds" in proc:
        score += 60
        alerts.append("Known attack-related process name")

    print(f"[RULES] Total score: {score} | Triggers: {alerts}")

    return score, alerts