# src/decision_engine.py
import pandas as pd
from src.preprocessor import preprocess
from src.ai_engine import get_ai_score
from src.rule_engine import apply_rules
from src.responder import auto_respond

def hybrid_verdict(ai_score, rule_score, rule_alerts):
    combined = max(ai_score, rule_score)

    if combined >= 35 or ai_score >= 25 or rule_score >= 50:
        verdict = "BLOCK"
        reason = f"CRITICAL – AI: {ai_score}/100 | Rules: {rule_score} → {', '.join(rule_alerts) if rule_alerts else 'Strong anomaly'}"
    elif combined >= 15:
        verdict = "ALERT"
        reason = f"Suspicious – AI: {ai_score} | Rules: {rule_score}"
    else:
        verdict = "NORMAL"
        reason = "No threat"

    print(f"[DECISION] AI={ai_score} | Rules={rule_score} | Combined={combined} → {verdict}")
    print(f"[REASON] {reason}")

    return verdict, reason


def final_decision(log_row):
    print(f"[START DETECT] {log_row.get('process_name')} – {log_row.get('label')}")

    try:
        X, _ = preprocess(pd.DataFrame([log_row]))
        ai_score = get_ai_score(X)
        rule_score, rule_alerts = apply_rules(log_row)
        verdict, reason = hybrid_verdict(ai_score, rule_score, rule_alerts)

        if verdict == "BLOCK":
            print("[BLOCK] Calling responder")
            auto_respond(log_row)

        log_row['anomaly_score'] = ai_score
        log_row['verdict'] = verdict
        log_row['reason'] = reason

        print(f"[END DETECT] Verdict: {verdict} | Score: {ai_score}")

        return log_row

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        log_row['verdict'] = "ERROR"
        log_row['reason'] = str(e)
        return log_row