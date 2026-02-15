# src/preprocessor.py
import pandas as pd
import joblib
import os
import numpy as np  # For append

MODEL_DIR = "models"

le_sig = joblib.load(os.path.join(MODEL_DIR, "le_signature.pkl"))
le_proc = joblib.load(os.path.join(MODEL_DIR, "le_process.pkl"))
le_ip = joblib.load(os.path.join(MODEL_DIR, "le_ip.pkl"))

def preprocess(df):
    df = df.copy()
    df.fillna({"log_line": "", "dns_query": "", "process_name": "unknown",
               "signature_status": "Unknown", "entropy": 4.0,
               "outbound_conn_5min": 0, "jndi_present": 0}, inplace=True)

    # Safe transform: add unseen labels dynamically
    def safe_transform(le, series):
        series = series.astype(str)
        unique_vals = series.unique()
        new_vals = [val for val in unique_vals if val not in le.classes_]
        if new_vals:
            le.classes_ = np.append(le.classes_, new_vals)
        return le.transform(series)

    df['sig_encoded'] = safe_transform(le_sig, df['signature_status'])
    df['proc_encoded'] = safe_transform(le_proc, df['process_name'])
    df['ip_encoded'] = safe_transform(le_ip, df['dst_ip'])

    features = ['outbound_conn_5min', 'sig_encoded', 'proc_encoded',
                'ip_encoded', 'jndi_present', 'entropy']

    return df[features].values, df