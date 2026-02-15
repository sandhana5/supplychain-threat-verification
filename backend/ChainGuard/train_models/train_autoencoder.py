from google.colab import files
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
import os

# 1. Load the same normal.csv (upload again or it's already there)
# If you closed Colab, upload normal.csv again
try:
    df = pd.read_csv("normal.csv")
except:
    uploaded = files.upload()
    df = pd.read_csv("normal.csv")

print(f"Loaded {len(df):,} normal rows for Autoencoder training")

# 2. Preprocessing – same as Isolation Forest
df.fillna({"process_name": "unknown.exe", "dst_ip": "unknown.com", 
           "signature_status": "Unknown", "entropy": 4.0, "jndi_present": 0}, inplace=True)

le_sig = LabelEncoder().fit(df['signature_status'])
le_proc = LabelEncoder().fit(df['process_name'])
le_ip = LabelEncoder().fit(df['dst_ip'])

df['sig'] = le_sig.transform(df['signature_status'])
df['proc'] = le_proc.transform(df['process_name'])
df['ip'] = le_ip.transform(df['dst_ip'])

features = ['outbound_conn_5min', 'sig', 'proc', 'ip', 'jndi_present', 'entropy']
X = df[features].astype(float).values

# 3. Scale the data (critical for neural networks)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print("Building & training Autoencoder (this takes ~2 minutes)...")

# 4. Autoencoder model – optimized for supply-chain attacks
model = Sequential([
    Dense(64, activation='relu', input_shape=(6,)),
    Dropout(0.1),
    Dense(32, activation='relu'),
    Dense(16, activation='relu'),
    Dense(8, activation='relu'),   # Bottleneck
    Dense(16, activation='relu'),
    Dense(32, activation='relu'),
    Dense(64, activation='relu'),
    Dense(6, activation='linear')   # Reconstruction
])

model.compile(optimizer='adam', loss='mse')
history = model.fit(X_scaled, X_scaled, epochs=30, batch_size=256, 
                    validation_split=0.1, verbose=1)

# 5. Save everything
os.makedirs("models", exist_ok=True)

model.save("models/autoencoder.h5")
joblib.dump(scaler, "models/autoencoder_scaler.pkl")
joblib.dump(le_sig, "models/le_signature.pkl")   # reuse same encoders
joblib.dump(le_proc, "models/le_process.pkl")
joblib.dump(le_ip, "models/le_ip.pkl")

print("AUTOENCODER TRAINED & SAVED!")

# 6. Download the new files
files.download("models/autoencoder.h5")
files.download("models/autoencoder_scaler.pkl")

print("DONE! You now have:")
print("   → isolation_forest.pkl + 3 encoders (from before)")
print("   → autoencoder.h5 + autoencoder_scaler.pkl (new!)")
print("Put ALL these files in your Windows → models/ folder")