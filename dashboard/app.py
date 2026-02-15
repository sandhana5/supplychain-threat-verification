import streamlit as st
import requests
import time
import pandas as pd
import os
import plotly.express as px
from datetime import datetime

# ── Page configuration ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="ChainGuard",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── Custom styling ───────────────────────────────────────────────────────────
st.markdown("""
    <style>
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2.5rem;
        max-width: 1400px;
    }
    h1, h2, h3 {
        font-family: 'Segoe UI', system-ui, sans-serif;
        font-weight: 600;
        color: #1e293b;
    }
    [data-testid="stMetricValue"] {
        font-size: 2.2rem !important;
        font-weight: 700;
    }
    [data-testid="stMetricLabel"] {
        font-size: 1.1rem;
        color: #64748b;
    }
    .alert-banner {
        background: #fee2e2;
        color: #991b1b;
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        margin-bottom: 1.5rem;
        border-left: 5px solid #ef4444;
        font-weight: 500;
        display: flex;
        justify-content: space-between;
        align-items: center;
        animation: fadeIn 0.6s;
    }
    .alert-banner.dark {
        background: #7f1d1d;
        color: #fecaca;
        border-left-color: #f87171;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-10px); }
        to   { opacity: 1; transform: translateY(0); }
    }
    .element-container > div > div {
        border-radius: 0.5rem;
        border: 1px solid #e5e7eb;
        background: #ffffff;
        padding: 1.25rem;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
    }
    @media (prefers-color-scheme: dark) {
        body, .stAppViewContainer { background-color: #0f172a; }
        h1, h2, h3, p, div, span, label { color: #e2e8f0 !important; }
        .element-container > div > div { background: #1e293b; border-color: #334155; }
    }
    </style>
""", unsafe_allow_html=True)

# ── Header ───────────────────────────────────────────────────────────────────
st.title("ChainGuard")
st.caption("Endpoint Detection & Response — Hybrid AI and Rule-based Analysis")
st.markdown("Real-time monitoring of endpoint activity and supply-chain attack patterns")

st.divider()

# ── Simulation Controls ──────────────────────────────────────────────────────
st.subheader("Simulation Controls")
st.caption("Inject representative attack patterns for testing")

cols = st.columns(4)
attack_types = [
    ("Kaseya Ransomware", "kaseya"),
    ("Log4j Exploitation", "log4j"),
    ("SolarWinds Backdoor", "solarwinds"),
    ("XZ Utils Backdoor", "xz")
]

for col, (label, key) in zip(cols, attack_types):
    with col:
        if st.button(label, use_container_width=True, type="secondary", key=f"btn_{key}"):
            try:
                r = requests.get(f"http://127.0.0.1:8000/inject/{key}", timeout=5)
                if r.status_code == 200 and r.json().get("status") == "injected":
                    st.session_state["injection_status"] = f"{label} injected"
                else:
                    st.session_state["injection_status"] = "Injection failed"
            except:
                st.session_state["injection_status"] = "Backend unreachable"

if "injection_status" in st.session_state:
    st.caption(st.session_state["injection_status"])
    time.sleep(5)
    del st.session_state["injection_status"]
    st.rerun()

st.divider()

# ── Session state for alerts & history ───────────────────────────────────────
if "latest_status" not in st.session_state:
    st.session_state.latest_status = {
        "threat_level": "Low", "anomaly_score": 0, "verdict": "Normal",
        "process": "—", "reason": "—", "timestamp": datetime.now().isoformat()
    }
if "history" not in st.session_state:
    st.session_state.history = []
if "alert_active" not in st.session_state:
    st.session_state.alert_active = False
if "last_alert_verdict" not in st.session_state:
    st.session_state.last_alert_verdict = None

# ── Alert Notification Banner ────────────────────────────────────────────────
def show_alert():
    if st.session_state.alert_active:
        alert_class = "alert-banner" + (" dark" if st.session_state.get("dark_mode", False) else "")
        st.markdown(f"""
            <div class="{alert_class}">
                <div>
                    <strong>CRITICAL THREAT DETECTED</strong><br>
                    Verdict: {st.session_state.latest_status['verdict']} | 
                    Process: {st.session_state.latest_status['process']} | 
                    Reason: {st.session_state.latest_status['reason']}
                </div>
                <button onclick="parent.document.querySelector('.stButton button[kind=primary]').click()">
                    Dismiss
                </button>
            </div>
        """, unsafe_allow_html=True)

        # JavaScript-free dismiss via button (Streamlit limitation workaround)
        if st.button("Dismiss Alert", type="primary", key="dismiss_alert", use_container_width=False):
            st.session_state.alert_active = False
            st.rerun()

# ── Live update loop ─────────────────────────────────────────────────────────
status_container = st.container(border=True)
timeline_container = st.container(border=True)
log_container = st.container(border=True)

while True:
    try:
        r = requests.get("http://127.0.0.1:8000/current_status", timeout=4)
        if r.status_code == 200:
            status = r.json()
            if "timestamp" not in status:
                status["timestamp"] = datetime.now().isoformat()

            # Detect new BLOCK alert
            current_verdict = status.get("verdict", "Normal")
            if current_verdict == "BLOCK" and st.session_state.last_alert_verdict != "BLOCK":
                st.session_state.alert_active = True
                st.session_state.last_alert_verdict = current_verdict

            # Reset alert if back to NORMAL/ALERT
            if current_verdict != "BLOCK":
                st.session_state.alert_active = False
                st.session_state.last_alert_verdict = current_verdict

            st.session_state.latest_status = status
            st.session_state.history.append(status)
            st.session_state.history = st.session_state.history[-30:]

            # ── Show alert banner if active ──────────────────────────────────
            show_alert()

            # ── Current Status ────────────────────────────────────────────────
            with status_container:
                cols = st.columns([2, 1, 1, 2])
                threat_level = status.get("threat_level", "Low")
                threat_color = {"Critical": "inverse", "Elevated": "normal", "Low": "normal"}.get(threat_level, "normal")

                with cols[0]:
                    st.metric("Threat Level", threat_level, delta_color=threat_color)
                with cols[1]:
                    st.metric("Anomaly Score", f"{int(status.get('anomaly_score', 0))}/100")
                with cols[2]:
                    st.metric("Verdict", status.get("verdict", "Normal"))
                with cols[3]:
                    st.markdown(f"**Process**  \n{status.get('process', '—')}")
                    st.markdown(f"**Reason**  \n{status.get('reason', '—')}")

            # ── Timeline Chart ────────────────────────────────────────────────
            with timeline_container:
                if len(st.session_state.history) >= 2:
                    df_timeline = pd.DataFrame(st.session_state.history)
                    df_timeline["timestamp"] = pd.to_datetime(df_timeline["timestamp"])
                    df_timeline = df_timeline.sort_values("timestamp")

                    color_map = {"BLOCK": "red", "ALERT": "orange", "NORMAL": "green"}

                    fig = px.line(
                        df_timeline,
                        x="timestamp",
                        y="anomaly_score",
                        color="verdict",
                        color_discrete_map=color_map,
                        markers=True,
                        title="Anomaly Score Over Time",
                        labels={"anomaly_score": "Anomaly Score", "timestamp": "Time"}
                    )

                    fig.update_traces(
                        mode="lines+markers",
                        marker=dict(size=10, line=dict(width=2, color="white")),
                        line=dict(width=2.5)
                    )

                    fig.update_layout(
                        xaxis_title="Time",
                        yaxis_title="Anomaly Score (0–100)",
                        height=320,
                        margin=dict(l=40, r=40, t=50, b=40),
                        legend_title_text="Verdict",
                        hovermode="x unified"
                    )

                    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
                else:
                    st.caption("Timeline will appear after at least two events are recorded")

            # ── Recent Logs Table ─────────────────────────────────────────────
            with log_container:
                st.subheader("Recent Activity", divider=True)
                if len(st.session_state.history) > 0:
                    df = pd.DataFrame(st.session_state.history[-8:])
                    df = df[["timestamp", "process", "verdict", "anomaly_score", "reason"]].rename(columns={
                        "process": "Process",
                        "verdict": "Decision",
                        "anomaly_score": "Score",
                        "reason": "Reason"
                    })
                    df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
                    st.dataframe(df, hide_index=True, use_container_width=True)
                else:
                    st.caption("No activity recorded yet")

    except requests.exceptions.RequestException:
        st.caption("Backend connection error — retrying...")
    except Exception:
        st.caption("Error during update — retrying...")

    time.sleep(2)