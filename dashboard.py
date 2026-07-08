"""
dashboard.py
------------
Streamlit dashboard to visually demo the PAM anomaly detection pipeline.
Run with: streamlit run dashboard.py

Shows:
  - Overview metrics (sessions analyzed, flagged, risk distribution)
  - A table of flagged sessions with AI-generated triage notes
  - Drill-down into any single flagged session
"""

import pandas as pd
import streamlit as st
import plotly.express as px
import os

st.set_page_config(page_title="PAM Anomaly Detection Dashboard", layout="wide")

st.title("AI-Powered Privileged Access Anomaly Detection")
st.caption(
    "Proof-of-concept demonstrating anomaly detection + AI triage principles "
    "used in PAM / UEBA platforms. Built on synthetic session data."
)

DATA_DIR = os.path.dirname(os.path.abspath(__file__))


@st.cache_data
def load_data():
    all_sessions = pd.read_csv(os.path.join(DATA_DIR, "all_sessions_scored.csv"))
    triaged_path = os.path.join(DATA_DIR, "triaged_sessions.csv")
    if os.path.exists(triaged_path):
        triaged = pd.read_csv(triaged_path)
    else:
        triaged = None
    return all_sessions, triaged


try:
    all_sessions, triaged = load_data()
except FileNotFoundError:
    st.error(
        "No data found. Run these first in your terminal:\n\n"
        "1. python generate_logs.py\n"
        "2. python detect_anomalies.py\n"
        "3. python ai_triage.py   (requires free GROQ_API_KEY)"
    )
    st.stop()

# ---- Top metrics ----
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Sessions Analyzed", len(all_sessions))
col2.metric("Flagged as Anomalous", int(all_sessions["is_anomaly"].sum()))
col3.metric("Unique Users", all_sessions["user"].nunique())
col4.metric(
    "Avg Risk Score (flagged)",
    f"{all_sessions[all_sessions['is_anomaly']]['risk_score'].mean():.1f}"
    if all_sessions["is_anomaly"].sum() > 0 else "N/A"
)

st.divider()

# ---- Risk score distribution ----
left, right = st.columns([2, 1])
with left:
    st.subheader("Risk Score Distribution")
    fig = px.histogram(
        all_sessions, x="risk_score", color="is_anomaly",
        nbins=40, color_discrete_map={True: "#e74c3c", False: "#3498db"},
        labels={"is_anomaly": "Flagged as Anomaly"},
    )
    st.plotly_chart(fig, width='stretch')

with right:
    st.subheader("Flags by User")
    flagged_by_user = (
        all_sessions[all_sessions["is_anomaly"]]["user"]
        .value_counts()
        .reset_index()
    )
    flagged_by_user.columns = ["user", "flagged_sessions"]
    st.dataframe(flagged_by_user, width='stretch', hide_index=True)

st.divider()

# ---- Flagged sessions table ----
st.subheader("Flagged Sessions — AI Triage")

if triaged is not None:
    display_cols = [
        "session_id", "user", "timestamp", "source_city", "source_country",
        "resource_accessed", "risk_score", "explanation",
        "mitre_technique", "recommended_action",
    ]
    display_cols = [c for c in display_cols if c in triaged.columns]
    sorted_triaged = triaged.sort_values("risk_score", ascending=False)
    st.dataframe(sorted_triaged[display_cols], width='stretch', hide_index=True)

    st.subheader("Drill Down into a Session")
    session_ids = sorted_triaged["session_id"].tolist()
    selected = st.selectbox("Select a flagged session:", session_ids)
    row = sorted_triaged[sorted_triaged["session_id"] == selected].iloc[0]

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"**User:** {row['user']}")
        st.markdown(f"**Timestamp:** {row['timestamp']}")
        st.markdown(f"**Location:** {row['source_city']}, {row['source_country']}")
        st.markdown(f"**Resource:** {row['resource_accessed']}")
        st.markdown(f"**Session Duration:** {row['session_duration_min']} min")
        st.markdown(f"**Commands Run:** {row['commands_run']}")
        st.markdown(f"**Privilege Escalations:** {row['privilege_escalations']}")
        st.markdown(f"**Risk Score:** :red[{row['risk_score']}/100]")
    with c2:
        st.info(f"**AI Explanation:**\n\n{row['explanation']}")
        st.warning(f"**MITRE ATT&CK Technique:** {row['mitre_technique']}")
        st.success(f"**Recommended Action:** {row['recommended_action']}")
else:
    st.warning(
        "AI triage notes not found. Run `python ai_triage.py` "
        "(requires a free Groq API key) to generate them, then refresh this page."
    )
    flagged_only = all_sessions[all_sessions["is_anomaly"]].sort_values(
        "risk_score", ascending=False)
    st.dataframe(flagged_only, width='stretch', hide_index=True)
