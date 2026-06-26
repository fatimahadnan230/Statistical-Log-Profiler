%%writefile app.py
import streamlit as st
import pandas as pd
import numpy as np
import re
import plotly.express as px
import random

st.set_page_config(page_title="Traffic Profiler", layout="wide")
st.title("📊 Statistical Log Parser & Traffic Profiler")
st.markdown(r"Upload web server logs to instantly isolate traffic anomalies using $\sigma$ thresholds.")

# --- DUMMY DATA GENERATOR (For instant testing) ---
def generate_mock_logs():
    ips = [f"192.168.1.{i}" for i in range(10, 20)]
    methods = ["GET", "POST", "HEAD"]
    urls = ["/index.html", "/about.html", "/api/v1/login", "/dashboard", "/assets/main.css"]
    
    logs = []
    # Generate normal traffic
    for _ in range(100):
        ip = random.choice(ips)
        size = random.randint(200, 5000)
        logs.append(f'{ip} - - [26/Jun/2026:14:22:10 +0000] "{random.choice(methods)} {random.choice(urls)} HTTP/1.1" 200 {size}')
    
    # Inject 2 blatant anomalies
    logs.append('192.168.1.99 - - [26/Jun/2026:14:23:00 +0000] "POST /data-backup HTTP/1.1" 200 8500000') 
    logs.append('192.168.1.88 - - [26/Jun/2026:14:23:15 +0000] "POST /upload-malware HTTP/1.1" 200 9000000') 
    return logs

# --- PROCESSING ENGINE ---
def process_logs(log_lines):
    log_pattern = re.compile(r'(?P<ip>\S+) \S+ \S+ \[(?P<date>.*?)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) (?P<size>\d+)')
    parsed_logs = []
    for line in log_lines:
        match = log_pattern.match(line)
        if match:
            data = match.groupdict()
            data['size'] = int(data['size'])
            parsed_logs.append(data)
            
    df = pd.DataFrame(parsed_logs)
    
    profile = df.groupby('ip').agg(
        request_count=('url', 'count'),
        avg_payload_size=('size', 'mean')
    ).reset_index()
    
    mean_size = np.mean(profile['avg_payload_size'])
    std_size = np.std(profile['avg_payload_size'])
    
    if std_size > 0:
        profile['z_score'] = (profile['avg_payload_size'] - mean_size) / std_size
    else:
        profile['z_score'] = 0
    return profile

# UI Sidebar Controls
st.sidebar.header("Settings")
threshold = st.sidebar.slider("Z-Score Anomaly Threshold (Sigma)", 1.0, 4.0, 2.0, 0.5)

# Input selection
log_source = st.sidebar.radio("Log Source", ["Use Demo Sample Logs", "Upload custom log file"])

if log_source == "Use Demo Sample Logs":
    raw_logs = generate_mock_logs()
else:
    uploaded_file = st.sidebar.file_uploader("Upload raw log (.txt, .log)")
    if uploaded_file is not None:
        raw_logs = [line.decode("utf-8").strip() for line in uploaded_file]
    else:
        raw_logs = []
        st.info("Please upload a file or switch to demo logs.")

if raw_logs:
    profile_df = process_logs(raw_logs)
    anomalies_df = profile_df[profile_df['z_score'] >= threshold]
    
    # --- METRIC CARDS ---
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Unique IPs Tracked", len(profile_df))
    col2.metric("Anomalies Flagged", len(anomalies_df), delta=f"{len(anomalies_df)} Critical Threats", delta_color="inverse")
    col3.metric("Avg Fleet Payload", f"{int(profile_df['avg_payload_size'].mean()):,} bytes")
    
    st.markdown("---")
    
    # --- VISUALIZATION CHART ---
    st.subheader("Traffic Distribution Map")
    profile_df['Is_Anomaly'] = profile_df['z_score'].apply(lambda x: '🚨 Anomaly' if x >= threshold else '✅ Normal')
    
    fig = px.scatter(
        profile_df, 
        x="request_count", 
        y="avg_payload_size", 
        color="Is_Anomaly",
        hover_data=["ip", "z_score"],
        color_discrete_map={'✅ Normal': '#2b5c8f', '🚨 Anomaly': '#ef4444'},
        labels={"request_count": "Request Frequency Count", "avg_payload_size": "Average Payload Size (Bytes)"}
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # --- DATA TABLES ---
    st.subheader("🚨 High-Risk Anomalies Detected")
    if not anomalies_df.empty:
        # Changed st.dataframe to st.table to stop Localtunnel asset errors
        st.table(anomalies_df.sort_values(by="z_score", ascending=False))
    else:
        st.success("No anomalies detected above selected threshold.")
