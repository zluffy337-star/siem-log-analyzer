import os
import sys
import sqlite3
import json
import time
import subprocess

import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import pydeck as pdk
from geopy.geocoders import Nominatim

# --- page config ---
st.set_page_config(page_title="SIEM Security Dashboard", layout="wide")

# --- paths & DB ---
base_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(base_dir, "siem.db")
country_cache_path = os.path.join(base_dir, "country_cache.json")
detect_script = os.path.join(base_dir, "detect_threats.py")

# ensure DB file exists (load_logs.py should create it)
if not os.path.exists(db_path):
    st.error("Database not found. Run load_logs.py to ingest logs into siem.db.")
    st.stop()

conn = sqlite3.connect(db_path, check_same_thread=False)

# --- helper: safe read SQL to DataFrame ---
def safe_read_sql(query):
    try:
        return pd.read_sql(query, conn)
    except Exception:
        return pd.DataFrame()

# --- run detection button (in-sidebar) ---
st.sidebar.title("SIEM Controls")
if st.sidebar.button("Run Detection Now", key="run_detection"):
    if os.path.exists(detect_script):
        try:
            proc = subprocess.run([sys.executable, detect_script], capture_output=True, text=True, cwd=base_dir, timeout=120)
            if proc.returncode == 0:
                st.sidebar.success("Detection completed.")
            else:
                st.sidebar.error(f"Detection failed: {proc.returncode}")
            if proc.stdout:
                st.sidebar.text(proc.stdout)
            if proc.stderr:
                st.sidebar.text(proc.stderr)
        except Exception as e:
            st.sidebar.error(f"Error running detection: {e}")
    else:
        st.sidebar.error("detect_threats.py not found.")

# --- load logs ---
df = safe_read_sql("SELECT * FROM logs")
if df.empty:
    st.error("No logs found in DB. Run load_logs.py first.")
    st.stop()

# normalize timestamp
if 'timestamp' in df.columns:
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

# --- sidebar filters ---
log_types = []
if 'event_type' in df.columns:
    log_types = sorted(df['event_type'].dropna().unique().tolist())

selected_log_type = st.sidebar.selectbox("Select Log Type", ["All"] + log_types, key="select_log_type")

# date range filter (unique key)
if 'timestamp' in df.columns and df['timestamp'].notna().any():
    min_ts = df['timestamp'].min().date()
    max_ts = df['timestamp'].max().date()
    start_end = st.sidebar.date_input("Date range", value=(min_ts, max_ts), key="date_range")
    if isinstance(start_end, (list, tuple)) and len(start_end) == 2:
        start, end = start_end
        df = df[(df['timestamp'].dt.date >= start) & (df['timestamp'].dt.date <= end)]

# IP / user quick filters
src_ip_filter = st.sidebar.text_input("Filter by Source IP (contains)", key="src_ip_filter")
user_filter = st.sidebar.text_input("Filter by Username (contains)", key="user_filter")

# apply filters
filtered_df = df.copy()
if selected_log_type != "All":
    filtered_df = filtered_df[filtered_df['event_type'] == selected_log_type]
if src_ip_filter:
    filtered_df = filtered_df[filtered_df['src_ip'].astype(str).str.contains(src_ip_filter, na=False)]
if user_filter:
    filtered_df = filtered_df[filtered_df['username'].astype(str).str.contains(user_filter, na=False)]

# --- Alerts panel ---
st.sidebar.markdown("### Alerts")
alerts_df = safe_read_sql("SELECT id, alert_type, details, detected_at FROM alerts ORDER BY detected_at DESC LIMIT 50")
if not alerts_df.empty:
    for _, r in alerts_df.head(6).iterrows():
        st.sidebar.warning(f"{r['alert_type']} • {r['detected_at']}")
else:
    st.sidebar.info("No alerts detected (run detection).")

# --- main header ---
st.title("🛡️ SIEM Security Dashboard")
st.markdown("Interactive view of security logs, alerts and trends.")

# --- top summary: rate / donut / bar / trend ---
col1, col2, col3 = st.columns([1.2, 1.0, 1.0])

# Log processing gauge (col1)
with col1:
    st.subheader("Log Processing Rate")
    log_rate = len(filtered_df)
    total_logs = len(df) if len(df) > 0 else 1
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=log_rate,
        title={'text': "Filtered Logs"},
        gauge={'axis': {'range': [0, total_logs]},
               'bar': {'color': "#ff4b4b"}}
    ))
    st.plotly_chart(fig_gauge, width="stretch")

# Event types donut (col2)
with col2:
    st.subheader("Top Log Classification")
    if 'event_type' in filtered_df.columns and not filtered_df['event_type'].empty:
        counts = filtered_df['event_type'].value_counts()
        fig, ax = plt.subplots(figsize=(4, 3))
        wedges, texts, autotexts = ax.pie(counts.values, labels=counts.index, autopct='%1.1f%%',
                                          startangle=90, wedgeprops=dict(width=0.4),
                                          colors=plt.cm.Set3.colors)
        ax.axis('equal')
        st.pyplot(fig)
    else:
        st.info("No event_type data")

# Top sources horizontal bar (col3)
with col3:
    st.subheader("Top Log Source")
    if 'src_ip' in filtered_df.columns and not filtered_df['src_ip'].empty:
        top_src = filtered_df['src_ip'].value_counts().head(7)
        fig, ax = plt.subplots(figsize=(4, 3))
        ax.barh(top_src.index.astype(str), top_src.values, color="#ff4b4b")
        ax.invert_yaxis()
        ax.set_xlabel("Count")
        st.pyplot(fig)
    else:
        st.info("No src_ip data")

# Events over time (full width)
st.subheader("Events Over Time")
if 'timestamp' in filtered_df.columns and not filtered_df['timestamp'].isna().all():
    try:
        if selected_log_type == "All" and 'event_type' in filtered_df.columns:
            ts = filtered_df.groupby([pd.Grouper(key='timestamp', freq='h'), 'event_type']).size().unstack(fill_value=0)
        else:
            ts = filtered_df.groupby([pd.Grouper(key='timestamp', freq='h'), 'status']).size().unstack(fill_value=0)
        st.line_chart(ts)
    except Exception:
        st.info("Unable to compute time-series (check timestamp format).")
else:
    st.info("No timestamp data available for trend chart.")

# --- Threat Activity Map ---
st.subheader("Threat Activity Map")
geolocator = Nominatim(user_agent="siem_dashboard")

# load or init cache (UTF-8)
try:
    if os.path.exists(country_cache_path):
        with open(country_cache_path, "r", encoding="utf-8") as fh:
            country_coords = json.load(fh)
    else:
        country_coords = {}
except Exception:
    country_coords = {}

countries = filtered_df['country'].dropna().unique() if 'country' in filtered_df.columns else []
new_cached = False
for country in countries:
    if country in country_coords:
        continue
    try:
        loc = geolocator.geocode(country, timeout=10)
        if loc:
            country_coords[country] = [loc.latitude, loc.longitude]
            new_cached = True
        time.sleep(1)
    except Exception:
        continue

if new_cached:
    try:
        with open(country_cache_path, "w", encoding="utf-8") as fh:
            json.dump(country_coords, fh)
    except Exception:
        pass

map_data = []
for c, coords in country_coords.items():
    cnt = int(filtered_df[filtered_df.get('country') == c].shape[0]) if 'country' in filtered_df.columns else 0
    if cnt > 0:
        map_data.append({'lat': coords[0], 'lon': coords[1], 'country': c, 'count': cnt})

if map_data:
    map_df = pd.DataFrame(map_data)
    st.pydeck_chart(pdk.Deck(
        map_style='mapbox://styles/mapbox/dark-v9',
        initial_view_state=pdk.ViewState(latitude=20, longitude=0, zoom=1),
        layers=[pdk.Layer(
            'ScatterplotLayer',
            data=map_df,
            get_position='[lon, lat]',
            get_color='[255, 75, 75, 160]',
            get_radius='count * 50000',
            pickable=True
        )]
    ))
else:
    st.info("No geolocation data to display on map.")

# --- Details & Alerts tables ---
st.header("Detailed Logs and Detection Results")

st.subheader("🚨 Recent Alerts")
if not alerts_df.empty:
    st.table(alerts_df.head(50))
else:
    st.info("No alerts found. Run detection to generate alerts.")

# useful SQL summaries
st.subheader("Brute Force IPs (failed attempts >= 3)")
bf = safe_read_sql("""
SELECT src_ip, COUNT(*) AS attempts
FROM logs
WHERE status='failed'
GROUP BY src_ip
HAVING attempts >= 3
ORDER BY attempts DESC
LIMIT 50
""")
if not bf.empty:
    st.table(bf)
else:
    st.info("No brute force IPs detected.")

st.subheader("Geo-location Anomalies (users with >1 country)")
geo = safe_read_sql("""
SELECT username, COUNT(DISTINCT country) AS country_count
FROM logs
GROUP BY username
HAVING country_count > 1
ORDER BY country_count DESC
LIMIT 50
""")
if not geo.empty:
    st.table(geo)
else:
    st.info("No geo anomalies detected.")

st.subheader("Recent 'user_added' events")
user_added = safe_read_sql("""
SELECT timestamp, username, src_ip
FROM logs
WHERE event_type='user_added'
ORDER BY timestamp DESC
LIMIT 50
""")
if not user_added.empty:
    st.table(user_added)
else:
    st.info("No recent user_added events.")

st.subheader("All Filtered Logs")
st.dataframe(filtered_df.reset_index(drop=True))

# close DB on script end
conn.close()