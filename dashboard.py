import streamlit as st
import sqlite3
import pandas as pd
import os
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from geopy.geocoders import Nominatim
import time
import pydeck as pdk

# Get the directory of the current script
base_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(base_dir, "siem.db")

conn = sqlite3.connect(db_path)

st.title("🛡️ SIEM Security Dashboard")
df = pd.read_sql("SELECT * FROM logs", conn)

# Sidebar filter for log type
log_types = df['event_type'].unique().tolist()
selected_log_type = st.sidebar.selectbox("Select Log Type", ["All"] + log_types)
if selected_log_type != "All":
    filtered_df = df[df['event_type'] == selected_log_type]
else:
    filtered_df = df

# --- Summary Visualizations ---
st.header("Security Event Overview")

# Log Processing Rate Gauge
st.subheader("Log Processing Rate")
log_rate = len(filtered_df)
fig = go.Figure(go.Indicator(
    mode="gauge+number",
    value=log_rate,
    title={'text': "Total Logs"},
    gauge={'axis': {'range': [0, len(df)]}, 'bar': {'color': "#ff4b4b"}}
))
st.plotly_chart(fig, use_container_width=True)

col1, col2 = st.columns(2)
with col1:
    st.subheader("Events Over Time")
    filtered_df['timestamp'] = pd.to_datetime(filtered_df['timestamp'])
    if selected_log_type == "All":
        time_series = filtered_df.groupby([pd.Grouper(key='timestamp', freq='H'), 'event_type']).size().unstack(fill_value=0)
    else:
        time_series = filtered_df.groupby([pd.Grouper(key='timestamp', freq='H'), 'status']).size().unstack(fill_value=0)
    st.line_chart(time_series)

with col2:
    st.subheader("Event Types Distribution")
    event_counts = filtered_df['event_type'].value_counts()
    st.bar_chart(event_counts)

col3, col4 = st.columns(2)
with col3:
    st.subheader("Top Log Source")
    top_sources = filtered_df['src_ip'].value_counts().head(5)
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.barh(top_sources.index, top_sources.values, color="#ff4b4b")
    ax.set_xlabel("Count")
    ax.set_ylabel("Source IP")
    ax.invert_yaxis()
    st.pyplot(fig)

with col4:
    st.subheader("Top Log Classification (Donut)")
    event_type_counts = filtered_df['event_type'].value_counts()
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.pie(event_type_counts.values, labels=event_type_counts.index, autopct='%1.1f%%', 
           startangle=90, wedgeprops=dict(width=0.4), colors=['#ff4b4b', '#ffa500', '#4b9cff', '#50c878'])
    st.pyplot(fig)

# Threat Activity Map
st.subheader("Threat Activity Map")
geolocator = Nominatim(user_agent="siem_dashboard")
country_coords = {}
for country in filtered_df['country'].unique():
    if country not in country_coords:
        try:
            location = geolocator.geocode(country)
            if location:
                country_coords[country] = (location.latitude, location.longitude)
            time.sleep(1)
        except Exception:
            pass

map_data = []
for country, coords in country_coords.items():
    count = len(filtered_df[filtered_df['country'] == country])
    map_data.append({'lat': coords[0], 'lon': coords[1], 'country': country, 'count': count})

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
            get_radius='count * 100000',
            pickable=True
        )]
    ))

# --- Details and Tables ---
st.header("Detailed Logs and Alerts")

st.subheader("🚨 Brute Force IPs")
bf = pd.read_sql("""
SELECT src_ip, COUNT(*) AS attempts
FROM logs
WHERE status='failed'
GROUP BY src_ip
HAVING attempts >= 3
""", conn)
st.table(bf)

st.subheader("🌍 Geo-location Anomalies")
geo = pd.read_sql("""
SELECT username, COUNT(DISTINCT country) AS country_count
FROM logs
GROUP BY username
HAVING country_count > 1
""", conn)
st.table(geo)

st.subheader("All Filtered Logs")
st.dataframe(filtered_df)