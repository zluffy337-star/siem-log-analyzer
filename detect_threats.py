import os
import sqlite3
import json
import time
from datetime import datetime, timezone

# Get the directory of the current script
base_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(base_dir, "siem.db")

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Ensure alerts table exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT,
    details TEXT,
    detected_at TEXT
)
""")
conn.commit()

def push_alert(alert_type, details):
    detected_at = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        "INSERT INTO alerts (alert_type, details, detected_at) VALUES (?, ?, ?)",
        (alert_type, details, detected_at)
    )
    conn.commit()
    print(f"[ALERT] {alert_type} - {details}")

print("\nBrute Force IPs")
for row in cursor.execute("""
SELECT src_ip, COUNT(*) as attempts
FROM logs
WHERE status='failed'
GROUP BY src_ip
HAVING attempts >= 3
"""):
    print(row)
    push_alert("Brute Force IP", json.dumps({"src_ip": row[0], "attempts": row[1]}))

print("\nUsers logging from multiple countries")
for row in cursor.execute("""
SELECT username, COUNT(DISTINCT country) AS country_count
FROM logs
GROUP BY username
HAVING country_count > 1
"""):
    print(row)
    push_alert("Geo Anomaly", json.dumps({"username": row[0], "country_count": row[1]}))

print("\nCredential stuffing candidates (many distinct usernames from same IP)")
for row in cursor.execute("""
SELECT src_ip, COUNT(DISTINCT username) AS distinct_users, COUNT(*) AS attempts
FROM logs
GROUP BY src_ip
HAVING distinct_users >= 5 OR attempts >= 10
"""):
    print(row)
    push_alert("Credential Stuffing", json.dumps({"src_ip": row[0], "distinct_users": row[1], "attempts": row[2]}))

print("\nRapid country change (same user logging from different countries within 8 hours)")
for row in cursor.execute("""
SELECT DISTINCT l1.username, l1.country AS country1, l2.country AS country2,
       ABS(strftime('%s', l1.timestamp) - strftime('%s', l2.timestamp))/3600.0 AS hours_diff
FROM logs l1
JOIN logs l2 ON l1.username = l2.username
WHERE l1.country <> l2.country
  AND ABS(strftime('%s', l1.timestamp) - strftime('%s', l2.timestamp))/3600.0 <= 8
ORDER BY hours_diff ASC
LIMIT 50
"""):
    print(row)
    push_alert("Rapid Country Change", json.dumps({"username": row[0], "from": row[1], "to": row[2], "hours_diff": row[3]}))

print("\nUnusual successful logins during off-hours (00:00-05:00)")
for row in cursor.execute("""
SELECT username, timestamp, src_ip
FROM logs
WHERE event_type='login' AND status='success'
  AND CAST(strftime('%H', timestamp) AS INTEGER) BETWEEN 0 AND 5
ORDER BY timestamp DESC
LIMIT 50
"""):
    print(row)
    push_alert("Off-hours Successful Login", json.dumps({"username": row[0], "timestamp": row[1], "src_ip": row[2]}))

print("\nPowerShell / Process creation spikes per IP")
for row in cursor.execute("""
SELECT src_ip, event_type, COUNT(*) AS cnt
FROM logs
WHERE event_type IN ('powershell', 'process_creation')
GROUP BY src_ip, event_type
HAVING cnt >= 5
"""):
    print(row)
    push_alert("Process/PowerShell Spike", json.dumps({"src_ip": row[0], "event_type": row[1], "count": row[2]}))

print("\nRecent user added events")
for row in cursor.execute("""
SELECT timestamp, username, src_ip
FROM logs
WHERE event_type='user_added'
ORDER BY timestamp DESC
LIMIT 20
"""):
    print(row)
    push_alert("User Added", json.dumps({"timestamp": row[0], "username": row[1], "src_ip": row[2]}))

print("\nDetection complete. Alerts written to 'alerts' table.")
conn.close()