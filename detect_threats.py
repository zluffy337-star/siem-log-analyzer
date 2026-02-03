import sqlite3
import os

# Get the directory of the current script
base_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(base_dir, "siem.db")

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

print("\nBrute Force IPs")
for row in cursor.execute("""
SELECT src_ip, COUNT(*)
FROM logs
WHERE status='failed'
GROUP BY src_ip
HAVING COUNT(*) >= 3
"""):
    print(row)

print("\nUsers logging from multiple countries")
for row in cursor.execute("""
SELECT username, COUNT(DISTINCT country)
FROM logs
GROUP BY username
HAVING COUNT(DISTINCT country) > 1
"""):
    print(row)
