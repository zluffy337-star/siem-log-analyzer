import pandas as pd
import sqlite3
import os

# Get the directory of the current script
base_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(base_dir, "security_logs.csv")
db_path = os.path.join(base_dir, "siem.db")

# Read CSV, skip comment lines and blank lines
df = pd.read_csv(csv_path, comment='#', skip_blank_lines=True)
conn = sqlite3.connect(db_path)
df.to_sql("logs", conn, if_exists="replace", index=False)
print("Logs ingested successfully")
