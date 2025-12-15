import sqlite3
import datetime

DB_NAME = "webscanner.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Create Targets Table
    c.execute('''CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    added_at TEXT NOT NULL
                )''')
                
    # Create Reports Table
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    date TEXT NOT NULL,
                    vuln_count INTEGER,
                    data TEXT
                )''')
    
    # Create Settings Table
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )''')

    # Initialize default settings if empty
    c.execute("SELECT count(*) FROM settings")
    if c.fetchone()[0] == 0:
        default_settings = {
            "dark_mode": "true",
            "auto_report": "true",
            "proxy": "",
            "scan_timeout": "10"
        }
        for k, v in default_settings.items():
            c.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (k, v))
    
    conn.commit()
    conn.close()

def add_target(url):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        added_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO targets (url, added_at) VALUES (?, ?)", (url, added_at))
        conn.commit()
        last_id = c.lastrowid
        conn.close()
        return {"id": last_id, "url": url, "addedAt": added_at}
    except sqlite3.IntegrityError:
        return None  # Duplicate
    except Exception as e:
        print(e)
        return None

def get_targets():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM targets ORDER BY id DESC")
    rows = c.fetchall()
    targets = [{"id": row["id"], "url": row["url"], "addedAt": row["added_at"]} for row in rows]
    conn.close()
    return targets

def delete_target(target_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM targets WHERE id = ?", (target_id,))
    conn.commit()
    conn.close()

def clean_targets():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM targets")
    conn.commit()
    conn.close()

def add_report(url, vuln_count, data_json):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO reports (url, date, vuln_count, data) VALUES (?, ?, ?, ?)", 
              (url, date_str, vuln_count, data_json))
    conn.commit()
    last_id = c.lastrowid
    conn.close()
    return {"id": last_id, "url": url, "date": date_str, "vulnCheck": vuln_count}

def get_reports():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, url, date, vuln_count FROM reports ORDER BY id DESC")
    rows = c.fetchall()
    reports = [{"id": row["id"], "url": row["url"], "date": row["date"], "vulnCheck": row["vuln_count"]} for row in rows]
    conn.close()
    return reports

def get_report_detail(report_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM reports WHERE id = ?", (report_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "id": row["id"],
            "url": row["url"],
            "date": row["date"],
            "vulnCheck": row["vuln_count"],
            "data": row["data"]  # This should be JSON string
        }
    return None

def get_settings():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM settings")
    rows = c.fetchall()
    conn.close()
    settings = {row['key']: row['value'] for row in rows}
    return settings

def update_setting(key, value):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()
    return {key: value}

# Initialize on import
init_db()
