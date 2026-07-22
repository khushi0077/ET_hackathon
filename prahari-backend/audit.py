import sqlite3
import hashlib
import json
import os

DB_PATH = "audit.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            event_data TEXT,
            action TEXT,
            prev_hash TEXT,
            hash TEXT
        )
    ''')
    # Insert genesis block only if table is empty
    c.execute("SELECT count(*) FROM audit_log")
    if c.fetchone()[0] == 0:
        c.execute(
            "INSERT INTO audit_log (timestamp, event_data, action, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
            (0.0, "GENESIS", "INIT", "0"*64, "0"*64)
        )
    conn.commit()
    conn.close()

def hash_data(prev_hash, data_str):
    h = hashlib.sha256()
    h.update((prev_hash + data_str).encode('utf-8'))
    return h.hexdigest()

def log_action(timestamp, event_data, action):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
    prev_hash = c.fetchone()[0]
    
    data_str = json.dumps(event_data, sort_keys=True)
    new_hash = hash_data(prev_hash, data_str + action)
    
    c.execute(
        "INSERT INTO audit_log (timestamp, event_data, action, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
        (timestamp, data_str, action, prev_hash, new_hash)
    )
    conn.commit()
    conn.close()
    return new_hash

def verify_chain():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, event_data, action, prev_hash, hash FROM audit_log ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    
    for i in range(1, len(rows)):
        prev_row = rows[i-1]
        curr_row = rows[i]
        
        expected_prev_hash = prev_row[4]
        if curr_row[3] != expected_prev_hash:
            return {"valid": False, "broken_at_id": curr_row[0], "reason": "prev_hash mismatch"}
            
        data_str = curr_row[1]
        action = curr_row[2]
        calc_hash = hash_data(expected_prev_hash, data_str + action)
        if curr_row[4] != calc_hash:
            return {"valid": False, "broken_at_id": curr_row[0], "reason": "hash recalculation mismatch"}
            
    return {"valid": True, "total_records": len(rows)}

def tamper_test():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, event_data FROM audit_log ORDER BY id DESC LIMIT 2")
    res = c.fetchall()
    if len(res) < 2:
        return {"error": "Not enough rows to tamper"}
        
    target_id = res[1][0]
    c.execute("UPDATE audit_log SET event_data = ? WHERE id = ?", ("TAMPERED_DATA", target_id))
    conn.commit()
    conn.close()
    return {"success": True, "tampered_id": target_id}

init_db()
