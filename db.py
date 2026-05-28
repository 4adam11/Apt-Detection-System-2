"""
database/db.py
SQLite database manager for APT Detection System
"""

import sqlite3
import hashlib
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'apt_detection.db')
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), 'schema.sql')


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # allows dict-like access
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create tables from schema and seed default admin."""
    conn = get_connection()
    with open(SCHEMA_PATH, 'r') as f:
        conn.executescript(f.read())

    # Seed default admin if not exists
    hashed = hashlib.sha256("apt@1234".encode()).hexdigest()
    conn.execute("""
        INSERT OR IGNORE INTO admins (username, password, full_name)
        VALUES (?, ?, ?)
    """, ("admin", hashed, "System Administrator"))
    conn.commit()
    conn.close()
    print("[DB] Database initialised ✅")


# ── Auth ─────────────────────────────────────────────────────────────────────

def verify_admin(username: str, password: str) -> bool:
    hashed = hashlib.sha256(password.encode()).hexdigest()
    conn = get_connection()
    row = conn.execute(
        "SELECT id FROM admins WHERE username=? AND password=?",
        (username, hashed)
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE admins SET last_login=? WHERE username=?",
            (datetime.now(), username)
        )
        conn.commit()
    conn.close()
    return row is not None


# ── Logs ─────────────────────────────────────────────────────────────────────

def insert_log(data: dict) -> int:
    conn = get_connection()
    cur = conn.execute("""
        INSERT INTO network_logs (
            src_ip, dst_ip, src_port, dst_port, protocol,
            duration, packet_count, byte_count, failed_logins,
            unique_ports, dns_requests, outbound_connections,
            data_exfil_bytes, privilege_escalation, lateral_movement,
            c2_beacon_interval, encrypted_traffic_ratio,
            predicted_label, predicted_class, confidence,
            is_threat, mitre_technique
        ) VALUES (
            :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
            :duration, :packet_count, :byte_count, :failed_logins,
            :unique_ports, :dns_requests, :outbound_connections,
            :data_exfil_bytes, :privilege_escalation, :lateral_movement,
            :c2_beacon_interval, :encrypted_traffic_ratio,
            :predicted_label, :predicted_class, :confidence,
            :is_threat, :mitre_technique
        )
    """, data)
    log_id = cur.lastrowid
    conn.commit()
    conn.close()
    return log_id


def get_recent_logs(limit: int = 50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM network_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    conn = get_connection()
    total     = conn.execute("SELECT COUNT(*) FROM network_logs").fetchone()[0]
    normal    = conn.execute("SELECT COUNT(*) FROM network_logs WHERE is_threat=0").fetchone()[0]
    threats   = conn.execute("SELECT COUNT(*) FROM network_logs WHERE is_threat=1").fetchone()[0]
    critical  = conn.execute(
        "SELECT COUNT(*) FROM network_logs WHERE predicted_label IN (3,4)"
    ).fetchone()[0]
    unresolved = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE is_resolved=0"
    ).fetchone()[0]
    conn.close()
    return {
        "total": total, "normal": normal,
        "threats": threats, "critical": critical,
        "unresolved_alerts": unresolved
    }


def get_threat_distribution():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM threat_summary").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Alerts ───────────────────────────────────────────────────────────────────

SEVERITY_MAP = {0: 'LOW', 1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CRITICAL'}

def insert_alert(log_id: int, threat_type: str, src_ip: str,
                 predicted_label: int, mitre_id: str, description: str):
    conn = get_connection()
    conn.execute("""
        INSERT INTO alerts (log_id, severity, threat_type, src_ip,
                            description, mitre_id)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (log_id, SEVERITY_MAP[predicted_label], threat_type,
          src_ip, description, mitre_id))
    conn.commit()
    conn.close()


def get_alerts(limit: int = 100):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM unresolved_alerts LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def resolve_alert(alert_id: int, admin: str):
    conn = get_connection()
    conn.execute("""
        UPDATE alerts SET is_resolved=1, resolved_at=?, resolved_by=?
        WHERE id=?
    """, (datetime.now(), admin, alert_id))
    conn.commit()
    conn.close()


# ── Model Metrics ─────────────────────────────────────────────────────────────

def save_model_metrics(metrics: dict):
    conn = get_connection()
    conn.execute("""
        INSERT INTO model_metrics (accuracy, precision, recall, f1_score,
                                   n_estimators, n_samples, model_file)
        VALUES (:accuracy, :precision, :recall, :f1_score,
                :n_estimators, :n_samples, :model_file)
    """, metrics)
    conn.commit()
    conn.close()


def get_latest_metrics():
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM model_metrics ORDER BY trained_at DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return dict(row) if row else {}
