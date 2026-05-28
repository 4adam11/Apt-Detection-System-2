-- ============================================================
-- APT Detection System - Database Schema
-- Database: SQLite (apt_detection.db)
-- ============================================================

CREATE TABLE IF NOT EXISTS admins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,           -- SHA-256 hashed
    full_name   TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login  DATETIME
);

CREATE TABLE IF NOT EXISTS network_logs (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp               DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip                  TEXT,
    dst_ip                  TEXT,
    src_port                INTEGER,
    dst_port                INTEGER,
    protocol                TEXT,

    -- Feature columns used by ML model
    duration                REAL,
    packet_count            INTEGER,
    byte_count              INTEGER,
    failed_logins           INTEGER,
    unique_ports            INTEGER,
    dns_requests            INTEGER,
    outbound_connections    INTEGER,
    data_exfil_bytes        INTEGER,
    privilege_escalation    INTEGER,
    lateral_movement        INTEGER,
    c2_beacon_interval      REAL,
    encrypted_traffic_ratio REAL,

    -- ML output
    predicted_label         INTEGER,    -- 0=Normal,1=Recon,2=Compromise,3=Lateral,4=Exfil
    predicted_class         TEXT,
    confidence              REAL,
    is_threat               INTEGER DEFAULT 0,  -- boolean
    mitre_technique         TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id          INTEGER REFERENCES network_logs(id),
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
    severity        TEXT CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    threat_type     TEXT,
    src_ip          TEXT,
    description     TEXT,
    mitre_id        TEXT,
    is_resolved     INTEGER DEFAULT 0,
    resolved_at     DATETIME,
    resolved_by     TEXT
);

CREATE TABLE IF NOT EXISTS model_metrics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    trained_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    accuracy    REAL,
    precision   REAL,
    recall      REAL,
    f1_score    REAL,
    n_estimators INTEGER,
    n_samples   INTEGER,
    model_file  TEXT
);

-- ── Indexes for performance ──────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_logs_timestamp    ON network_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_src_ip       ON network_logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_is_threat    ON network_logs(is_threat);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved   ON alerts(is_resolved);

-- ── Views ────────────────────────────────────────────────────────────────
CREATE VIEW IF NOT EXISTS threat_summary AS
    SELECT
        predicted_class,
        COUNT(*) AS total,
        ROUND(AVG(confidence) * 100, 2) AS avg_confidence
    FROM network_logs
    GROUP BY predicted_class;

CREATE VIEW IF NOT EXISTS unresolved_alerts AS
    SELECT a.*, n.src_ip, n.dst_ip, n.confidence
    FROM alerts a
    JOIN network_logs n ON a.log_id = n.id
    WHERE a.is_resolved = 0
    ORDER BY a.timestamp DESC;
