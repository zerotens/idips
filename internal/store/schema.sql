PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS upstreams (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL,
    address      TEXT NOT NULL DEFAULT '',
    username     TEXT NOT NULL DEFAULT '',
    password_enc TEXT NOT NULL DEFAULT '',
    wg_config_enc TEXT NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 1,
    priority     INTEGER NOT NULL DEFAULT 0,
    health       TEXT NOT NULL DEFAULT 'unknown',
    last_check   INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL,
    priority           INTEGER NOT NULL DEFAULT 100,
    enabled            INTEGER NOT NULL DEFAULT 1,
    match_domain       TEXT NOT NULL DEFAULT '',
    domain_mode        TEXT NOT NULL DEFAULT 'suffix',
    match_logic        TEXT NOT NULL DEFAULT 'and',
    match_cidr         TEXT NOT NULL DEFAULT '',
    match_geoip        TEXT NOT NULL DEFAULT '',
    match_asn          TEXT NOT NULL DEFAULT '',
    match_client_cidr  TEXT NOT NULL DEFAULT '',
    match_port         TEXT NOT NULL DEFAULT '',
    action             TEXT NOT NULL DEFAULT 'proxy',
    upstream_id        INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority, id);

CREATE TABLE IF NOT EXISTS leases (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fake_ip       TEXT NOT NULL UNIQUE,
    target_domain TEXT NOT NULL,
    target_ips    TEXT NOT NULL DEFAULT '[]',
    client_key    TEXT NOT NULL DEFAULT '',
    expires_at    INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_leases_domain ON leases(target_domain);
CREATE INDEX IF NOT EXISTS idx_leases_expires ON leases(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
