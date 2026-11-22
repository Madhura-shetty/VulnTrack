CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(10) NOT NULL CHECK (role IN ('admin','viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    asset_code VARCHAR(30) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL,
    asset_type VARCHAR(30) NOT NULL,
    owner VARCHAR(100) NOT NULL,
    host VARCHAR(255) NOT NULL,
    environment VARCHAR(20) NOT NULL CHECK (environment IN ('Production','Staging','Development','Test')),
    criticality VARCHAR(10) NOT NULL CHECK (criticality IN ('Low','Medium','High','Critical')),
    status VARCHAR(20) NOT NULL CHECK (status IN ('Active','Inactive','Decommissioned')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL UNIQUE CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    description TEXT NOT NULL,
    cvss_score NUMERIC(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    severity VARCHAR(10) NOT NULL DEFAULT 'UNKNOWN' CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE','UNKNOWN')),
    affected_products TEXT NOT NULL DEFAULT '',
    published_at TIMESTAMPTZ,
    last_modified_at TIMESTAMPTZ,
    refs JSONB NOT NULL DEFAULT '[]',
    source VARCHAR(10) NOT NULL CHECK (source IN ('nvd','sample','manual')),
    is_kev BOOLEAN NOT NULL DEFAULT FALSE,
    kev_data JSONB,
    analyst_notes TEXT NOT NULL DEFAULT '',
    synced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerabilities(is_kev);
CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published_at DESC);
CREATE TABLE IF NOT EXISTS risk_assessments (
    id SERIAL PRIMARY KEY,
    risk_code VARCHAR(12) GENERATED ALWAYS AS ('RISK-' || lpad(id::text, 4, '0')) STORED,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE RESTRICT,
    likelihood SMALLINT NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact SMALLINT NOT NULL CHECK (impact BETWEEN 1 AND 5),
    risk_score SMALLINT NOT NULL,
    risk_level VARCHAR(10) NOT NULL CHECK (risk_level IN ('Low','Medium','High','Critical')),
    mitigation TEXT NOT NULL DEFAULT '',
    status VARCHAR(20) NOT NULL CHECK (status IN ('Open','In Progress','Mitigated','Accepted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (asset_id, vulnerability_id)
);
CREATE INDEX IF NOT EXISTS idx_risk_asset ON risk_assessments(asset_id);
CREATE INDEX IF NOT EXISTS idx_risk_vuln ON risk_assessments(vulnerability_id);
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(50) NOT NULL,
    action VARCHAR(40) NOT NULL,
    module VARCHAR(30) NOT NULL,
    record_id VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_audit_immutable ON audit_logs;
CREATE TRIGGER trg_audit_immutable BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
CREATE TABLE IF NOT EXISTS api_sync_logs (
    id SERIAL PRIMARY KEY,
    source VARCHAR(20) NOT NULL,
    query TEXT NOT NULL DEFAULT '',
    fetched INTEGER NOT NULL DEFAULT 0,
    inserted INTEGER NOT NULL DEFAULT 0,
    updated INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(10) NOT NULL CHECK (status IN ('success','partial','failed')),
    message TEXT NOT NULL DEFAULT '',
    username VARCHAR(50) NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
