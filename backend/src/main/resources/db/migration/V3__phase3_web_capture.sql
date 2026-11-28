CREATE TABLE web_targets (
  id UUID PRIMARY KEY,
  display_name VARCHAR(200) NOT NULL,
  start_url VARCHAR(2048) NOT NULL,
  authorization_basis VARCHAR(64) NOT NULL,
  authorization_reference VARCHAR(2000) NOT NULL,
  authorization_confirmed BOOLEAN NOT NULL CHECK (authorization_confirmed = TRUE),
  authorization_expires_at TIMESTAMPTZ NOT NULL,
  allowed_hosts JSONB NOT NULL,
  allowed_path_prefixes JSONB NOT NULL,
  allowed_ports JSONB NOT NULL,
  max_requests INTEGER NOT NULL CHECK (max_requests BETWEEN 1 AND 200),
  max_pages INTEGER NOT NULL CHECK (max_pages BETWEEN 1 AND 50),
  max_saved_javascript_bytes INTEGER NOT NULL CHECK (max_saved_javascript_bytes BETWEEN 1024 AND 10485760),
  max_duration_seconds INTEGER NOT NULL CHECK (max_duration_seconds BETWEEN 1 AND 300),
  local_lab BOOLEAN NOT NULL DEFAULT FALSE,
  status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_web_targets_created ON web_targets(created_at DESC);
CREATE INDEX idx_web_targets_expiry ON web_targets(authorization_expires_at);

CREATE TABLE web_capture_runs (
  id UUID PRIMARY KEY,
  web_target_id UUID NOT NULL REFERENCES web_targets(id) ON DELETE RESTRICT,
  status VARCHAR(24) NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled')),
  workspace_path VARCHAR(2048) NOT NULL,
  manifest_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_summary VARCHAR(4000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);
CREATE INDEX idx_web_capture_runs_target ON web_capture_runs(web_target_id, created_at DESC);
CREATE INDEX idx_web_capture_runs_status ON web_capture_runs(status, created_at);
