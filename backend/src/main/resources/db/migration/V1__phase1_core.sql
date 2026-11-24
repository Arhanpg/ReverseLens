CREATE TABLE targets (
  id UUID PRIMARY KEY, target_type VARCHAR(32) NOT NULL, display_name VARCHAR(200) NOT NULL,
  identifier VARCHAR(512), original_filename VARCHAR(512) NOT NULL, sha256 CHAR(64) NOT NULL,
  size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0), storage_path VARCHAR(2048) NOT NULL,
  authorization_basis VARCHAR(64) NOT NULL, authorization_confirmed BOOLEAN NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_targets_created_at ON targets(created_at DESC);
CREATE INDEX idx_targets_sha256 ON targets(sha256);
CREATE TABLE analysis_runs (
  id UUID PRIMARY KEY, target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  status VARCHAR(24) NOT NULL, selection_mode VARCHAR(32) NOT NULL, selected_engine_ids TEXT NOT NULL,
  input_sha256 CHAR(64) NOT NULL, workspace_path VARCHAR(2048) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ
);
CREATE INDEX idx_analysis_runs_target ON analysis_runs(target_id, created_at DESC);
CREATE TABLE engine_executions (
  id UUID PRIMARY KEY, run_id UUID NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
  engine_id VARCHAR(64) NOT NULL, status VARCHAR(24) NOT NULL, output_directory VARCHAR(2048) NOT NULL,
  tool_version VARCHAR(128), adapter_version VARCHAR(32) NOT NULL DEFAULT '0.1.0',
  exit_code INTEGER, duration_ms BIGINT, output_bytes BIGINT, error_summary VARCHAR(4000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ,
  UNIQUE(run_id, engine_id)
);
CREATE INDEX idx_engine_executions_run ON engine_executions(run_id, created_at);
