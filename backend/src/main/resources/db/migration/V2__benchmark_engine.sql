CREATE TABLE benchmark_datasets (
  id UUID PRIMARY KEY,
  dataset_key VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(200) NOT NULL,
  version VARCHAR(64) NOT NULL,
  source_type VARCHAR(48) NOT NULL,
  description TEXT,
  platforms TEXT NOT NULL,
  capability_classes TEXT NOT NULL,
  source_repository VARCHAR(2048),
  source_revision VARCHAR(128),
  artifact_manifest_sha256 CHAR(64),
  ground_truth_available BOOLEAN NOT NULL DEFAULT FALSE,
  license_identifier VARCHAR(120) NOT NULL,
  redistribution_status VARCHAR(24) NOT NULL,
  license_notes TEXT,
  maintainer_notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE benchmark_dataset_targets (
  dataset_id UUID NOT NULL REFERENCES benchmark_datasets(id) ON DELETE CASCADE,
  target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  PRIMARY KEY(dataset_id, target_id)
);
CREATE TABLE benchmark_profiles (
  profile_key VARCHAR(128) PRIMARY KEY,
  name VARCHAR(200) NOT NULL,
  platform VARCHAR(32) NOT NULL,
  capability_classes TEXT NOT NULL,
  engine_ids TEXT NOT NULL,
  default_repetitions INTEGER NOT NULL DEFAULT 3 CHECK(default_repetitions BETWEEN 1 AND 50),
  default_concurrency INTEGER NOT NULL DEFAULT 1 CHECK(default_concurrency = 1),
  is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE benchmark_ground_truth (
  id UUID PRIMARY KEY,
  dataset_id UUID NOT NULL REFERENCES benchmark_datasets(id) ON DELETE CASCADE,
  target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  capability_class VARCHAR(100) NOT NULL,
  item_type VARCHAR(48) NOT NULL,
  expected_value VARCHAR(8000) NOT NULL,
  canonical_key VARCHAR(1000) NOT NULL,
  validation_status VARCHAR(24) NOT NULL CHECK(validation_status IN ('unreviewed','reviewed','verified','disputed','not_applicable')),
  source_reference JSONB NOT NULL DEFAULT '{}'::jsonb,
  reviewer VARCHAR(200),
  owasp_mappings TEXT NOT NULL DEFAULT '',
  reviewed_at TIMESTAMPTZ,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_benchmark_ground_truth_scope ON benchmark_ground_truth(dataset_id,target_id,capability_class,validation_status);
CREATE TABLE benchmark_experiments (
  id UUID PRIMARY KEY,
  experiment_key VARCHAR(128) NOT NULL UNIQUE,
  name VARCHAR(200) NOT NULL,
  dataset_id UUID NOT NULL REFERENCES benchmark_datasets(id),
  profile_key VARCHAR(128) NOT NULL REFERENCES benchmark_profiles(profile_key),
  status VARCHAR(24) NOT NULL CHECK(status IN ('queued','running','completed','partial','failed','cancelled')),
  input_manifest_sha256 CHAR(64) NOT NULL,
  methodology_version VARCHAR(32) NOT NULL DEFAULT '1.1.0',
  repetitions INTEGER NOT NULL CHECK(repetitions BETWEEN 1 AND 50),
  concurrency INTEGER NOT NULL CHECK(concurrency = 1),
  cache_policy VARCHAR(32) NOT NULL CHECK(cache_policy IN ('cold_each_run','warm_each_run','mixed','not_controlled')),
  engine_ids TEXT NOT NULL,
  target_ids TEXT NOT NULL,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);
CREATE INDEX idx_benchmark_experiments_created ON benchmark_experiments(created_at DESC);
CREATE TABLE benchmark_attempts (
  id UUID PRIMARY KEY,
  experiment_id UUID NOT NULL REFERENCES benchmark_experiments(id) ON DELETE CASCADE,
  target_id UUID NOT NULL REFERENCES targets(id),
  engine_id VARCHAR(64) NOT NULL,
  repetition INTEGER NOT NULL CHECK(repetition BETWEEN 1 AND 50),
  input_sha256 CHAR(64) NOT NULL,
  status VARCHAR(24) NOT NULL,
  run_id UUID REFERENCES analysis_runs(id) ON DELETE SET NULL,
  execution_id UUID REFERENCES engine_executions(id) ON DELETE SET NULL,
  worker_metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
  output_bytes BIGINT,
  output_file_count INTEGER,
  observation_count INTEGER NOT NULL DEFAULT 0,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  error_summary TEXT,
  UNIQUE(experiment_id,target_id,engine_id,repetition)
);
CREATE INDEX idx_benchmark_attempts_experiment ON benchmark_attempts(experiment_id,status);
CREATE INDEX idx_benchmark_attempt_execution ON benchmark_attempts(execution_id);
CREATE TABLE benchmark_observations (
  id UUID PRIMARY KEY,
  attempt_id UUID NOT NULL REFERENCES benchmark_attempts(id) ON DELETE CASCADE,
  execution_id UUID NOT NULL REFERENCES engine_executions(id) ON DELETE CASCADE,
  capability_class VARCHAR(100) NOT NULL,
  item_type VARCHAR(48) NOT NULL,
  title VARCHAR(300) NOT NULL,
  observed_value VARCHAR(8000) NOT NULL,
  canonical_key VARCHAR(1000) NOT NULL,
  evidence_path VARCHAR(2048) NOT NULL,
  evidence_sha256 CHAR(64) NOT NULL,
  confidence VARCHAR(16) NOT NULL DEFAULT 'unknown',
  attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_benchmark_observations_attempt ON benchmark_observations(attempt_id);
CREATE INDEX idx_benchmark_observations_canonical ON benchmark_observations(canonical_key);
CREATE TABLE benchmark_results (
  id UUID PRIMARY KEY,
  experiment_id UUID NOT NULL REFERENCES benchmark_experiments(id) ON DELETE CASCADE,
  attempt_id UUID NOT NULL UNIQUE REFERENCES benchmark_attempts(id) ON DELETE CASCADE,
  target_id UUID NOT NULL REFERENCES targets(id),
  engine_id VARCHAR(64) NOT NULL,
  tool_version VARCHAR(128),
  adapter_version VARCHAR(64),
  repetition INTEGER NOT NULL,
  status VARCHAR(24) NOT NULL,
  duration_ms BIGINT,
  cpu_time_ms BIGINT,
  peak_rss_bytes BIGINT,
  output_bytes BIGINT,
  output_file_count INTEGER,
  observation_count INTEGER NOT NULL DEFAULT 0,
  ground_truth_count INTEGER,
  true_positive INTEGER,
  false_positive INTEGER,
  false_negative INTEGER,
  precision DOUBLE PRECISION,
  recall DOUBLE PRECISION,
  f1 DOUBLE PRECISION,
  coverage DOUBLE PRECISION,
  duplicate_rate DOUBLE PRECISION,
  evidence_completeness DOUBLE PRECISION,
  matched_items JSONB NOT NULL DEFAULT '[]'::jsonb,
  missed_items JSONB NOT NULL DEFAULT '[]'::jsonb,
  false_positive_items JSONB NOT NULL DEFAULT '[]'::jsonb,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_benchmark_results_experiment ON benchmark_results(experiment_id,engine_id,repetition);
INSERT INTO benchmark_profiles(profile_key,name,platform,capability_classes,engine_ids,default_repetitions,default_concurrency,is_builtin)
VALUES
('android-static-core','Android static core','android',
 'apk_parsing,dex_analysis,dex_to_source,android_resources,manifest,smali,packer_detection,compiler_detection,protector_detection',
 'jadx,apktool,androguard,apkid',3,1,TRUE),
('android-package-metadata','Android package metadata','android',
 'apk_parsing,android_resources,manifest',
 'androguard,apktool',3,1,TRUE),
('android-dex-recovery','Android DEX recovery','android',
 'dex_analysis,dex_to_source,cross_references,call_graph',
 'jadx,androguard',3,1,TRUE),
('android-app-bundle','Android App Bundle inspection','android',
 'aab_processing,split_apk_processing','bundletool',3,1,TRUE);
