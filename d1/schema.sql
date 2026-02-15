CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  pass_salt TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved')) DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  approved_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limit (
  ip TEXT NOT NULL,
  action TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (ip, action, window_start)
);

CREATE TABLE IF NOT EXISTS login_lockouts (
  email TEXT PRIMARY KEY,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS denied_users (
  email TEXT PRIMARY KEY,
  reason TEXT,
  denied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_status_created
  ON users (status, created_at);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
  ON sessions (expires_at);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
  ON sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_login_lockouts_until
  ON login_lockouts (locked_until);

CREATE INDEX IF NOT EXISTS idx_denied_users_denied_at
  ON denied_users (denied_at);

-- Maths question bank tables.

CREATE TABLE IF NOT EXISTS maths_files (
  id TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('past_paper', 'mark_scheme', 'datasheet')),
  year INTEGER,
  paper_number INTEGER,
  calculator_allowed INTEGER,
  session TEXT,
  tokens_json TEXT,
  sha256 TEXT,
  page_count INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_maths_files_type_year_paper
  ON maths_files (type, year, paper_number);

CREATE TABLE IF NOT EXISTS maths_pages (
  id TEXT PRIMARY KEY,
  file_id TEXT NOT NULL,
  page_index INTEGER NOT NULL,
  width_pt REAL NOT NULL,
  height_pt REAL NOT NULL,
  render_dpi INTEGER NOT NULL,
  storage_kind TEXT NOT NULL DEFAULT 'public' CHECK (storage_kind IN ('public', 'r2')),
  storage_key TEXT NOT NULL,
  thumb_key TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (file_id) REFERENCES maths_files(id) ON DELETE CASCADE,
  UNIQUE (file_id, page_index)
);

CREATE INDEX IF NOT EXISTS idx_maths_pages_file_page
  ON maths_pages (file_id, page_index);

CREATE TABLE IF NOT EXISTS maths_questions (
  id TEXT PRIMARY KEY,
  year INTEGER NOT NULL,
  paper_number INTEGER NOT NULL CHECK (paper_number IN (1, 2)),
  q_number INTEGER NOT NULL,
  q_label TEXT NOT NULL,
  topic TEXT,
  topic_confidence REAL,
  text_extracted TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_maths_questions_year_paper_q
  ON maths_questions (year, paper_number, q_number);

CREATE INDEX IF NOT EXISTS idx_maths_questions_topic
  ON maths_questions (topic);

CREATE TABLE IF NOT EXISTS maths_crops (
  id TEXT PRIMARY KEY,
  question_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('question', 'answer', 'thumb')),
  file_id TEXT NOT NULL,
  page_index INTEGER NOT NULL,
  x0 REAL NOT NULL,
  y0 REAL NOT NULL,
  x1 REAL NOT NULL,
  y1 REAL NOT NULL,
  render_dpi INTEGER NOT NULL,
  storage_kind TEXT NOT NULL DEFAULT 'public' CHECK (storage_kind IN ('public', 'r2')),
  storage_key TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'auto' CHECK (status IN ('auto', 'reviewed')),
  updated_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (question_id) REFERENCES maths_questions(id) ON DELETE CASCADE,
  FOREIGN KEY (file_id) REFERENCES maths_files(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_maths_crops_question_kind
  ON maths_crops (question_id, kind);

CREATE INDEX IF NOT EXISTS idx_maths_crops_file_page_kind
  ON maths_crops (file_id, page_index, kind);

CREATE TABLE IF NOT EXISTS maths_datasheets (
  id TEXT PRIMARY KEY,
  year INTEGER NOT NULL,
  paper_number INTEGER NOT NULL CHECK (paper_number IN (1, 2)),
  file_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (file_id) REFERENCES maths_files(id) ON DELETE CASCADE,
  UNIQUE (year, paper_number)
);

CREATE INDEX IF NOT EXISTS idx_maths_datasheets_year_paper
  ON maths_datasheets (year, paper_number);

CREATE TABLE IF NOT EXISTS maths_pipeline_runs (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL CHECK (status IN ('running', 'ok', 'error')),
  scope TEXT,
  log_text TEXT
);

CREATE INDEX IF NOT EXISTS idx_maths_pipeline_runs_started
  ON maths_pipeline_runs (started_at);
