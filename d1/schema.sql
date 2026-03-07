CREATE TABLE IF NOT EXISTS countdown_timers (
  id TEXT PRIMARY KEY,
  token TEXT NOT NULL,
  start_at_ms INTEGER,
  deadline_ms INTEGER NOT NULL,
  title_text TEXT,
  display_units TEXT,
  is_public INTEGER NOT NULL DEFAULT 0,
  pass_salt TEXT,
  pass_hash TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_countdown_timers_deadline
  ON countdown_timers (deadline_ms);
