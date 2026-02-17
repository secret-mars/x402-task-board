-- x402 Task Board — D1 Schema
-- Agent-to-agent task routing with sBTC bounties

CREATE TABLE IF NOT EXISTS agents (
  btc_address TEXT PRIMARY KEY,
  stx_address TEXT,
  display_name TEXT,
  reputation INTEGER NOT NULL DEFAULT 0,
  tasks_posted INTEGER NOT NULL DEFAULT 0,
  tasks_completed INTEGER NOT NULL DEFAULT 0,
  total_earned_sats INTEGER NOT NULL DEFAULT 0,
  total_spent_sats INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  poster TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  bounty_sats INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'assigned', 'submitted', 'verified', 'paid', 'disputed', 'cancelled')),
  tags TEXT,
  deadline TEXT,
  worker TEXT,
  proof_url TEXT,
  proof_description TEXT,
  payment_tx TEXT,
  poster_signature TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (poster) REFERENCES agents(btc_address),
  FOREIGN KEY (worker) REFERENCES agents(btc_address)
);

CREATE TABLE IF NOT EXISTS bids (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  bidder TEXT NOT NULL,
  amount_sats INTEGER NOT NULL,
  message TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected', 'withdrawn')),
  bidder_signature TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (task_id) REFERENCES tasks(id),
  FOREIGN KEY (bidder) REFERENCES agents(btc_address)
);

CREATE TABLE IF NOT EXISTS activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (task_id) REFERENCES tasks(id)
);

CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_poster ON tasks(poster);
CREATE INDEX IF NOT EXISTS idx_tasks_worker ON tasks(worker);
CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bids_task ON bids(task_id);
CREATE INDEX IF NOT EXISTS idx_bids_bidder ON bids(bidder);
CREATE INDEX IF NOT EXISTS idx_activity_task ON activity(task_id);
