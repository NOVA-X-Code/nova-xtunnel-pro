const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const config = require('../config');

const db = new Database(config.PANEL_DB_FILE);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS resellers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  data_quota_gb REAL,               -- NULL = unlimited
  max_users INTEGER NOT NULL DEFAULT 10,
  protocols TEXT NOT NULL DEFAULT '[]', -- JSON array of allowed protocol keys
  expiry_date TEXT,                 -- NULL = never expires
  status TEXT NOT NULL DEFAULT 'active', -- active | locked_manual | locked_expired
  consumed_quota_gb REAL NOT NULL DEFAULT 0, -- permanently-counted quota from deleted clients
  created_at TEXT DEFAULT (datetime('now')),
  notes TEXT
);

CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reseller_id INTEGER NOT NULL REFERENCES resellers(id) ON DELETE CASCADE,
  type TEXT NOT NULL,               -- 'ssh' | 'zivpn'
  identifier TEXT NOT NULL,         -- username for ssh, password for zivpn
  protocols TEXT NOT NULL DEFAULT '[]', -- JSON array subset of reseller.protocols (which tunnel types this client may use)
  max_connections INTEGER DEFAULT 1,
  quota_gb REAL,                    -- NULL = unlimited
  expiry_date TEXT,                 -- NULL = never
  status TEXT NOT NULL DEFAULT 'active', -- active | locked_manual | locked_expired | locked_reseller
  deleted INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  deleted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_clients_reseller ON clients(reseller_id);

-- Access Codes & Custom Premium JSON Config System
CREATE TABLE IF NOT EXISTS config_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  protocol TEXT NOT NULL,                -- 'ssh' | 'vless' | 'vmess' | 'trojan' | 'slowdns' | 'udp'
  name TEXT NOT NULL,                    -- ex: "Cloudflare VLESS WS"
  server_ip TEXT NOT NULL,
  server_port INTEGER DEFAULT 22,

  -- 3X-UI Inbound Integration
  xray_inbound_id INTEGER DEFAULT NULL,  -- Inbound ID in 3X-UI (e.g. 1, 2, 3)
  xray_inbound_tag TEXT DEFAULT NULL,    -- Tag name in 3X-UI

  -- Rules & Flags
  is_base_config INTEGER DEFAULT 0,      -- 1 = Included in base JSON by default
  is_customizable INTEGER DEFAULT 1,     -- 1 = Re-generated with unique premium credentials for Access Codes
  is_quota_counted INTEGER DEFAULT 1,    -- 1 = Counted against reseller quota, 0 = Unlimited/Free for reseller
  is_global_premium INTEGER DEFAULT 0,   -- 1 = Forced on ALL premium access codes for all resellers
  max_data_gb REAL DEFAULT 0,            -- 0 = Unlimited / Uses global access code limit

  payload TEXT,
  sni TEXT,
  path TEXT,
  default_user TEXT,
  default_pass TEXT
);

CREATE TABLE IF NOT EXISTS access_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reseller_id INTEGER REFERENCES resellers(id) ON DELETE SET NULL,
  code TEXT UNIQUE NOT NULL,             -- ex: "NOVA-98A2-33F1"
  client_reference TEXT DEFAULT '',      -- Phone number or client name (e.g. "+225 07080910")
  max_data_gb REAL DEFAULT 10.0,         -- Max data limit in GB (0 = unlimited)
  consumed_data_gb REAL DEFAULT 0.0,     -- Consumed data in GB
  max_devices INTEGER DEFAULT 1,
  expiry_date TEXT,                      -- Expiration date YYYY-MM-DD
  allowed_hwids TEXT DEFAULT '',         -- Bound HWID(s)
  status TEXT DEFAULT 'active',          -- 'active' | 'expired' | 'depleted' | 'locked'
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_access_codes_code ON access_codes(code);

CREATE TABLE IF NOT EXISTS code_credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  access_code_id INTEGER NOT NULL REFERENCES access_codes(id) ON DELETE CASCADE,
  config_template_id INTEGER NOT NULL REFERENCES config_templates(id) ON DELETE CASCADE,

  xray_inbound_id INTEGER DEFAULT NULL,
  client_uuid_or_user TEXT NOT NULL,     -- Generated unique UUID or SSH user
  client_password TEXT DEFAULT NULL,     -- Generated unique SSH password
  client_email_tag TEXT NOT NULL,        -- 3X-UI client email identifier
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS broadcast_notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  url TEXT DEFAULT '',
  is_active INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL,     -- 'admin' | 'reseller' | 'system'
  actor_name TEXT NOT NULL,
  action TEXT NOT NULL,         -- short machine-friendly code
  message TEXT NOT NULL,        -- human-readable description
  reseller_id INTEGER,          -- for scoping "my activity" views, NULL for admin-only actions
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_reseller ON audit_log(reseller_id);
`);

// Migrations / ALTER TABLE statements (outside db.exec SQL string):
try { db.exec('ALTER TABLE config_templates ADD COLUMN is_global_premium INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE config_templates ADD COLUMN max_data_gb REAL DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE config_templates ADD COLUMN info TEXT DEFAULT ""'); } catch (e) {}
try { db.exec('ALTER TABLE config_templates ADD COLUMN flag TEXT DEFAULT "fr"'); } catch (e) {}
try { db.exec('ALTER TABLE config_templates ADD COLUMN proxy_ip TEXT DEFAULT ""'); } catch (e) {}
try { db.exec('ALTER TABLE config_templates ADD COLUMN proxy_port INTEGER DEFAULT 8080'); } catch (e) {}
try { db.exec('ALTER TABLE config_templates ADD COLUMN v2ray_link TEXT DEFAULT ""'); } catch (e) {}
try { db.exec('ALTER TABLE config_templates ADD COLUMN public_key TEXT DEFAULT ""'); } catch (e) {}
try { db.exec('ALTER TABLE config_templates ADD COLUMN nameserver TEXT DEFAULT ""'); } catch (e) {}
try { db.exec('ALTER TABLE config_templates ADD COLUMN dns_server TEXT DEFAULT "8.8.8.8"'); } catch (e) {}
try { db.exec('ALTER TABLE access_codes ADD COLUMN client_reference TEXT DEFAULT ""'); } catch (e) {}
try { db.exec('ALTER TABLE access_codes ADD COLUMN expiry_days INTEGER DEFAULT 30'); } catch (e) {}
try { db.exec('ALTER TABLE access_codes ADD COLUMN activated_at TEXT DEFAULT NULL'); } catch (e) {}

try {
  db.exec('ALTER TABLE clients ADD COLUMN usage_at_deletion_gb REAL');
} catch (e) {
  if (!/duplicate column/i.test(e.message)) throw e;
}

try {
  db.exec('ALTER TABLE resellers ADD COLUMN quota_reset_offset_gb REAL DEFAULT 0');
} catch (e) {
  if (!/duplicate column/i.test(e.message)) throw e;
}

// Bootstrap a default admin account on first run only.
const adminCount = db.prepare('SELECT COUNT(*) AS c FROM admins').get().c;
if (adminCount === 0) {
  const defaultUser = process.env.DEFAULT_ADMIN_USER || 'admin';
  const defaultPass = process.env.DEFAULT_ADMIN_PASS || 'ChangeMe123!';
  const hash = bcrypt.hashSync(defaultPass, 10);
  db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)').run(defaultUser, hash);
  console.log('======================================================');
  console.log(' NOVA XTUNNEL - default admin account created:');
  console.log('   username:', defaultUser);
  console.log('   password:', defaultPass);
  console.log(' CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN.');
  console.log('======================================================');
}

module.exports = db;
