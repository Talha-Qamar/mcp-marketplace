/**
 * Database migrations for databases created by older builds.
 *
 * database/schema.sql is always the full current schema; these steps only
 * bring an existing marketplace.db up to it. Each runs once and is recorded in
 * schema_migrations. Column additions check the table first, so a migration
 * is a no-op on a fresh database whose tables schema.sql already created
 * with the column.
 */

const MIGRATIONS = [
  {
    id: '001_tool_source',
    up: db => {
      addColumn(db, 'tools', 'source_code', 'TEXT');
      addColumn(db, 'tools', 'source_language', 'TEXT');
    },
  },
  {
    id: '002_scan_record_json',
    up: db => addColumn(db, 'mcs_scan_records', 'record_json', 'TEXT'),
  },
  {
    id: '003_listing_gate',
    up: db => {
      // Existing catalog rows predate the gate: they stay visible as 'legacy'.
      addColumn(db, 'servers', 'listing_status', "TEXT DEFAULT 'legacy'");
      addColumn(db, 'servers', 'source_json', 'TEXT');
      addColumn(db, 'users', 'role', "TEXT DEFAULT 'publisher'");
    },
  },
  {
    id: '004_demo_admin',
    // The seeded security persona reviews flagged submissions in the demo.
    up: db => {
      if (tableExists(db, 'users') && hasColumn(db, 'users', 'role')) {
        db.prepare(`UPDATE users SET role = 'admin' WHERE username = 'dave_sec'`).run();
      }
    },
  },
];

function tableExists(db, table) {
  return !!db.prepare(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?`).get(table);
}

function hasColumn(db, table, column) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === column);
}

function addColumn(db, table, column, type) {
  if (tableExists(db, table) && !hasColumn(db, table, column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
  }
}

/** Apply pending migrations; returns the ids applied in this call. */
function runMigrations(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`);
  const done = new Set(db.prepare(`SELECT id FROM schema_migrations`).all().map(r => r.id));
  const applied = [];
  // A fresh database (no servers table yet) gets its columns from schema.sql;
  // only record migrations once the base tables exist.
  if (!tableExists(db, 'servers')) return applied;
  for (const m of MIGRATIONS) {
    if (done.has(m.id)) continue;
    db.transaction(() => {
      m.up(db);
      db.prepare(`INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)`).run(m.id, new Date().toISOString());
    })();
    applied.push(m.id);
  }
  return applied;
}

module.exports = { runMigrations, MIGRATIONS };
