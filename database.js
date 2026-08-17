import { createClient } from "@libsql/client";
import crypto from "crypto";

export const db = createClient({
  url: process.env.TURSO_DATABASE_URL || "file:local.db",
  authToken: process.env.TURSO_AUTH_TOKEN || undefined,
});

export async function initDb() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hostname TEXT,
      device_token TEXT UNIQUE NOT NULL,
      enrolled_at TEXT DEFAULT CURRENT_TIMESTAMP,
      last_seen_at TEXT
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id INTEGER REFERENCES devices(id),
      type TEXT,
      severity TEXT,
      detail TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS install_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // NEW: raw log storage - every event the agent sends, not just alerts.
  // This is what makes search possible, instead of only seeing events
  // that happened to match a pre-written detection rule.
  await db.execute(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id INTEGER REFERENCES devices(id),
      type TEXT,
      event_id INTEGER,
      account TEXT,
      src_ip TEXT,
      raw TEXT,
      event_timestamp TEXT,
      received_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Indexes matter here - without them, every search does a full table
  // scan, which gets slow fast once you're logging every raw event
  // instead of just alerts.
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_logs_device ON logs(device_id)`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(type)`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(event_timestamp)`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_logs_account ON logs(account)`);
}

export async function generateInstallCode() {
  const code = crypto.randomBytes(4).toString("hex");
  await db.execute({
    sql: "INSERT INTO install_codes (code) VALUES (?)",
    args: [code],
  });
  return code;
}

export function generateDeviceToken() {
  return crypto.randomBytes(32).toString("hex");
}
