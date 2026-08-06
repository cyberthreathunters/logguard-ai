import { createClient } from "@libsql/client";
import crypto from "crypto";

// TURSO_DATABASE_URL and TURSO_AUTH_TOKEN come from your Turso dashboard.
// Falls back to a local file DB if unset, so this still works for local dev
// without a Turso account.
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
