import express from "express";
import { db, generateDeviceToken, generateInstallCode } from "./database.js";
import { runAnalyzers, DEFAULT_CONFIG } from "./engineBridge.js";
import { recordFailure } from "./bruteforceTracker.js";
import { verifyToken } from "./security.js";

export const router = express.Router();

// ---------------- ENROLL ----------------
router.post("/devices/enroll", async (req, res) => {
  const { install_code, hostname } = req.body;

  const codeResult = await db.execute({
    sql: "SELECT * FROM install_codes WHERE code = ? AND used = 0",
    args: [install_code],
  });
  const codeRecord = codeResult.rows[0];

  if (!codeRecord) {
    return res.status(401).json({ error: "Invalid or already-used install code" });
  }

  await db.execute({
    sql: "UPDATE install_codes SET used = 1 WHERE id = ?",
    args: [codeRecord.id],
  });

  const deviceToken = generateDeviceToken();
  const insertResult = await db.execute({
    sql: "INSERT INTO devices (hostname, device_token) VALUES (?, ?)",
    args: [hostname, deviceToken],
  });

  res.json({
    device_id: Number(insertResult.lastInsertRowid),
    device_token: deviceToken,
  });
});

// ---------------- DEVICE AUTH MIDDLEWARE ----------------
async function verifyDevice(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Malformed authorization header" });
  }

  const token = header.replace("Bearer ", "").trim();
  const result = await db.execute({
    sql: "SELECT * FROM devices WHERE device_token = ?",
    args: [token],
  });
  const device = result.rows[0];

  if (!device) {
    return res.status(401).json({ error: "Unknown device token" });
  }

  req.device = device;
  next();
}

// ---------------- INGEST ----------------
router.post("/devices/events", verifyDevice, async (req, res) => {
  const { events } = req.body;
  const device = req.device;

  await db.execute({
    sql: "UPDATE devices SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?",
    args: [device.id],
  });

  // NEW: store every raw event, not just the ones that trigger an alert.
  // This is what search is built on - without this, only pre-detected
  // patterns are ever visible, same limitation as before.
  if (events && events.length > 0) {
    const statements = events.map((e) => ({
      sql: "INSERT INTO logs (device_id, type, event_id, account, src_ip, raw, event_timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
      args: [
        device.id,
        e.type || "unknown",
        e.event_id ?? null,
        e.account ?? null,
        e.src_ip ?? null,
        e.raw ?? "",
        e.timestamp ?? null,
      ],
    }));
    await db.batch(statements, "write");
  }

  const config = {
    ...DEFAULT_CONFIG,
    ssh: { ...DEFAULT_CONFIG.ssh, tracker: { recordFailure }, deviceId: device.id },
  };
  const alertsByType = runAnalyzers(events || [], config);

  const stored = [];
  for (const alerts of Object.values(alertsByType)) {
    for (const alert of alerts) {
      await db.execute({
        sql: "INSERT INTO alerts (device_id, type, severity, detail) VALUES (?, ?, ?, ?)",
        args: [device.id, alert.type, alert.severity || null, JSON.stringify(alert)],
      });
      stored.push(alert);
    }
  }

  res.json({
    device_id: device.id,
    events_received: (events || []).length,
    alerts_raised: stored.length,
    alerts: stored,
  });
});

// ---------------- INSTALL CODE ----------------
router.post("/devices/install-code", verifyToken, async (req, res) => {
  const code = await generateInstallCode();
  res.json({ install_code: code });
});

// ---------------- LIST DEVICES ----------------
router.get("/devices", verifyToken, async (req, res) => {
  const result = await db.execute("SELECT id, hostname, enrolled_at, last_seen_at FROM devices ORDER BY id");
  res.json({ devices: result.rows });
});

// ---------------- LIST ALERTS ----------------
router.get("/devices/:id/alerts", verifyToken, async (req, res) => {
  const result = await db.execute({
    sql: "SELECT * FROM alerts WHERE device_id = ? ORDER BY created_at DESC",
    args: [req.params.id],
  });
  res.json({
    alerts: result.rows.map((a) => ({ ...a, detail: JSON.parse(a.detail) })),
  });
});
