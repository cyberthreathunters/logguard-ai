import express from "express";
import { db, generateDeviceToken, generateInstallCode } from "./database.js";
import { runAnalyzers, DEFAULT_CONFIG } from "./engineBridge.js";
import { recordFailure } from "./bruteforceTracker.js";

export const router = express.Router();

// ---------------- ENROLL ----------------
router.post("/devices/enroll", (req, res) => {
  const { install_code, hostname } = req.body;

  const codeRecord = db
    .prepare("SELECT * FROM install_codes WHERE code = ? AND used = 0")
    .get(install_code);

  if (!codeRecord) {
    return res.status(401).json({ error: "Invalid or already-used install code" });
  }

  db.prepare("UPDATE install_codes SET used = 1 WHERE id = ?").run(codeRecord.id);

  const deviceToken = generateDeviceToken();
  const result = db
    .prepare("INSERT INTO devices (hostname, device_token) VALUES (?, ?)")
    .run(hostname, deviceToken);

  res.json({ device_id: result.lastInsertRowid, device_token: deviceToken });
});

// ---------------- DEVICE AUTH MIDDLEWARE ----------------
function verifyDevice(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Malformed authorization header" });
  }

  const token = header.replace("Bearer ", "").trim();
  const device = db.prepare("SELECT * FROM devices WHERE device_token = ?").get(token);

  if (!device) {
    return res.status(401).json({ error: "Unknown device token" });
  }

  req.device = device;
  next();
}

// ---------------- INGEST ----------------
router.post("/devices/events", verifyDevice, (req, res) => {
  const { events } = req.body;
  const device = req.device;

  db.prepare("UPDATE devices SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?").run(device.id);

  const config = {
    ...DEFAULT_CONFIG,
    ssh: { ...DEFAULT_CONFIG.ssh, tracker: { recordFailure }, deviceId: device.id },
  };
  const alertsByType = runAnalyzers(events || [], config);

  const insertAlert = db.prepare(
    "INSERT INTO alerts (device_id, type, severity, detail) VALUES (?, ?, ?, ?)"
  );

  const stored = [];
  for (const alerts of Object.values(alertsByType)) {
    for (const alert of alerts) {
      insertAlert.run(device.id, alert.type, alert.severity || null, JSON.stringify(alert));
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
// TODO: put this behind your human JWT auth (verifyToken) before real use,
// so only a logged-in admin can generate install codes.
router.post("/devices/install-code", (req, res) => {
  const code = generateInstallCode();
  res.json({ install_code: code });
});

// ---------------- LIST ALERTS (handy for testing) ----------------
router.get("/devices/:id/alerts", (req, res) => {
  const alerts = db
    .prepare("SELECT * FROM alerts WHERE device_id = ? ORDER BY created_at DESC")
    .all(req.params.id);
  res.json({ alerts: alerts.map((a) => ({ ...a, detail: JSON.parse(a.detail) })) });
});
