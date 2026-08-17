import express from "express";
import { db } from "./database.js";
import { verifyToken } from "./security.js";

export const router = express.Router();

const MAX_LIMIT = 500;
const DEFAULT_LIMIT = 100;

// ---------------- SEARCH ----------------
// GET /logs/search?device_id=1&q=chira&type=ssh&account=SYSTEM&from=...&to=...&limit=100&offset=0
router.get("/logs/search", verifyToken, async (req, res) => {
  const {
    device_id,
    q,
    type,
    account,
    src_ip,
    event_id,
    from,
    to,
    limit,
    offset,
  } = req.query;

  const clauses = [];
  const args = [];

  if (device_id) {
    clauses.push("device_id = ?");
    args.push(device_id);
  }
  if (type) {
    clauses.push("type = ?");
    args.push(type);
  }
  if (account) {
    clauses.push("account = ?");
    args.push(account);
  }
  if (src_ip) {
    clauses.push("src_ip = ?");
    args.push(src_ip);
  }
  if (event_id) {
    clauses.push("event_id = ?");
    args.push(event_id);
  }
  if (from) {
    clauses.push("event_timestamp >= ?");
    args.push(from);
  }
  if (to) {
    clauses.push("event_timestamp <= ?");
    args.push(to);
  }
  if (q) {
    // Free-text search across the raw event string - the closest
    // equivalent here to Splunk's basic keyword search.
    clauses.push("raw LIKE ?");
    args.push(`%${q}%`);
  }

  const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
  const safeLimit = Math.min(Number(limit) || DEFAULT_LIMIT, MAX_LIMIT);
  const safeOffset = Number(offset) || 0;

  const result = await db.execute({
    sql: `SELECT * FROM logs ${whereSql} ORDER BY received_at DESC LIMIT ? OFFSET ?`,
    args: [...args, safeLimit, safeOffset],
  });

  const countResult = await db.execute({
    sql: `SELECT COUNT(*) as total FROM logs ${whereSql}`,
    args,
  });

  res.json({
    logs: result.rows,
    total: Number(countResult.rows[0].total),
    limit: safeLimit,
    offset: safeOffset,
  });
});

// ---------------- STATS (counts by type, for a quick breakdown view) ----------------
router.get("/logs/stats", verifyToken, async (req, res) => {
  const { device_id } = req.query;

  const clauses = [];
  const args = [];
  if (device_id) {
    clauses.push("device_id = ?");
    args.push(device_id);
  }
  const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";

  const result = await db.execute({
    sql: `SELECT type, COUNT(*) as count FROM logs ${whereSql} GROUP BY type ORDER BY count DESC`,
    args,
  });

  res.json({ stats: result.rows.map((r) => ({ type: r.type, count: Number(r.count) })) });
});
