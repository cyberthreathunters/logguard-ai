/**
 * Tracks failed-logon counts in a rolling time window, across batches -
 * not just within whatever batch happened to arrive together.
 * In-memory (per server process) - resets on redeploy, same as the rest
 * of this free-tier setup, but persists correctly between agent polls.
 */

const WINDOW_MS = 5 * 60 * 1000; // 5 minutes

const failures = new Map(); // key: "deviceId:kind:value" -> [timestamp, ...]

export function recordFailure(deviceId, kind, value, timestampMs) {
  const key = `${deviceId}:${kind}:${value}`;
  const list = failures.get(key) || [];
  const cutoff = timestampMs - WINDOW_MS;
  const pruned = [...list.filter((t) => t >= cutoff), timestampMs];
  failures.set(key, pruned);
  return pruned.length;
}
