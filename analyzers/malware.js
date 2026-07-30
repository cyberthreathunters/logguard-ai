/**
 * TODO: still a placeholder — flags any line containing "error". Replace
 * with real detection logic before relying on this analyzer for live data.
 */
export function analyze(events, config) {
  const alerts = [];
  for (const e of events) {
    if (e.raw.toLowerCase().includes("error")) {
      alerts.push({ type: "simple_alert", raw: e.raw });
    }
  }
  return alerts;
}
