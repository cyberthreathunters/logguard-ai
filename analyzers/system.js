/**
 * System analyzer - Windows System channel.
 * Event ID 7034 = a service crashed unexpectedly
 * Event ID 7031 = a service terminated unexpectedly
 * Event ID 6008 = the system shut down unexpectedly (not a clean shutdown)
 */

const SERVICE_CRASH_IDS = new Set([7031, 7034]);
const UNEXPECTED_SHUTDOWN_ID = 6008;

export function analyze(events, config) {
  const alerts = [];

  for (const e of events) {
    if (SERVICE_CRASH_IDS.has(e.event_id)) {
      alerts.push({
        type: "service_crash",
        severity: "medium",
        event_id: e.event_id,
        timestamp: e.timestamp ?? null,
        raw: e.raw,
      });
    }

    if (e.event_id === UNEXPECTED_SHUTDOWN_ID) {
      alerts.push({
        type: "unexpected_shutdown",
        severity: "medium",
        timestamp: e.timestamp ?? null,
        raw: e.raw,
      });
    }
  }

  return alerts;
}
