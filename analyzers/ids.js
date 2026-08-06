/**
 * IDS/IPS analyzer - currently UNWIRED, not just unimplemented.
 *
 * No event source in this pipeline is ever classified as type "ids" -
 * check event_adapter.js's classify() function. This function will
 * never receive any events as things stand, regardless of what's
 * written here.
 *
 * Real IDS-style detection (signature matching, known-attack patterns)
 * typically needs a dedicated source like Sysmon or Windows Defender
 * ATP/EDR telemetry - a plain Windows laptop's built-in Event Log
 * doesn't have an equivalent "IDS" channel the way it has Security,
 * System, and Defender channels.
 *
 * The closest real coverage that exists today lives in ssh.js instead
 * (remote_logon_attempt, for LogonType 3/10 - network/RDP attempts).
 */
export function analyze(events, config) {
  return [];
}
