/**
 * Web server log analyzer - currently UNWIRED, not just unimplemented.
 *
 * No event source in this pipeline is ever classified as type "web" -
 * check event_adapter.js's classify() function. A laptop endpoint
 * doesn't run a web server by default, so there's no Windows Event Log
 * channel this would naturally map to.
 *
 * This analyzer only becomes relevant if LogGuard AI is later extended
 * to monitor an actual web server (e.g. IIS logs on a server the
 * company runs) - at that point this needs its own event source and
 * adapter classification, similar to how "firewall" and "malware" were
 * wired to their real Windows sources.
 */
export function analyze(events, config) {
  return [];
}
