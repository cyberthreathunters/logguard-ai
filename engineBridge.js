import * as ssh from "./analyzers/ssh.js";
import * as firewall from "./analyzers/firewall.js";
import * as ids from "./analyzers/ids.js";
import * as malware from "./analyzers/malware.js";
import * as web from "./analyzers/web.js";
import * as system from "./analyzers/system.js";
import * as ml from "./analyzers/ml.js";

const DEFAULT_CONFIG = {
  ssh: { bruteforce_threshold: 5, suspicious_hours: { start: 0, end: 6 } },
  firewall: { portscan_threshold: 10, large_outbound_threshold: 1_000_000 },
  ids: { enabled: true },
  malware: { enabled: true },
  web: { enabled: true },
  system: { enabled: true },
  ml: { contamination: 0.1 },
};

const ANALYZERS = {
  ssh: ssh.analyze,
  firewall: firewall.analyze,
  ids: ids.analyze,
  malware: malware.analyze,
  web: web.analyze,
  system: system.analyze,
  ml: ml.analyze,
};

export function runAnalyzers(events, config = DEFAULT_CONFIG) {
  const grouped = {};
  for (const event of events) {
    const type = event.type || "unknown";
    if (!grouped[type]) grouped[type] = [];
    grouped[type].push(event);
  }

  const results = {};
  for (const [type, typeEvents] of Object.entries(grouped)) {
    const analyzer = ANALYZERS[type];
    if (!analyzer) continue;
    results[type] = analyzer(typeEvents, config[type] || {});
  }

  return results;
}
