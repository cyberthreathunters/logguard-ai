/**
 * Firewall analyzer: port-scan detection + large-outbound-transfer detection.
 */

export function analyze(events, config) {
  const portscanThreshold = config.portscan_threshold ?? 10;
  const largeOutboundThreshold = config.large_outbound_threshold ?? 1_000_000;

  const alerts = [];
  const droppedPortsBySrc = new Map();

  for (const e of events) {
    const action = (e.action || "").toUpperCase();

    if (action === "DROP" && e.src_ip && e.dst_port != null) {
      if (!droppedPortsBySrc.has(e.src_ip)) droppedPortsBySrc.set(e.src_ip, new Set());
      droppedPortsBySrc.get(e.src_ip).add(e.dst_port);
    }

    if (e.bytes_out != null && e.bytes_out >= largeOutboundThreshold) {
      alerts.push({
        type: "large_outbound_transfer",
        severity: "medium",
        src_ip: e.src_ip ?? null,
        bytes_out: e.bytes_out,
        threshold: largeOutboundThreshold,
        timestamp: e.timestamp ?? null,
        raw: e.raw,
      });
    }
  }

  for (const [srcIp, ports] of droppedPortsBySrc) {
    if (ports.size >= portscanThreshold) {
      alerts.push({
        type: "possible_port_scan",
        severity: "high",
        src_ip: srcIp,
        distinct_ports_dropped: ports.size,
        threshold: portscanThreshold,
        raw: `${ports.size} distinct ports dropped from '${srcIp}' in this batch`,
      });
    }
  }

  return alerts;
}
