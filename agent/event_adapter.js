/**
 * Converts a Windows event's raw XML (from EventLogRecord.ToXml() via
 * PowerShell) into the shape the backend analyzers expect.
 *
 * The Security channel carries multiple event types, so routing is done
 * by Event ID, not just by channel name:
 *   4624 / 4625        -> "ssh"      (logon success / failure)
 *   5152 / 5157         -> "firewall" (WFP blocked a packet/connection -
 *                          requires "Filtering Platform Packet Drop" and
 *                          "Filtering Platform Connection" audit policies
 *                          to be enabled; see SETUP.md)
 * The System channel -> "system" (service/shutdown events)
 * The Defender operational channel -> "malware" (threat detections)
 */

const AUTH_EVENT_IDS = new Set([4624, 4625]);
const FIREWALL_BLOCK_EVENT_IDS = new Set([5152, 5157]);

function extractTag(xml, tag) {
  const match = xml.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`));
  return match ? match[1] : null;
}

function extractAttr(xml, tag, attr) {
  const match = xml.match(new RegExp(`<${tag}[^>]*\\s${attr}=['"]([^'"]*)['"]`));
  return match ? match[1] : null;
}

function extractDataByName(xml, name) {
  const match = xml.match(new RegExp(`<Data Name=['"]${name}['"]>([^<]*)</Data>`));
  return match ? match[1] : null;
}

function classify(channel, eventId) {
  if (channel === "Security") {
    if (AUTH_EVENT_IDS.has(eventId)) return "ssh";
    if (FIREWALL_BLOCK_EVENT_IDS.has(eventId)) return "firewall";
    return "unknown";
  }
  if (channel === "System") return "system";
  if (channel === "Microsoft-Windows-Windows Defender/Operational") return "malware";
  return "unknown";
}

export function adaptEvent(xmlString, channel) {
  const eventIdRaw = extractTag(xmlString, "EventID");
  const eventId = eventIdRaw !== null ? Number(eventIdRaw) : null;
  const timestamp = extractAttr(xmlString, "TimeCreated", "SystemTime");
  const eventType = classify(channel, eventId);

  const event = {
    raw: `[${channel}] EventID=${eventId}`,
    type: eventType,
    event_id: eventId,
    account: null,
    src_ip: null,
    timestamp,
  };

  if (eventType === "ssh") {
    const account =
      extractDataByName(xmlString, "TargetUserName") ||
      extractDataByName(xmlString, "SubjectUserName") ||
      null;
    let srcIp = extractDataByName(xmlString, "IpAddress");
    if (srcIp === "-" || srcIp === "") srcIp = null;
    const logonType = extractDataByName(xmlString, "LogonType");

    event.account = account;
    event.src_ip = srcIp;
    event.logon_type = logonType !== null ? Number(logonType) : null;

    const rawParts = [event.raw];
    if (account) rawParts.push(`account=${account}`);
    if (srcIp) rawParts.push(`src_ip=${srcIp}`);
    event.raw = rawParts.join(" ");
  }

  if (eventType === "firewall") {
    const srcIp = extractDataByName(xmlString, "SourceAddress");
    const dstPort = extractDataByName(xmlString, "DestPort");

    event.src_ip = srcIp && srcIp !== "-" ? srcIp : null;
    event.action = "DROP"; // 5152/5157 are, by definition, block events
    event.dst_port = dstPort !== null && dstPort !== "" ? Number(dstPort) : null;
    event.bytes_out = null; // not available from WFP audit events

    const rawParts = [event.raw];
    if (event.src_ip) rawParts.push(`src_ip=${event.src_ip}`);
    if (event.dst_port) rawParts.push(`dst_port=${event.dst_port}`);
    event.raw = rawParts.join(" ");
  }

  if (eventType === "malware") {
    const threatName = extractDataByName(xmlString, "Threat Name");
    const severity = extractDataByName(xmlString, "Severity Name");
    const actionTaken = extractDataByName(xmlString, "Action Name");

    event.threat_name = threatName || null;
    event.severity_name = severity || null;
    event.action_taken = actionTaken || null;

    const rawParts = [event.raw];
    if (event.threat_name) rawParts.push(`threat=${event.threat_name}`);
    event.raw = rawParts.join(" ");
  }

  return event;
}
