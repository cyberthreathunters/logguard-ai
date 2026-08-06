/**
 * Polls the Windows Event Log every POLL_INTERVAL_MS using PowerShell's
 * Get-WinEvent, adapts new events, batches them, and POSTs to the backend.
 *
 * This replaces Python's win32evtlog.EvtSubscribe (true push) with polling
 * (near-real-time). Given we already batch on a similar interval, the
 * end-to-end delay is comparable either way.
 */

import { execFile } from "child_process";
import axios from "axios";
import { adaptEvent } from "./event_adapter.js";
import { loadConfig } from "./config.js";

const WATCHED_CHANNELS = [
  "Security", // covers both logon events AND firewall drops (5152/5157) if WFP auditing is enabled - see SETUP.md
  "System",
  "Microsoft-Windows-Windows Defender/Operational",
];
const POLL_INTERVAL_MS = 15_000;

// Tracks the last-seen timestamp per channel so we only fetch new events
const lastSeen = {};
for (const channel of WATCHED_CHANNELS) {
  lastSeen[channel] = new Date().toISOString();
}

function fetchNewEvents(channel, sinceIso) {
  return new Promise((resolve, reject) => {
    // Get-WinEvent's .Properties collection only gives raw values, not
    // field names - .ToXml() gives the full rendered XML instead, which
    // preserves named <Data Name="..."> fields (matches how the Python
    // agent's EvtRender-to-XML worked).
    const script = `
      $events = Get-WinEvent -FilterHashtable @{ LogName='${channel}'; StartTime='${sinceIso}' } -ErrorAction SilentlyContinue
      $events | ForEach-Object { $_.ToXml() } | ConvertTo-Json -Depth 2
    `;

    execFile(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { maxBuffer: 1024 * 1024 * 20 },
      (error, stdout) => {
        if (error) return reject(error);
        if (!stdout || !stdout.trim()) return resolve([]);

        try {
          const parsed = JSON.parse(stdout);
          resolve(Array.isArray(parsed) ? parsed : [parsed]);
        } catch (parseErr) {
          reject(parseErr);
        }
      }
    );
  });
}

async function pollOnce(config) {
  const batch = [];

  for (const channel of WATCHED_CHANNELS) {
    try {
      const events = await fetchNewEvents(channel, lastSeen[channel]);
      for (const rawEvent of events) {
        batch.push(adaptEvent(rawEvent, channel));
      }
      if (events.length > 0) {
        lastSeen[channel] = new Date().toISOString();
      }
    } catch (err) {
      console.error(`[agent] failed to poll channel ${channel}:`, err.message);
    }
  }

  if (batch.length === 0) return;

  try {
    const response = await axios.post(
      `${config.backend_url}/devices/events`,
      { events: batch },
      { headers: { Authorization: `Bearer ${config.device_token}` } }
    );
    if (response.data.alerts_raised) {
      console.log(`[agent] ${response.data.alerts_raised} alert(s) raised from this batch`);
    }
  } catch (err) {
    console.error(`[agent] failed to send batch of ${batch.length} events:`, err.message);
  }
}

function start() {
  const config = loadConfig();
  console.log(`[agent] polling ${WATCHED_CHANNELS.join(", ")} every ${POLL_INTERVAL_MS / 1000}s`);
  setInterval(() => pollOnce(config), POLL_INTERVAL_MS);
}

start();
