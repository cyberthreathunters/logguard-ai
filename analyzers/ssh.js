/**
 * Auth / logon analyzer.
 * Event ID 4625 = failed logon, 4624 = successful logon (Windows Security channel).
 *
 * Brute-force detection uses config.tracker (bruteforceTracker.js) to count
 * failures across batches within a rolling time window - not just within
 * whatever batch happened to arrive together, since the agent's batch
 * boundaries are arbitrary relative to when events actually happen.
 * If no tracker is passed (e.g. in unit tests), falls back to a
 * per-batch-only count.
 */

function hourOf(event) {
  if (!event.timestamp) return null;
  const date = new Date(event.timestamp);
  return isNaN(date) ? null : date.getUTCHours();
}

function isSuspiciousHour(hour, start, end) {
  if (hour === null || start === end) return false;
  if (start < end) return hour >= start && hour < end;   // e.g. 0-6, doesn't cross midnight
  return hour >= start || hour < end;                     // e.g. 22-6, crosses midnight
}

export function analyze(events, config) {
  const threshold = config.bruteforce_threshold ?? 5;
  const { start = 0, end = 6 } = config.suspicious_hours ?? {};
  const tracker = config.tracker;
  const deviceId = config.deviceId ?? "unknown";

  const alerts = [];
  const failuresByAccount = new Map();
  const failuresByIp = new Map();

  for (const e of events) {
    const isFailedLogon = e.event_id === 4625 || /failed password/i.test(e.raw);
    const isSuccessLogon = e.event_id === 4624 || /accepted password/i.test(e.raw);

    if (isFailedLogon) {
      // LogonType 10 = RemoteInteractive (RDP), 3 = Network. Both represent
      // an attempt that didn't originate from someone physically at the
      // keyboard - worth flagging on its own, not just when it crosses the
      // brute-force threshold, since a single unexpected RDP attempt can
      // matter even alone (e.g. RDP shouldn't be internet-exposed at all
      // on most laptops).
      if (e.logon_type === 10 || e.logon_type === 3) {
        alerts.push({
          type: "remote_logon_attempt",
          severity: "medium",
          account: e.account ?? null,
          src_ip: e.src_ip ?? null,
          logon_type: e.logon_type,
          timestamp: e.timestamp ?? null,
          raw: e.raw,
        });
      }

      const ts = e.timestamp ? Date.parse(e.timestamp) : Date.now();

      if (tracker) {
        if (e.account) {
          const count = tracker.recordFailure(deviceId, "account", e.account, ts);
          if (count === threshold) {
            alerts.push({
              type: "bruteforce_account",
              severity: "high",
              account: e.account,
              attempt_count: count,
              threshold,
              timestamp: e.timestamp ?? null,
              raw: `${count} failed logon attempts for account '${e.account}' within the tracking window`,
            });
          }
        }
        if (e.src_ip) {
          const count = tracker.recordFailure(deviceId, "ip", e.src_ip, ts);
          if (count === threshold) {
            alerts.push({
              type: "bruteforce_source_ip",
              severity: "high",
              src_ip: e.src_ip,
              attempt_count: count,
              threshold,
              timestamp: e.timestamp ?? null,
              raw: `${count} failed logon attempts from source '${e.src_ip}' within the tracking window`,
            });
          }
        }
      } else {
        // Fallback: per-batch only (used when no tracker is supplied, e.g. tests)
        if (e.account) {
          if (!failuresByAccount.has(e.account)) failuresByAccount.set(e.account, []);
          failuresByAccount.get(e.account).push(e);
        }
        if (e.src_ip) {
          if (!failuresByIp.has(e.src_ip)) failuresByIp.set(e.src_ip, []);
          failuresByIp.get(e.src_ip).push(e);
        }
      }
    }

    if (isSuccessLogon) {
      const isSystemAccount =
        e.account && (e.account.toUpperCase() === "SYSTEM" || e.account.endsWith("$"));
      const hour = hourOf(e);
      if (!isSystemAccount && isSuspiciousHour(hour, start, end)) {
        alerts.push({
          type: "suspicious_hour_login",
          severity: "medium",
          account: e.account ?? null,
          src_ip: e.src_ip ?? null,
          timestamp: e.timestamp ?? null,
          raw: e.raw,
        });
      }
    }
  }

  if (!tracker) {
    for (const [account, fails] of failuresByAccount) {
      if (fails.length >= threshold) {
        alerts.push({
          type: "bruteforce_account",
          severity: "high",
          account,
          attempt_count: fails.length,
          threshold,
          timestamp: fails[fails.length - 1].timestamp ?? null,
          raw: `${fails.length} failed logon attempts for account '${account}'`,
        });
      }
    }

    for (const [ip, fails] of failuresByIp) {
      if (fails.length >= threshold) {
        alerts.push({
          type: "bruteforce_source_ip",
          severity: "high",
          src_ip: ip,
          attempt_count: fails.length,
          threshold,
          timestamp: fails[fails.length - 1].timestamp ?? null,
          raw: `${fails.length} failed logon attempts from source '${ip}'`,
        });
      }
    }
  }

  return alerts;
}
