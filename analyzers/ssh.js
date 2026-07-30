/**
 * Auth / logon analyzer.
 * Event ID 4625 = failed logon, 4624 = successful logon (Windows Security channel).
 */

function hourOf(event) {
  if (!event.timestamp) return null;
  const date = new Date(event.timestamp);
  return isNaN(date) ? null : date.getUTCHours();
}

export function analyze(events, config) {
  const threshold = config.bruteforce_threshold ?? 5;
  const { start = 0, end = 6 } = config.suspicious_hours ?? {};

  const alerts = [];
  const failuresByAccount = new Map();
  const failuresByIp = new Map();

  for (const e of events) {
    const isFailedLogon = e.event_id === 4625 || /failed password/i.test(e.raw);
    const isSuccessLogon = e.event_id === 4624 || /accepted password/i.test(e.raw);

    if (isFailedLogon) {
      if (e.account) {
        if (!failuresByAccount.has(e.account)) failuresByAccount.set(e.account, []);
        failuresByAccount.get(e.account).push(e);
      }
      if (e.src_ip) {
        if (!failuresByIp.has(e.src_ip)) failuresByIp.set(e.src_ip, []);
        failuresByIp.get(e.src_ip).push(e);
      }
    }

    if (isSuccessLogon) {
      const hour = hourOf(e);
      if (hour !== null && (hour >= start || hour < end)) {
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

  return alerts;
}
