/**
 * Installs poll_events.js as a real Windows Service using node-windows,
 * so it runs on boot under the system account.
 *
 * Run once (as Administrator):   node install-service.js
 * Uninstall:                     node uninstall-service.js
 */

import { Service } from "node-windows";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const svc = new Service({
  name: "LogGuardAgent",
  description: "LogGuard AI - Live Log Monitoring Agent",
  script: path.join(__dirname, "poll_events.js"),
});

svc.on("install", () => {
  console.log("[agent] service installed, starting...");
  svc.start();
});

svc.install();
