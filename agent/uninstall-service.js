import { Service } from "node-windows";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const svc = new Service({
  name: "LogGuardAgent",
  script: path.join(__dirname, "poll_events.js"),
});

svc.on("uninstall", () => {
  console.log("[agent] service uninstalled");
});

svc.uninstall();
