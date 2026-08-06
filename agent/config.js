import fs from "fs";
import path from "path";

const CONFIG_DIR = "C:\\ProgramData\\LogGuardAgent";
const CONFIG_PATH = path.join(CONFIG_DIR, "config.json");

export function saveConfig(config) {
  if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

export function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf-8"));
}

export { CONFIG_PATH };
