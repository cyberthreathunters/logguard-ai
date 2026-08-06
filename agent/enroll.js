import axios from "axios";
import os from "os";
import { saveConfig } from "./config.js";

async function enroll(backendUrl, installCode) {
  const response = await axios.post(`${backendUrl}/devices/enroll`, {
    install_code: installCode,
    hostname: os.hostname(),
  });

  const { device_id, device_token } = response.data;

  saveConfig({ backend_url: backendUrl, device_id, device_token });
  console.log(`[agent] enrolled as device_id=${device_id}`);
}

const [, , backendUrl, installCode] = process.argv;
if (!backendUrl || !installCode) {
  console.log("Usage: node enroll.js <backend_url> <install_code>");
  process.exit(1);
}

enroll(backendUrl, installCode).catch((err) => {
  console.error("[agent] enrollment failed:", err.message);
  process.exit(1);
});
