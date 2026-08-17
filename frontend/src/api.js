const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function request(path, options = {}) {
  const token = localStorage.getItem("lg_token");
  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Request failed: ${response.status}`);
  }
  return response.json();
}

export function login(email, password) {
  return request("/login", { method: "POST", body: JSON.stringify({ email, password }) });
}

export function register(email, password) {
  return request("/register", { method: "POST", body: JSON.stringify({ email, password }) });
}

export function listDevices() {
  return request("/devices");
}

export function listAlerts(deviceId) {
  return request(`/devices/${deviceId}/alerts`);
}

// NEW: log search
export function searchLogs(params) {
  const query = new URLSearchParams(
    Object.fromEntries(Object.entries(params).filter(([, v]) => v !== "" && v != null))
  );
  return request(`/logs/search?${query.toString()}`);
}

export function logStats(deviceId) {
  const query = deviceId ? `?device_id=${deviceId}` : "";
  return request(`/logs/stats${query}`);
}
