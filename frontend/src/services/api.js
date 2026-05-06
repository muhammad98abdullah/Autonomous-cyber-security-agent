import { API_BASE_URL } from "../config";

const headers = {
  "Content-Type": "application/json"
};

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      ...headers,
      ...(options.headers || {})
    }
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed: ${response.status}`);
  }

  return response.json();
}

export async function detect(features) {
  return request("/detect", {
    method: "POST",
    body: JSON.stringify({ features })
  });
}

export async function getSystemStatus() {
  return request("/status");
}

export async function getLogs() {
  const response = await request("/logs?limit=300");
  return response.items || [];
}

export async function getMetrics() {
  const logs = await getLogs();
  const packetsProcessed = logs.length;
  const attacksDetected = logs.filter((item) => String(item.attack).toLowerCase() === "attack").length;
  const actionsTaken = logs.filter((item) => String(item.action || "").toLowerCase() !== "no action needed").length;

  const buckets = new Map();
  logs.forEach((item) => {
    const date = new Date(item.timestamp);
    const time = `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
    if (!buckets.has(time)) {
      buckets.set(time, { time, normal: 0, attack: 0 });
    }
    const bucket = buckets.get(time);
    if (String(item.attack).toLowerCase() === "attack") {
      bucket.attack += 1;
    } else {
      bucket.normal += 1;
    }
  });

  const trend = Array.from(buckets.values()).slice(0, 15).reverse();

  return { packetsProcessed, attacksDetected, actionsTaken, trend };
}

export async function startMonitoring() {
  return request("/monitoring/start", { method: "POST", body: JSON.stringify({}) });
}

export async function stopMonitoring() {
  return request("/monitoring/stop", { method: "POST", body: JSON.stringify({}) });
}

export async function retrainModel() {
  return request("/model/retrain", { method: "POST", body: JSON.stringify({}) });
}

export async function createSite(payload) {
  return request("/sites", { method: "POST", body: JSON.stringify(payload) });
}

export async function getSites() {
  const response = await request("/sites");
  return response.items || [];
}

export async function getSiteInstallCommand(siteId) {
  return request(`/sites/${siteId}/install-command`);
}

export async function updateSitePolicy(siteId, mode) {
  return request(`/sites/${siteId}/policy`, {
    method: "PATCH",
    body: JSON.stringify({ mode })
  });
}

export async function getSiteOverview(siteId) {
  return request(`/sites/${siteId}/overview`);
}
