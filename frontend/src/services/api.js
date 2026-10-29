const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");
const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === "true";

export function getAppMode() {
  return DEMO_MODE ? "Demo mode" : "API mode";
}

export async function apiRequest(path, options = {}) {
  if (!API_BASE_URL) throw new Error("API URL is not configured. Set VITE_API_BASE_URL in frontend/.env.");
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers },
    });
  } catch (error) {
    throw new Error(`Could not reach the API at ${API_BASE_URL}. ${error.message || "Check that the backend is running."}`, { cause: error });
  }
  if (!response.ok) {
    let message = `API request failed with status ${response.status}.`;
    try {
      const data = await response.json();
      const detail = data.detail;
      message = Array.isArray(detail)
        ? detail.map((item) => [item.loc?.join("."), item.msg].filter(Boolean).join(": ")).join("; ")
        : typeof detail === "string" ? detail : JSON.stringify(detail || data);
    } catch { /* retain status fallback */ }
    throw new Error(message);
  }
  if (response.status === 204) return null;
  const text = await response.text();
  if (!text) return null;
  try { return JSON.parse(text); } catch { return text; }
}

export function listItems(response) {
  if (Array.isArray(response)) return response;
  return Array.isArray(response?.items) ? response.items : [];
}

export const fetchAssets = () => apiRequest("/assets");
export const createAsset = (payload) => apiRequest("/assets", { method: "POST", body: JSON.stringify(payload) });
export const fetchAuditHistory = () => apiRequest("/audits?skip=0&limit=200");
export const fetchAudit = (auditId) => apiRequest(`/audits/${encodeURIComponent(auditId)}`);
export const fetchAuditFindings = (auditId) => apiRequest(`/audits/${encodeURIComponent(auditId)}/findings`);
export const fetchDrift = (auditId) => apiRequest(`/audits/${encodeURIComponent(auditId)}/drift`);
export const fetchAuditCorrelations = (auditId) => apiRequest(`/audits/${encodeURIComponent(auditId)}/correlations`);
export const startAudit = (payload) => apiRequest("/run-audit", { method: "POST", body: JSON.stringify(payload) });

export function getReportUrl() {
  return null; // The backend does not currently expose report-generation routes.
}
