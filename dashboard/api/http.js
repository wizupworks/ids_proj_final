const API_BASE_STORAGE_KEY = "ids_dashboard_api_base";

/**
 * Base URL for the Phase 4 dashboard JSON API (no trailing slash).
 * - Query `?api_base=http://host:port` sets it for this load and persists to localStorage.
 * - `file://` defaults to http://127.0.0.1:18081 (same machine). Remote machines: open
 *   http://<server-ip>:18081 (Compose binds 0.0.0.0:18081 by default — do not use 0.0.0.0 in the browser URL).
 * - Otherwise empty string = same origin (use when dashboard and `/dash_api/` proxy share one host).
 */
export function resolveApiBase() {
  const q = new URLSearchParams(window.location.search).get("api_base") || "";
  if (q) {
    const v = q.replace(/\/$/, "");
    try {
      localStorage.setItem(API_BASE_STORAGE_KEY, v);
    } catch {
      /* ignore quota / private mode */
    }
    return v;
  }
  try {
    const stored = localStorage.getItem(API_BASE_STORAGE_KEY);
    if (stored && String(stored).trim()) {
      return String(stored).trim().replace(/\/$/, "");
    }
  } catch {
    /* ignore */
  }
  if (window.location.protocol === "file:") {
    return "http://127.0.0.1:18081";
  }
  return "";
}

/** For debugging in DevTools: `window.__IDS_DASHBOARD_API_BASE__` */
export function getResolvedApiBase() {
  return resolveApiBase();
}

/** DevTools: `window.__IDS_CLEAR_DASHBOARD_API_BASE__()` then reload if a bad api_base was stored. */
export function clearPersistedApiBase() {
  try {
    localStorage.removeItem(API_BASE_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

if (typeof window !== "undefined") {
  window.__IDS_CLEAR_DASHBOARD_API_BASE__ = clearPersistedApiBase;
}

function buildFetchInit(options) {
  const { headers: orig, ...rest } = options;
  const h = new Headers();
  if (orig instanceof Headers) {
    orig.forEach((v, k) => h.set(k, v));
  } else if (orig && typeof orig === "object") {
    for (const [k, v] of Object.entries(orig)) {
      if (v != null) h.set(k, String(v));
    }
  }
  if (!h.has("Accept")) h.set("Accept", "application/json");
  return { ...rest, headers: h };
}

export async function jsonFetch(url, options = {}) {
  const method = options.method || "GET";
  let res;
  try {
    res = await fetch(url, buildFetchInit(options));
  } catch (err) {
    const base = resolveApiBase();
    const hint =
      err?.name === "TypeError"
        ? " Often: wrong origin (static server without /dash_api proxy), API down, ad blocker, or CORS. Use http://<server-ip>:18081 when the stack binds 0.0.0.0:18081, or ?api_base=http://<server-ip>:18081 / :8090 (dash-api accepts /dash_api/ paths)."
        : "";
    console.error("[dashboard] fetch failed", { url, method, page: window.location.href, apiBase: base || "(same-origin)", err });
    throw new Error(`Network failure ${method} ${url}: ${err?.message || String(err)}.${hint}`);
  }

  const text = await res.text();
  let payload = {};
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      console.error("[dashboard] non-JSON response", {
        url,
        method,
        status: res.status,
        snippet: text.slice(0, 400),
      });
      throw new Error(`Non-JSON HTTP ${res.status} for ${url}: ${text.slice(0, 200)}`);
    }
  }
  if (!res.ok) {
    const detail = payload.detail ? `: ${payload.detail}` : "";
    const msg = (payload.error || payload.message || `${res.status} ${res.statusText}`) + detail;
    console.error("[dashboard] HTTP error", { url, method, status: res.status, payload });
    throw new Error(msg);
  }
  return payload;
}
