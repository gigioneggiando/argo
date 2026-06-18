// Thin API client for the pipeline backend. Same-origin; the SPA is served by FastAPI.

async function req(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(`${res.status}: ${detail}`);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

export const api = {
  health: () => req("GET", "/health"),
  startRun: (payload) => req("POST", "/runs", payload),
  listRuns: () => req("GET", "/runs"),
  getRun: (id) => req("GET", `/runs/${id}`),
  cancelRun: (id) => req("POST", `/runs/${id}/cancel`),
  report: (id) => req("GET", `/runs/${id}/report`),
  validated: (id) => req("GET", `/runs/${id}/artifacts/validated_findings`),
  artifact: (id, name) => req("GET", `/runs/${id}/artifacts/${name}`),
  prompts: (id) => req("GET", `/runs/${id}/prompts`),
  drafts: (id) => req("GET", `/runs/${id}/drafts`),
  getSettings: () => req("GET", "/settings"),
  saveSettings: (s) => req("PUT", "/settings", s),
  recommend: (payload) => req("POST", "/recommend", payload),
  getChat: (id) => req("GET", `/runs/${id}/chat`),
  sendChat: (id, message) => req("POST", `/runs/${id}/chat`, { message }),
  generated: (id) => req("GET", `/runs/${id}/generated`),
  knowledge: () => req("GET", "/knowledge"),
  models: () => req("GET", "/models"),
  costs: () => req("GET", "/costs"),
  benchmark: () => req("GET", "/benchmark"),
  benchmarkAb: () => req("GET", "/benchmark/ab"),
  quality: () => req("GET", "/quality"),
  getFixes: (id) => req("GET", `/runs/${id}/fixes`),
  patches: (id) => req("GET", `/runs/${id}/patches`),
  generateFixes: (id, opts) => req("POST", `/runs/${id}/fixes`, opts || { verify: true }),
};

// Live status via Server-Sent Events. onUpdate(status) is called on each event;
// onDone(status) when a terminal state is reached. Returns a close() function.
export function streamRun(id, onUpdate, onDone) {
  const es = new EventSource(`/runs/${id}/events`);
  let last = null;
  es.onmessage = (e) => {
    let st;
    try { st = JSON.parse(e.data); } catch (_) { return; }
    last = st;
    onUpdate(st);
    if (["completed", "failed", "cancelled"].includes(st.state)) {
      es.close();
      onDone && onDone(st);
    }
  };
  es.onerror = () => {
    // SSE closes when the run ends; only treat as error if we never reached terminal.
    es.close();
    if (!last || !["completed", "failed", "cancelled"].includes(last.state)) {
      onDone && onDone(last, new Error("stream interrupted"));
    }
  };
  return () => es.close();
}
