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

async function upload(path, file) {
  const fd = new FormData();
  fd.append("file", file);
  const res = await fetch(path, { method: "POST", body: fd });   // browser sets the multipart boundary
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json();
}

export const api = {
  health: () => req("GET", "/health"),
  startRun: (payload) => req("POST", "/runs", payload),
  uploadRepo: (file) => upload("/uploads", file),
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
  screen: (payload) => req("POST", "/screen", payload),
  plan: (payload) => req("POST", "/plan", payload),
  getChat: (id) => req("GET", `/runs/${id}/chat`),
  sendChat: (id, message) => req("POST", `/runs/${id}/chat`, { message }),
  generated: (id) => req("GET", `/runs/${id}/generated`),
  knowledge: () => req("GET", "/knowledge"),
  models: () => req("GET", "/models"),
  costs: () => req("GET", "/costs"),
  benchmark: () => req("GET", "/benchmark"),
  benchmarkAb: () => req("GET", "/benchmark/ab"),
  benchmarkCross: () => req("GET", "/benchmark/cross"),
  refusalProbe: () => req("GET", "/refusal-probe"),
  quality: () => req("GET", "/quality"),
  getFixes: (id) => req("GET", `/runs/${id}/fixes`),
  patches: (id) => req("GET", `/runs/${id}/patches`),
  generateFixes: (id, opts) => req("POST", `/runs/${id}/fixes`, opts || { verify: true }),
  questions: (id) => req("GET", `/runs/${id}/questions`),
  buildQuestions: (id) => req("POST", `/runs/${id}/questions`),
  answerQuestion: (id, qid, answer, provenance) =>
    req("POST", `/runs/${id}/questions/${encodeURIComponent(qid)}/answer`, { answer, provenance }),
  revalidateContext: (id, body) => req("POST", `/runs/${id}/revalidate-context`, body || {}),
};

// One chat turn streamed as NDJSON (POST, so not EventSource): onActivity(text) for each live
// progress line, resolves with the same payload as sendChat. Falls back to reading the whole body
// when the browser cannot stream it.
export async function streamChat(id, message, onActivity) {
  const res = await fetch(`/runs/${id}/chat/stream`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ message }),
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(`${res.status}: ${detail}`);
  }
  let done = null;
  const handle = (line) => {
    if (!line.trim()) return;
    const ev = JSON.parse(line);
    if (ev.type === "activity") { if (onActivity) onActivity(ev.text); }
    else if (ev.type === "error") throw new Error(ev.detail || "chat failed");
    else if (ev.type === "done") { const { type, ...rest } = ev; done = rest; }
  };
  if (res.body && res.body.getReader) {
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done: end } = await reader.read();
      if (end) break;
      buf += dec.decode(value, { stream: true });
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) { handle(buf.slice(0, nl)); buf = buf.slice(nl + 1); }
    }
    handle(buf);
  } else {
    (await res.text()).split("\n").forEach(handle);
  }
  if (!done) throw new Error("chat stream ended without a reply");
  return done;
}

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
