// Router + views. Hash-based routing keeps deep links working with zero server config.
import { api, streamRun } from "./api.js";
import {
  h, mount, toast, sevPill, verdictPill, stateChip, costChip,
  SEVERITIES, sevRank, confRank, effSev, effConf, verdict, primaryRef,
} from "./ui.js";

const app = () => document.getElementById("app");
const STAGES = ["ingest", "recon", "audit", "validate", "report"];
let teardown = null;  // called before leaving a view (e.g. close an SSE stream)

// --------------------------------------------------------------------- router
function parseRoute() {
  const hash = location.hash.replace(/^#/, "") || "/";
  const m = hash.match(/^\/run\/(.+)$/);
  if (m) return { name: "run", id: decodeURIComponent(m[1]) };
  if (hash.startsWith("/history")) return { name: "history" };
  if (hash.startsWith("/settings")) return { name: "settings" };
  if (hash.startsWith("/knowledge")) return { name: "knowledge" };
  if (hash.startsWith("/costs")) return { name: "costs" };
  if (hash.startsWith("/benchmark")) return { name: "benchmark" };
  return { name: "new" };
}

function render() {
  if (teardown) { try { teardown(); } catch (_) {} teardown = null; }
  const r = parseRoute();
  document.querySelectorAll("#nav a").forEach((a) => {
    const target = a.getAttribute("href").replace(/^#/, "");
    a.classList.toggle("active", (r.name === "new" && target === "/") ||
      (r.name === "history" && target === "/history") ||
      (r.name === "settings" && target === "/settings") ||
      (r.name === "knowledge" && target === "/knowledge") ||
      (r.name === "costs" && target === "/costs") ||
      (r.name === "benchmark" && target === "/benchmark"));
  });
  const view = r.name === "run" ? runView(r.id)
    : r.name === "history" ? historyView()
    : r.name === "settings" ? settingsView()
    : r.name === "knowledge" ? knowledgeView()
    : r.name === "costs" ? costsView()
    : r.name === "benchmark" ? benchmarkView()
    : newRunView();
  mount(app(), view);
  window.scrollTo(0, 0);
}
window.addEventListener("hashchange", render);

function setupTheme() {
  const btn = document.getElementById("themeToggle");
  if (!btn) return;
  const icon = () => { btn.textContent = document.documentElement.getAttribute("data-theme") === "light" ? "☾" : "☀"; };
  icon();
  btn.addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("theme", next); } catch (_) {}
    icon();
  });
}

setupTheme();
render();

// --------------------------------------------------------------- NEW RUN view
function newRunView() {
  const form = { brief: "", repo: "", links: "", runner: "mock", budget: "", audit_model: "", parallel: 3, dry_run: false, calibration: false, research: true, codex_model: "", codex_oss: false, codex_local_provider: "" };

  let mode = "general";  // "general" = audit any code (no brief) · "bounty" = scoped program
  const briefEl = h("textarea", { placeholder: "Paste the bug-bounty program page: scope, rules, rewards, exclusions, “no DoS”…", oninput: (e) => form.brief = e.target.value });
  const linksEl = h("textarea", { placeholder: "https://project.example/docs\nhttps://project.example/security", style: { minHeight: "70px" }, oninput: (e) => form.links = e.target.value });
  const repoEl = h("input", { type: "text", placeholder: "/home/me/project   ·   C:\\dev\\app   ·   https://github.com/org/repo", oninput: (e) => form.repo = e.target.value });

  const runnerSeg = seg([["mock", "Mock · free"], ["headless", "Claude"], ["codex", "Codex"]], "mock", (v) => {
    form.runner = v; costBanner.classList.toggle("hidden", v === "mock");
    codexRow.classList.toggle("hidden", v !== "codex");
    startBtn.lastChild.textContent = v === "mock" ? "Start run (free)" : "Start real run";
  });
  const codexModelEl = h("input", { type: "text", list: "dl-codex-models", placeholder: "blank = your Codex default model", oninput: (e) => form.codex_model = e.target.value.trim() });
  const codexProviderEl = h("input", { type: "text", placeholder: "blank = OpenAI; or ollama / lmstudio", oninput: (e) => { form.codex_local_provider = e.target.value.trim(); form.codex_oss = !!form.codex_local_provider; } });
  const codexRow = h("div", { class: "grid-2 hidden", style: { marginTop: "14px" } },
    field("Codex model", codexModelEl, "Model id for the Codex CLI; blank = its own default."),
    field("Codex provider", codexProviderEl, "Blank uses OpenAI; set ollama/lmstudio to run a local/open-source model via Codex --oss."));
  const drySeg = seg([["false", "Full pipeline"], ["true", "Dry-run (stop after recon)"]], "false", (v) => form.dry_run = v === "true");
  const calSeg = seg([["false", "Off"], ["true", "Calibration (audit→Opus)"]], "false", (v) => form.calibration = v === "true");
  const researchSeg = seg([["true", "On · web OSINT"], ["false", "Off · offline"]], "true", (v) => form.research = v === "true");
  const budgetEl = h("input", { type: "number", min: "0", step: "1", placeholder: "blank = no limit (run to completion)", oninput: (e) => form.budget = e.target.value });
  const modelEl = h("input", { type: "text", list: "dl-claude-models", placeholder: "default (per-stage)", oninput: (e) => form.audit_model = e.target.value });
  const claudeDL = h("datalist", { id: "dl-claude-models" });
  const codexDL = h("datalist", { id: "dl-codex-models" });
  api.models().then((mm) => {
    const cl = (mm.backends || []).find((b) => b.id === "headless");
    const cx = (mm.backends || []).find((b) => b.id === "codex");
    (cl ? cl.models : []).forEach((m) => claudeDL.append(h("option", { value: m.id }, m.label || "")));
    (cx ? cx.models : []).forEach((m) => codexDL.append(h("option", { value: m.id })));
    if (cx && cx.default) codexModelEl.placeholder = `blank = your Codex default (${cx.default})`;
  }).catch(() => {});
  const parallelEl = h("input", { type: "number", min: "1", max: "16", value: "3", oninput: (e) => form.parallel = +e.target.value || 3 });

  const adv = h("div", { class: "adv hidden" },
    h("div", { class: "grid-2" },
      field("Runner", runnerSeg, "Mock replays fixtures (zero tokens). Claude = Claude Code; Codex = Codex CLI (OpenAI / local-OSS)."),
      field("Mode", drySeg, "Dry-run shows the generated prompts before paying for audits.")),
    h("div", { class: "grid-2", style: { marginTop: "14px" } },
      field("Budget (USD)", budgetEl, "Hard per-run ceiling in USD. Leave blank for no limit — the default: the audit runs to completion regardless of cost. Set a number to abort once spending reaches it."),
      field("Audit model", modelEl, "Override only the Stage-3 model (the missed-bug lever).")),
    h("div", { class: "grid-2", style: { marginTop: "14px" } },
      field("Parallel sessions", parallelEl, "How many audit/validate sessions run at once (default 3). Higher = faster wall-clock but more simultaneous spend and more chance of provider rate-limits; lower = slower but gentler. It changes speed, not what's found."),
      field("Calibration", calSeg, "Force audit on Opus while prompts are unproven.")),
    h("div", { class: "grid-2", style: { marginTop: "14px" } },
      field("Web research (Stage 0)", researchSeg, "On: a web-OSINT pass (CVEs, advisories, the project's history) feeds recon — the ONLY networked step, never the live in-scope hosts. Off: fully offline.")),
    codexRow);
  const advToggle = h("div", { class: "adv-toggle" }, h("span", { class: "chev" }, "▸"), "Advanced configuration");
  advToggle.addEventListener("click", () => { advToggle.classList.toggle("open"); adv.classList.toggle("hidden"); });

  const costBanner = h("div", { class: "banner warn hidden", style: { marginTop: "16px" } },
    h("span", {}, "⚠"),
    h("span", {}, h("strong", {}, "Real run. "), "Spends real tokens on the selected backend (Claude / Codex; a full audit can cost real money). Set a budget and confirm before starting."));

  const startBtn = h("button", { class: "btn btn-primary btn-lg", onclick: submit },
    h("span", {}, "⏵"), h("span", {}, "Start run (free)"));

  // ---- "Let the AI choose" ---------------------------------------------------
  let recoTarget = "standard";
  const recoSeg = seg([["quick", "Quick"], ["standard", "Standard"], ["thorough", "Thorough"]], "standard", (v) => recoTarget = v);
  const recoBanner = h("div", { class: "banner info hidden", style: { marginTop: "14px" } });
  const recoBtn = h("button", { class: "btn btn-ghost", onclick: async () => {
    recoBtn.disabled = true;
    try {
      const r = await api.recommend({ repo: form.repo || null, target: recoTarget });
      applyConfig(r.config);
      advToggle.classList.add("open"); adv.classList.remove("hidden");
      mount(recoBanner, h("span", {}, "✨"), h("span", {}, h("strong", {}, "Recommended. "), r.rationale));
      recoBanner.classList.remove("hidden");
    } catch (e) { toast(e.message, true); } finally { recoBtn.disabled = false; }
  } }, h("span", {}, "✨"), h("span", {}, "Recommend settings"));
  const recoCard = h("div", { class: "card" },
    h("div", { class: "spread" },
      h("div", { class: "grow" }, h("h2", {}, "✨ Let the pipeline choose"),
        h("div", { class: "hint" }, "Pick how thorough this run should be — models, budget and parallelism are set for you (runner stays Mock until you switch it).")),
      recoSeg, recoBtn),
    recoBanner);

  function applyConfig(cfg) {
    if (cfg.runner) setSeg(runnerSeg, cfg.runner);
    const b = (cfg.budget_usd == null ? "" : String(cfg.budget_usd)); form.budget = b; budgetEl.value = b;
    if (cfg.parallel) { form.parallel = cfg.parallel; parallelEl.value = cfg.parallel; }
    const am = cfg.audit_model || (cfg.models && cfg.models.audit) || "";
    form.audit_model = am; modelEl.value = am;
    setSeg(calSeg, cfg.calibration ? "true" : "false");
  }

  async function submit() {
    if (!form.repo.trim()) return toast("Add code to audit: a local folder path or a git URL", true);
    // General mode => empty brief => local/personal source-only review (scope synthesized).
    const brief = mode === "general" ? "" : form.brief;
    const links = mode === "general" ? null : (form.links.trim() || null);
    startBtn.disabled = true; startBtn.lastChild.textContent = "Starting…";
    try {
      const cfg = { runner: form.runner, parallel: form.parallel, calibration: form.calibration,
        budget_usd: form.budget ? Number(form.budget) : null, audit_model: form.audit_model.trim() || null,
        codex_model: form.codex_model || null, codex_oss: form.codex_oss, codex_local_provider: form.codex_local_provider || null };
      const res = await api.startRun({ brief, repo: form.repo, links, dry_run: form.dry_run, research: form.research, config: cfg });
      location.hash = `#/run/${encodeURIComponent(res.run_id)}`;
    } catch (e) {
      toast(e.message, true); startBtn.disabled = false;
      startBtn.lastChild.textContent = form.runner === "headless" ? "Start real run" : "Start run (free)";
    }
  }

  // load persisted defaults (Settings page)
  api.getSettings().then((s) => applyConfig({ runner: s.runner, budget_usd: s.budget_usd, parallel: s.parallel, audit_model: s.audit_model, calibration: s.calibration, models: s.models })).catch(() => {});

  // ---- mode: general code audit (default) vs bug-bounty triage ----------------
  const briefField = field("Program description", briefEl, "The bug-bounty program page — scope, rules and exclusions are extracted from it; it drives scope filtering and the submission drafts.");
  const linksField = field("Reference links", linksEl, "Docs / security pages / advisory history. One URL per line. Optional.");
  const repoField = field("Code to audit", repoEl,
    "A local folder path (resolved on the machine running the server) or a git URL (cloned read-only). The repo is mounted read-only and never pushed anywhere — but a cloud backend (Claude / Codex) sends the source to that provider's API to analyze it; only a local / OSS model keeps everything on-device. Examples: ./src · C:\\dev\\app · https://github.com/org/repo", true);
  const modeHint = h("div", { class: "help", style: { marginTop: "8px" } });
  const MODE_COPY = {
    general: "Audit any codebase for vulnerabilities — point at a local folder or repo, no program brief needed. The repo stays read-only and is never pushed anywhere (a local / OSS model keeps it fully on-device; a cloud backend sends the source to its API to analyze).",
    bounty: "Triage a scoped bug-bounty program — paste the program brief; scope, rules and submission drafts come from it.",
  };
  function setMode(m) {
    mode = m;
    briefField.classList.toggle("hidden", m === "general");
    linksField.classList.toggle("hidden", m === "general");
    modeHint.textContent = MODE_COPY[m];
  }
  const modeSeg = seg([["general", "🔍 General audit"], ["bounty", "🎯 Bug bounty"]], "general", setMode);
  setMode("general");
  const modeRow = h("div", { class: "field" }, h("label", { class: "lbl" }, "Mode"), modeSeg, modeHint);

  return h("div", {},
    claudeDL, codexDL,
    h("div", { class: "page-head" },
      h("h1", {}, "New audit run"),
      h("p", {}, "Point Argo at any codebase — a local folder, a private repo, or a public one — and an LLM audits the source like a human reviewer: it profiles the code, writes target-specific audit prompts, hunts findings, and adversarially validates them, stopping at human-review drafts. Never touches a live host, never patches.")),
    recoCard,
    h("div", { class: "card" },
      modeRow,
      briefField, linksField, repoField,
      advToggle, adv, costBanner,
      h("div", { class: "spread", style: { marginTop: "22px" } },
        h("span", { class: "grow faint", style: { fontSize: "13px" } }, "Default runner is Mock (free). Switch to Real in Advanced."),
        startBtn)));
}

function field(label, control, help, required) {
  return h("div", { class: "field" },
    h("label", { class: "lbl" }, label, required ? h("span", { class: "req" }, " *") : null),
    control, help ? h("div", { class: "help" }, help) : null);
}
function seg(options, current, onChange) {
  const wrap = h("div", { class: "seg" });
  options.forEach(([val, lab]) => {
    const b = h("button", { "data-val": val, class: val === current ? "on" : "", onclick: () => {
      [...wrap.children].forEach((c) => c.classList.remove("on", "danger"));
      b.classList.add("on"); if (val === "headless") b.classList.add("danger");
      onChange(val);
    } }, lab);
    if (val === current && val === "headless") b.classList.add("danger");
    wrap.append(b);
  });
  return wrap;
}
const setSeg = (segEl, val) => { const b = segEl.querySelector(`[data-val="${val}"]`); if (b) b.click(); };

// ------------------------------------------------------------------ SETTINGS view
function settingsView() {
  const STAGES = ["ingest", "research", "recon", "audit", "validate", "report"];
  const s = { runner: "mock", budget_usd: null, parallel: 3, audit_model: null, calibration: false, models: {} };

  const runnerSeg = seg([["mock", "Mock · free"], ["headless", "Real · claude"]], "mock", (v) => s.runner = v);
  const calSeg = seg([["false", "Off"], ["true", "Calibration"]], "false", (v) => s.calibration = v === "true");
  const budgetEl = h("input", { type: "number", min: "0", placeholder: "none", oninput: (e) => s.budget_usd = e.target.value ? Number(e.target.value) : null });
  const parallelEl = h("input", { type: "number", min: "1", max: "16", value: "3", oninput: (e) => s.parallel = +e.target.value || 3 });
  const auditEl = h("input", { type: "text", list: "dl-set-models", placeholder: "default", oninput: (e) => s.audit_model = e.target.value.trim() || null });
  const setDL = h("datalist", { id: "dl-set-models" });
  api.models().then((mm) => {
    const cl = (mm.backends || []).find((b) => b.id === "headless");
    (cl ? cl.models : []).forEach((m) => setDL.append(h("option", { value: m.id }, m.label || "")));
  }).catch(() => {});
  const modelEls = {};
  STAGES.forEach((st) => { modelEls[st] = h("input", { type: "text", list: "dl-set-models", placeholder: "default", oninput: (e) => { const v = e.target.value.trim(); if (v) s.models[st] = v; else delete s.models[st]; } }); });

  const saveBtn = h("button", { class: "btn btn-primary", onclick: async () => {
    saveBtn.disabled = true;
    try { await api.saveSettings({ runner: s.runner, budget_usd: s.budget_usd, parallel: s.parallel, audit_model: s.audit_model, calibration: s.calibration, models: s.models }); toast("Settings saved"); }
    catch (e) { toast(e.message, true); } finally { saveBtn.disabled = false; }
  } }, "Save defaults");

  function apply(d) {
    s.runner = d.runner || "mock"; setSeg(runnerSeg, s.runner);
    s.budget_usd = d.budget_usd ?? null; budgetEl.value = s.budget_usd ?? "";
    s.parallel = d.parallel || 3; parallelEl.value = s.parallel;
    s.audit_model = d.audit_model || null; auditEl.value = s.audit_model || "";
    s.calibration = !!d.calibration; setSeg(calSeg, s.calibration ? "true" : "false");
    s.models = d.models || {}; STAGES.forEach((st) => { modelEls[st].value = (s.models && s.models[st]) || ""; });
  }
  api.getSettings().then(apply).catch((e) => toast(e.message, true));

  return h("div", {},
    setDL,
    h("div", { class: "page-head" }, h("h1", {}, "Settings"),
      h("p", {}, "Defaults applied to the New Run form. Each run can still override them. Stored server-side (not in the browser).")),
    h("div", { class: "card" },
      h("div", { class: "grid-2" },
        field("Default runner", runnerSeg, "Mock is free; Claude/Codex spend real tokens."),
        field("Default budget (USD)", budgetEl, "Hard per-run ceiling.")),
      h("div", { class: "grid-2", style: { marginTop: "14px" } },
        field("Parallel sessions", parallelEl),
        field("Calibration", calSeg, "Force audit on Opus.")),
      field("Audit model override", auditEl, "Shortcut for the Stage-3 model.")),
    h("div", { class: "card" },
      h("h2", {}, "Per-stage models"),
      h("div", { class: "hint" }, "Leave blank for the smart defaults (Sonnet ingest/audit, Opus recon/validate)."),
      h("div", { class: "grid-2", style: { marginTop: "14px" } },
        ...STAGES.map((st) => field(st[0].toUpperCase() + st.slice(1), modelEls[st])))),
    h("div", { class: "spread", style: { marginTop: "18px" } }, h("span", { class: "grow" }), saveBtn));
}

// ------------------------------------------------------------------- RUN view
function runView(id) {
  const stateChipHost = h("span", {});
  const costHost = h("span", {});
  const cancelBtn = h("button", { class: "btn btn-danger hidden", onclick: async () => {
    cancelBtn.disabled = true; try { await api.cancelRun(id); toast("Cancellation requested"); } catch (e) { toast(e.message, true); }
  } }, "Cancel");

  const tlHost = h("div", { class: "timeline" });
  const artHost = h("div", { class: "artifacts" });
  const resultsHost = h("div", { style: { marginTop: "26px" } });

  let resultsRendered = false;

  function renderStatus(st) {
    mount(stateChipHost, stateChip(st.state));
    mount(costHost, costChip(st.cost_usd));
    cancelBtn.classList.toggle("hidden", !["starting", "running"].includes(st.state));
    renderTimeline(tlHost, st.stages || []);
    renderArtifacts(artHost, st.artifacts || {});
    if (["completed", "failed", "cancelled"].includes(st.state) && !resultsRendered) {
      resultsRendered = true;
      renderResults(resultsHost, id, st);
    }
  }

  api.getRun(id).then(renderStatus).catch((e) => toast(e.message, true));
  const close = streamRun(id, renderStatus, (st, err) => { if (err) toast("Live updates ended", true); if (st) renderStatus(st); });
  teardown = () => close();

  return h("div", {},
    h("div", { class: "page-head" },
      h("div", { class: "spread" },
        h("h1", { class: "grow" }, "Run"),
        costHost, stateChipHost, cancelBtn),
      h("p", { class: "mono", style: { fontSize: "13px" } }, id)),
    h("div", { class: "card" }, tlHost, artHost),
    resultsHost);
}

function renderTimeline(host, stages) {
  const prog = h("div", { class: "progress" });
  const steps = stages.map((s, i) => h("div", { class: `step ${s.state}` },
    h("div", { class: "node" }, s.state === "done" ? "✓" : s.state === "failed" ? "!" : String(i + 1)),
    h("div", { class: "lab" }, s.name)));
  const n = stages.length;
  let lastActive = -1;
  stages.forEach((s, i) => { if (s.state === "done" || s.state === "running") lastActive = i; });
  const frac = n > 1 && lastActive >= 0 ? lastActive / (n - 1) : 0;
  prog.style.width = `calc((100% - 56px) * ${frac})`;
  mount(host, prog, ...steps);
}

function renderArtifacts(host, a) {
  const cards = [
    ["Scope", a.scope ? "ready" : "—", a.scope],
    ["Repo profile", a.repo_profile ? "ready" : "—", a.repo_profile],
    ["Prompts", a.prompts || 0, a.prompts > 0],
    ["Findings files", a.findings || 0, a.findings > 0],
    ["Validated", a.validated_findings ? "ready" : "—", a.validated_findings],
    ["Report", a.report ? "ready" : "—", a.report],
    ["Drafts", a.drafts || 0, a.drafts > 0],
  ];
  mount(host, ...cards.map(([k, v, on]) =>
    h("div", { class: "acard" + (on ? " on" : "") },
      h("div", { class: "k" }, k), h("div", { class: "v" }, String(v)))));
}

// ------------------------------------------------------- results (completed run)
function renderResults(host, id, st) {
  if (st.state === "failed") {
    const err = st.error || "Unknown error";
    const budget = /budget|ceiling|exceed|cost cap/i.test(err);
    return mount(host, h("div", { class: "banner danger" }, h("span", {}, budget ? "💸" : "✖"),
      h("span", {}, h("strong", {}, budget ? "Run stopped — budget reached. " : "Run failed. "), err,
        budget ? h("div", { class: "help", style: { marginTop: "4px" } }, "Raise the per-run budget in Advanced and start a new run.") : null)));
  }
  if (st.state === "cancelled") {
    return mount(host, h("div", { class: "banner info" }, "Run cancelled."));
  }
  if (!st.artifacts || !st.artifacts.report) {
    // dry-run or report not produced: show prompts instead
    const panel = h("div", { class: "card" });
    mount(host, h("div", { class: "tabs" },
      h("button", { class: "on" }, "Generated prompts")), panel);
    api.prompts(id).then((ps) => mount(panel, ...ps.map(promptBlock))).catch((e) => toast(e.message, true));
    return;
  }

  const tabs = ["Report", "Findings", "Fixes", "Chat", "Drafts", "Artifacts"];
  const panel = h("div", {});
  const cache = {};
  const tabBar = h("div", { class: "tabs" });
  function select(name, btn) {
    [...tabBar.children].forEach((c) => c.classList.remove("on")); btn.classList.add("on");
    mount(panel, h("div", { class: "skeleton", style: { height: "120px" } }));
    loadTab(name, id, cache).then((node) => mount(panel, node)).catch((e) => { mount(panel, h("div", { class: "empty" }, e.message)); });
  }
  tabs.forEach((name, i) => {
    const b = h("button", { class: i === 0 ? "on" : "", onclick: () => select(name, b) }, name);
    tabBar.append(b);
  });
  mount(host, h("div", { class: "card" }, tabBar, panel));
  select("Report", tabBar.firstChild);
}

async function loadTab(name, id, cache) {
  if (name === "Chat") return chatPanel(id);
  if (name === "Fixes") return fixesPanel(id);
  if (name === "Report") {
    const md = cache.report || (cache.report = await api.report(id));
    const div = h("div", { class: "md" });
    div.innerHTML = window.marked ? window.marked.parse(md) : `<pre>${escapeHtml(md)}</pre>`;
    return div;
  }
  if (name === "Findings") {
    const doc = cache.validated || (cache.validated = await api.validated(id));
    return findingsTable(doc);
  }
  if (name === "Drafts") {
    const ds = cache.drafts || (cache.drafts = await api.drafts(id));
    if (!ds.length) return h("div", { class: "empty" }, h("div", { class: "big" }, "No submission drafts"),
      "Drafts are produced only for confirmed findings.");
    return h("div", {}, ...ds.map((d) => {
      const body = h("div", { class: "md", style: { marginTop: "8px" } });
      body.innerHTML = window.marked ? window.marked.parse(d.content) : `<pre>${escapeHtml(d.content)}</pre>`;
      return h("div", { class: "detail" }, h("h3", {}, d.name), body);
    }));
  }
  // Artifacts
  const buttons = [["Scope", "scope", "json"], ["Repo profile", "repo_profile", "json"],
    ["Synthesis notes", "synthesis_notes", "md"], ["Validated findings", "validated_findings", "json"]];
  const out = h("div", { style: { marginTop: "12px" } });
  const bar = h("div", { class: "row" }, ...buttons.map(([lab, key, kind]) =>
    h("button", { class: "btn btn-ghost", onclick: async () => {
      try {
        const data = await api.artifact(id, key);
        if (kind === "md" && typeof data === "string") {
          const d = h("div", { class: "md" }); d.innerHTML = window.marked ? window.marked.parse(data) : `<pre>${escapeHtml(data)}</pre>`;
          mount(out, h("div", { class: "detail" }, d));
        } else {
          mount(out, h("div", { class: "detail" }, h("pre", { class: "mono", style: { whiteSpace: "pre-wrap", fontSize: "12.5px", margin: 0 } }, JSON.stringify(data, null, 2))));
        }
      } catch (e) { toast(e.message, true); }
    } }, lab)));
  return h("div", {}, bar, out);
}

function findingsTable(doc) {
  const findings = (doc.findings || []).slice().sort((a, b) =>
    sevRank(effSev(b)) - sevRank(effSev(a)) || confRank(effConf(b)) - confRank(effConf(a)));
  const stats = doc.stats || {};
  const active = new Set(SEVERITIES);
  const wrap = h("div", {});

  const summary = h("div", { class: "row", style: { marginBottom: "14px" } },
    statChip("Survivors", findings.length),
    statChip("Confirmed", findings.filter((f) => verdict(f) === "confirmed").length),
    statChip("Needs runtime check", findings.filter((f) => verdict(f) === "needs_runtime_verification").length),
    statChip("Dropped", (doc.dropped || []).length));

  const filters = h("div", { class: "filters" }, ...SEVERITIES.map((s) => {
    const c = h("span", { class: `pill sev-${s}`, onclick: () => { active.has(s) ? active.delete(s) : active.add(s); c.classList.toggle("off", !active.has(s)); draw(); } },
      h("span", { class: "dot" }), s);
    return c;
  }));

  const tableHost = h("div", {});
  const detailHost = h("div", {});

  function draw() {
    const rows = findings.filter((f) => active.has(effSev(f)));
    if (!rows.length) return mount(tableHost, h("div", { class: "empty" }, "No findings match the filter."));
    const table = h("table", { class: "findings" },
      h("thead", {}, h("tr", {}, ...["#", "Finding", "Severity", "Verdict", "Location"].map((t) => h("th", {}, t)))),
      h("tbody", {}, ...rows.map((f) => {
        const tr = h("tr", { class: "frow", onclick: () => mount(detailHost, findingDetail(f)) },
          h("td", {}, h("span", { class: "fid" }, f.id)),
          h("td", {}, h("div", { class: "ftitle" }, f.title), h("div", { class: "fid" }, f.cwe || "")),
          h("td", {}, sevPill(effSev(f))),
          h("td", {}, verdictPill(verdict(f))),
          h("td", {}, h("span", { class: "floc" }, primaryRef(f))));
        return tr;
      })));
    mount(tableHost, table);
  }
  if (!findings.length) {
    mount(wrap, summary, h("div", { class: "empty" }, h("div", { class: "big" }, "No findings survived validation")));
    return wrap;
  }
  mount(wrap, summary, filters, tableHost, detailHost);
  draw();
  return wrap;
}

function findingDetail(f) {
  const v = f.validation || {};
  const block = (k, val, mono) => val ? h("div", { class: "block" }, h("div", { class: "bk" }, k), h("div", { class: "bv" + (mono ? " mono" : "") }, val)) : null;
  return h("div", { class: "detail" },
    h("div", { class: "spread" }, h("h3", { class: "grow" }, f.title), sevPill(effSev(f)), verdictPill(verdict(f))),
    h("div", { class: "row", style: { marginTop: "8px" } },
      h("span", { class: "pill" }, f.id), h("span", { class: "pill" }, f.cwe || ""),
      f.owasp ? h("span", { class: "pill" }, f.owasp) : null),
    block("Affected", (f.affected || []).join("\n"), true),
    block("Vulnerable flow", f.vulnerable_flow, true),
    block("Why vulnerable", f.why_vulnerable),
    block("Exploit scenario", f.exploit_scenario),
    block("Impact", f.impact),
    block("Validated data flow", v.surviving_data_flow, true),
    block("Validation rationale", v.rationale),
    block("Recommended fix (guidance)", f.recommended_fix),
    block("Live verification plan", f.live_verification_plan));
}

const statChip = (k, v) => h("div", { class: "acard", style: { minWidth: "120px", flex: "0 0 auto" } },
  h("div", { class: "k" }, k), h("div", { class: "v" }, String(v)));

function promptBlock(p) {
  const body = h("div", { class: "md", style: { marginTop: "8px" } });
  body.innerHTML = window.marked ? window.marked.parse(p.content) : `<pre>${escapeHtml(p.content)}</pre>`;
  return h("div", { class: "detail" }, h("h3", { class: "mono", style: { fontSize: "14px" } }, p.name), body);
}

// ------------------------------------------------------------------ HISTORY
function historyView() {
  const host = h("div", { class: "runlist" }, h("div", { class: "skeleton", style: { height: "70px" } }));
  api.listRuns().then((runs) => {
    if (!runs.length) return mount(host, h("div", { class: "empty" },
      h("div", { class: "big" }, "No runs yet"), h("a", { href: "#/" }, "Start your first audit →")));
    mount(host, ...runs.map((r) => h("div", { class: "runrow", onclick: () => location.hash = `#/run/${encodeURIComponent(r.run_id)}` },
      h("div", { class: "grow" },
        h("div", { class: "rprog" }, r.program_name || "(unnamed run)"),
        h("div", { class: "rid" }, r.run_id)),
      r.archetype ? h("span", { class: "pill" }, ARCH_LABELS[r.archetype] || r.archetype) : null,
      r.target_type ? h("span", { class: "pill" }, r.target_type) : null,
      costChip(r.cost_usd), stateChip(r.state))));
  }).catch((e) => mount(host, h("div", { class: "empty" }, e.message)));
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Run history"),
      h("p", {}, "Every run is kept under runs/. Click one to reopen its live status or results.")),
    host);
}

// ------------------------------------------------------------------ chat panel
function chatPanel(id) {
  const root = h("div", {});
  const list = h("div", { class: "chat-list" });
  const input = h("textarea", { class: "chat-input", rows: 2,
    placeholder: "Ask about the analysis — “why didn't you find X?”, “explain SQLI-001”, “generate a test for CWE-89”…" });
  let busy = false;

  const md = (t) => { const d = h("div", { class: "md" }); d.innerHTML = window.marked ? window.marked.parse(t) : escapeHtml(t); return d; };
  const bubble = (role, body) => h("div", { class: `chat-msg ${role}` },
    h("div", { class: "chat-role" }, role === "user" ? "You" : "Analyst"), h("div", { class: "chat-body" }, body));
  const scroll = () => { list.scrollTop = list.scrollHeight; };
  const addUser = (t) => { list.append(bubble("user", h("div", { class: "chat-plain" }, t))); scroll(); };
  const addAssistant = (t) => { list.append(bubble("assistant", md(t))); scroll(); };

  async function send(text) {
    text = (text || input.value).trim();
    if (!text || busy) return;
    busy = true; sendBtn.disabled = true; input.value = "";
    addUser(text);
    const pending = bubble("assistant", h("span", {}, h("span", { class: "spin" }), " analyzing…"));
    list.append(pending); scroll();
    try {
      const res = await api.sendChat(id, text);
      pending.remove(); addAssistant(res.reply);
      if (res.generated && res.generated.length) {
        const files = await api.generated(id).catch(() => []);
        res.generated.forEach((name) => {
          const f = files.find((x) => x.name === name);
          list.append(h("div", { class: "detail" },
            h("h3", { class: "mono", style: { fontSize: "13px" } }, "✚ " + name),
            h("pre", { class: "mono", style: { whiteSpace: "pre-wrap", fontSize: "12.5px", margin: 0 } }, f ? f.content : "")));
        });
        scroll();
      }
    } catch (e) {
      pending.remove(); addAssistant("⚠ " + e.message); toast(e.message, true);
    } finally { busy = false; sendBtn.disabled = false; }
  }

  const chip = (label, prefill) => h("span", { class: "pill", style: { cursor: "pointer" },
    onclick: () => { input.value = prefill; input.focus(); } }, label);
  const chips = h("div", { class: "filters" },
    chip("Explain a finding", "Explain finding "),
    chip("Why didn't you find…", "Why didn't the audit find "),
    chip("Generate tests for a CWE", "Generate a test suite that would catch "),
    chip("What did you deprioritize?", "What surfaces did you deprioritize, and why?"));
  const sendBtn = h("button", { class: "btn btn-primary", onclick: () => send() }, "Send");
  input.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); send(); } });

  api.getChat(id).then((msgs) => {
    if (!msgs.length) list.append(h("div", { class: "empty" },
      h("div", { class: "big" }, "Ask the analyst anything about this run"),
      "It has the full context + read-only repo. Try a suggestion below."));
    msgs.forEach((m) => (m.role === "user" ? addUser(m.content) : addAssistant(m.content)));
  }).catch((e) => toast(e.message, true));

  mount(root, list, chips, h("div", { class: "chat-inputrow" }, input, sendBtn),
    h("div", { class: "help" }, "Cmd/Ctrl+Enter to send. Chat uses the run's runner (free for mock runs), is read-only on the repo, and writes any generated tests to a separate folder — never the target."));
  return root;
}

// canonical archetype keys -> display labels (mirrors argo/archetype.py)
const ARCH_LABELS = {
  web_api_cms: "Web / API / CMS", plugin_extension: "Plugin / Extension / Mod",
  library_sdk: "Library / SDK / Framework", cli_desktop: "CLI / Desktop",
  agent_llm_mcp: "Agent / LLM / MCP", mobile: "Mobile", data_ml: "Data / ML pipeline",
  smart_contract: "Smart contract", firmware: "Firmware / Embedded",
  iac: "Infrastructure-as-code", other: "Other",
};

// ------------------------------------------------------------------ fixes panel (Phase 6)
function fixesPanel(id) {
  const root = h("div", {});
  const body = h("div", {});

  const verdict = (v) => {
    if (!v) return h("span", { class: "pill" }, "not verified");
    if (v.verified) return h("span", { class: "chip ok" }, "✓ verified — compiles, no new errors");
    const why = v.reason || (v.applied ? "build/verify failed" : "did not apply");
    return h("span", { class: "chip warn" }, "⚠ " + why);
  };

  function render(report, patches) {
    const byId = Object.fromEntries((patches || []).map((p) => [p.name, p.content]));
    if (!report || !report.fixes || !report.fixes.length)
      return mount(body, h("div", { class: "empty" },
        h("div", { class: "big" }, "No fixes proposed yet"),
        "Generate proposed patches for the confirmed findings. Each is verified on an isolated copy — the target repo is never modified."));
    const head = h("div", { class: "banner info" },
      `${report.patched} patch(es) proposed · ${report.verified}/${report.patched} verified (apply + compile + no new errors). Detection-only: these are proposals for a maintainer, never auto-applied or submitted.`);
    const cards = report.fixes.map((f) => {
      const diff = f.patch ? byId[f.patch] : null;
      return h("div", { class: "detail" },
        h("div", { class: "row", style: { justifyContent: "space-between", alignItems: "center" } },
          h("h3", { class: "mono", style: { fontSize: "13px", margin: 0 } }, `${f.finding_id} — ${f.title || ""}`),
          verdict(f.verify)),
        f.primary_file ? h("div", { class: "rid" }, f.primary_file) : null,
        diff ? h("pre", { class: "mono diff", style: { whiteSpace: "pre-wrap", fontSize: "12.5px", marginTop: "8px" } }, diff)
             : h("div", { class: "help" }, "No patch produced for this finding."),
        f.verify && f.verify.new_errors && f.verify.new_errors.length
          ? h("div", { class: "help", style: { color: "var(--danger, #e0556b)" } },
              "Introduced errors: " + f.verify.new_errors.join(" · "))
          : null);
    });
    mount(body, head, ...cards);
  }

  async function load(generate) {
    mount(body, h("div", { class: "skeleton", style: { height: "100px" } }));
    try {
      if (generate) { genBtn.disabled = true; genBtn.textContent = "Generating + verifying…"; }
      const report = generate ? await api.generateFixes(id, { verify: true })
                              : await api.getFixes(id);
      const patches = await api.patches(id).catch(() => []);
      render(report, patches);
    } catch (e) {
      mount(body, h("div", { class: "empty" }, e.message));
    } finally {
      genBtn.disabled = false; genBtn.textContent = "Propose & verify fixes";
    }
  }

  const genBtn = h("button", { class: "btn btn-primary", onclick: () => load(true) }, "Propose & verify fixes");
  mount(root,
    h("div", { class: "row", style: { justifyContent: "space-between", alignItems: "center", marginBottom: "10px" } },
      h("div", { class: "help", style: { margin: 0 } },
        "Proposes a root-cause patch per confirmed finding and verifies each on an isolated copy (applies? compiles? no new errors?). Uses this run's runner — free for mock runs."),
      genBtn),
    body);
  load(false);
  return root;
}

// ------------------------------------------------------------------ knowledge view
function knowledgeView() {
  const LABELS = { ...ARCH_LABELS, general: "General (always-applicable)" };
  const host = h("div", {}, h("div", { class: "skeleton", style: { height: "140px" } }));
  api.knowledge().then((idx) => {
    const cards = Object.entries(idx).map(([k, items]) => h("div", { class: "card" },
      h("h2", {}, LABELS[k] || k),
      h("div", { class: "kgrid" }, ...(items || []).map((it) => h("div", { class: "krow" },
        h("span", { class: "pill" }, it.cwe || ""),
        h("div", {}, h("div", { class: "kname" }, it.name || ""),
          it.note ? h("div", { class: "knote" }, it.note) : null))))));
    mount(host, ...cards);
  }).catch((e) => mount(host, h("div", { class: "empty" }, e.message)));
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Vulnerability index"),
      h("p", {}, "The bug classes that most often hide real findings, by software archetype. This curated index is injected into recon as reference context — the agent still classifies the target and discovers on its own.")),
    host);
}

// ------------------------------------------------------------------ costs view
function costsView() {
  const usd = (n) => "$" + Number(n || 0).toFixed(4);
  const kv = (k, v) => h("div", { class: "acard" }, h("div", { class: "k" }, k), h("div", { class: "v" }, String(v)));
  const dataTable = (headers, rows) => rows.length
    ? h("table", { class: "findings" },
        h("thead", {}, h("tr", {}, ...headers.map((x) => h("th", {}, x)))),
        h("tbody", {}, ...rows.map((r) => h("tr", {}, ...r.map((c, i) =>
          h("td", { class: i === 0 ? "floc" : "" }, String(c)))))))
    : h("div", { class: "empty" }, "No data yet — run a real (headless) audit to populate this.");
  const cardOf = (title, body) => h("div", { class: "card" }, h("h2", {}, title),
    h("div", { style: { marginTop: "12px" } }, body));

  const host = h("div", {}, h("div", { class: "skeleton", style: { height: "120px" } }));
  Promise.all([api.costs(), api.models().catch(() => null)]).then(([c, mm]) => {
    const t = c.totals;
    const head = h("div", { class: "artifacts" },
      kv("Avg / run", usd(t.avg_cost_per_run)), kv("Total spent", usd(t.cost_usd)),
      kv("Runs", t.runs), kv("LLM calls", t.calls));
    const cheapest = c.cheapest_model_per_1k_output
      ? h("div", { class: "banner info", style: { marginTop: "16px", marginBottom: "4px" } },
          h("span", {}, "💡"),
          h("span", {}, "Most cost-effective by output tokens: ", h("strong", {}, c.cheapest_model_per_1k_output)))
      : null;
    const models = dataTable(["Model", "Calls", "Cost", "$/call", "$/1k out", "%"],
      c.by_model.map((m) => [m.model, m.calls, usd(m.cost_usd), usd(m.avg_cost_per_call),
        m.cost_per_1k_output == null ? "—" : usd(m.cost_per_1k_output), m.pct_of_total + "%"]));
    const stages = dataTable(["Stage", "Calls", "Cost", "$/call", "% of total"],
      c.by_stage.map((s) => [s.stage, s.calls, usd(s.cost_usd), usd(s.avg_cost_per_call), s.pct_of_total + "%"]));
    const runs = dataTable(["Run", "Calls", "Cost"],
      c.recent_runs.map((r) => [r.run_id, r.calls, usd(r.cost_usd)]));
    const archCard = (c.by_archetype && c.by_archetype.length)
      ? cardOf("By archetype — cost per software type", dataTable(
          ["Archetype", "Runs", "Calls", "Cost", "Avg / run"],
          c.by_archetype.map((a) => [a.label || a.archetype, a.runs, a.calls,
            usd(a.cost_usd), usd(a.avg_cost_per_run)])))
      : null;
    let pricingCard = null;
    if (mm) {
      const backends = h("div", { class: "banner info" }, "Backends: ",
        ...(mm.backends || []).map((b, i) => h("span", {}, (i ? " · " : ""),
          h("strong", {}, b.label), ` — cost: ${b.cost}` + (b.default ? ` (default ${b.default})` : ""))));
      const priceTbl = (mm.pricing && mm.pricing.length)
        ? dataTable(["Model", "$ / 1M input", "$ / 1M output"],
            mm.pricing.map((p) => [p.model, "$" + p.input_per_mtok, "$" + p.output_per_mtok]))
        : h("div", { class: "help" }, "No price table.");
      pricingCard = cardOf("Model pricing & backends", h("div", {}, backends,
        h("div", { class: "help", style: { margin: "8px 0" } },
          "Claude Code reports real USD per call. Codex (OpenAI / OSS) reports tokens, so its cost is ESTIMATED from this table (local/open-source models ≈ $0)."),
        priceTbl));
    }
    mount(host, head, cheapest, cardOf("By model", models),
      cardOf("By stage — where the money goes", stages), archCard, cardOf("Recent runs", runs),
      pricingCard);
  }).catch((e) => mount(host, h("div", { class: "empty" }, e.message)));

  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Costs"),
      h("p", {}, "Observed economics from your local ledger — real per-call costs, not estimates. This data lives only on this machine (the ledger is git-ignored, served on localhost); it is never bundled with the app or shared. Mock runs are free ($0); figures populate as you do real (headless) runs. This also feeds the budget hint in “Let the pipeline choose”.")),
    host);
}

// ------------------------------------------------------------------ benchmarks view (Phase 7)
function benchmarkView() {
  const pct = (n) => (Number(n || 0) * 100).toFixed(1) + "%";
  const kv = (k, v) => h("div", { class: "acard" }, h("div", { class: "k" }, k), h("div", { class: "v" }, String(v)));
  const table = (headers, rows) => h("table", { class: "findings" },
    h("thead", {}, h("tr", {}, ...headers.map((x) => h("th", {}, x)))),
    h("tbody", {}, ...rows.map((r) => h("tr", {}, ...r.map((c, i) =>
      h("td", { class: i === 0 ? "floc" : "" }, String(c)))))));
  const cardOf = (title, body) => h("div", { class: "card" }, h("h2", {}, title),
    h("div", { style: { marginTop: "12px" } }, body));
  const prf = (m) => [pct(m.precision), pct(m.recall), pct(m.f1)];

  const host = h("div", {}, h("div", { class: "skeleton", style: { height: "120px" } }));
  Promise.all([api.benchmark().catch(() => null), api.benchmarkAb().catch(() => null)]).then(([rep, ab]) => {
    if (!rep) return mount(host, h("div", { class: "empty" },
      h("div", { class: "big" }, "No benchmark report yet"),
      h("div", {}, "Run a suite from the CLI: "),
      h("pre", { class: "mono", style: { marginTop: "8px" } }, "argo bench --suite benchmarks --runner mock"),
      h("div", { class: "help" }, "Headless measures real model quality (costs money); mock checks the harness for free.")));
    const t = rep.totals;
    const head = h("div", { class: "artifacts" },
      kv("Precision", pct(t.precision)), kv("Recall", pct(t.recall)),
      kv("F1", pct(t.f1)), kv("Cases", t.cases));
    const counts = h("div", { class: "banner info" },
      `Suite “${rep.suite}” · TP ${t.tp} · FP ${t.fp} · FN ${t.fn}. Labels are treated as exhaustive: an unmatched reported finding is a false positive.`);
    const patch = rep.patch_quality
      ? h("div", { class: "banner info" }, `Patch quality (Phase 6): ${rep.patch_quality.verified} / ${rep.patch_quality.patched} proposed fixes verified (${pct(rep.patch_quality.verified_rate)}).`)
      : null;
    const cases = cardOf("Per case", table(["Case", "Archetype", "P", "R", "F1", "Missed", "Spurious"],
      rep.cases.map((c) => [c.name, ARCH_LABELS[c.archetype] || c.archetype || "—",
        pct(c.precision), pct(c.recall), pct(c.f1),
        (c.missed || []).join(", ") || "—", (c.spurious || []).join(", ") || "—"])));
    const byArch = cardOf("By archetype", table(["Archetype", "P", "R", "F1", "TP", "FP", "FN"],
      Object.entries(rep.by_archetype).map(([k, m]) => [ARCH_LABELS[k] || k, ...prf(m), m.tp, m.fp, m.fn])));
    const byCwe = cardOf("By CWE", table(["CWE", "P", "R", "F1", "TP", "FP", "FN"],
      Object.entries(rep.by_cwe).map(([k, m]) => [k, ...prf(m), m.tp, m.fp, m.fn])));
    let abCard = null;
    if (ab && ab.delta_b_minus_a) {
      const d = ab.delta_b_minus_a;
      const sign = (n) => (n > 0 ? "+" : "") + (n * 100).toFixed(1) + "pp";
      abCard = cardOf(`A/B — audit model ${ab.audit_model_b} (B) vs default (A)`,
        table(["Metric", "A", "B", "Δ (B−A)"],
          [["Precision", pct(ab.a.totals.precision), pct(ab.b.totals.precision), sign(d.precision)],
           ["Recall", pct(ab.a.totals.recall), pct(ab.b.totals.recall), sign(d.recall)],
           ["F1", pct(ab.a.totals.f1), pct(ab.b.totals.f1), sign(d.f1)]]));
    }
    mount(host, head, counts, patch, cases, byArch, byCwe, abCard);
  }).catch((e) => mount(host, h("div", { class: "empty" }, e.message)));

  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Benchmarks"),
      h("p", {}, "Findings quality — precision / recall / F1 against labeled suites, sliced by archetype and CWE. Generated by ", h("code", {}, "argo bench"), "; this page is read-only.")),
    host);
}

function escapeHtml(s) { return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
