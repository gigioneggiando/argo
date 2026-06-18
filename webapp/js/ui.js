// Tiny DOM helpers + reusable components. No framework, just a hyperscript factory.

export function h(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "html") e.innerHTML = v;
    else if (k === "for") e.htmlFor = v;
    else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "style" && typeof v === "object") Object.assign(e.style, v);
    else if (k in e) { try { e[k] = v; } catch (_) { e.setAttribute(k, v); } }
    else e.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    e.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return e;
}

export const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
export const mount = (el, ...nodes) => { clear(el); el.append(...nodes.flat().filter(Boolean)); return el; };

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"];
export const sevRank = (s) => ({ Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 })[s] || 0;
export const confRank = (c) => ({ Confirmed: 4, High: 3, Medium: 2, Low: 1 })[c] || 0;

export const effSev = (f) => (f.validation && f.validation.validated_severity) || f.severity;
export const effConf = (f) => (f.validation && f.validation.validated_confidence) || f.confidence;
export const verdict = (f) => (f.validation && f.validation.verdict) || "";

export function sevPill(s) {
  return h("span", { class: `pill sev-${s}` }, h("span", { class: "dot" }), s);
}
export function verdictPill(v) {
  if (!v) return h("span", { class: "pill" }, "—");
  const label = v.replace(/_/g, " ");
  return h("span", { class: `pill vd-${v}` }, h("span", { class: "dot" }), label);
}
export function stateChip(state) {
  const spin = state === "running" || state === "starting";
  return h("span", { class: `state-chip state-${state}` },
    spin ? h("span", { class: "spin" }) : null, state);
}
export const costChip = (c) => h("span", { class: "cost-chip" }, "$" + Number(c || 0).toFixed(4));

export function toast(msg, isErr = false) {
  const wrap = document.getElementById("toasts");
  const t = h("div", { class: "toast" + (isErr ? " err" : "") }, msg);
  wrap.append(t);
  setTimeout(() => { t.style.transition = "opacity .3s"; t.style.opacity = "0"; setTimeout(() => t.remove(), 300); }, 4200);
}

export const primaryRef = (f) => (f.affected && f.affected[0]) || "";
