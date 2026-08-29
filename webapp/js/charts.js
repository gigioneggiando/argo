// Dependency-free, theme-aware chart primitives for the dashboard.
// Inline SVG only (no runtime CDN, matching Argo's vendored ethos); colors are
// CSS custom properties so every chart re-themes automatically with the app.
//
// Forms follow the data's job (see dataviz method): parts-of-whole -> donut with
// a status/label legend; magnitude comparison -> single-hue horizontal bars;
// a single headline -> stat tile. Text always wears ink tokens, never a series
// color; identity is carried by the legend + labels, never color alone.

const SVGNS = "http://www.w3.org/2000/svg";

function s(tag, attrs = {}, ...kids) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2).toLowerCase(), v);
    else e.setAttribute(k, String(v));
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}
function el(tag, cls, ...kids) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
}

// ---- shared hover tooltip (one node, reused) --------------------------------
let tip;
function tooltip() {
  if (!tip) { tip = el("div", "chart-tip"); tip.hidden = true; document.body.append(tip); }
  return tip;
}
function showTip(html, ev) {
  const t = tooltip();
  t.innerHTML = html; t.hidden = false;
  const pad = 12, w = t.offsetWidth, h = t.offsetHeight;
  let x = ev.clientX + pad, y = ev.clientY + pad;
  if (x + w > innerWidth - 8) x = ev.clientX - w - pad;
  if (y + h > innerHeight - 8) y = ev.clientY - h - pad;
  t.style.left = x + "px"; t.style.top = y + "px";
}
function hideTip() { if (tip) tip.hidden = true; }

// ---- severity / state -> color-var mapping ----------------------------------
export const SEV_COLOR = {
  Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)",
  Low: "var(--low)", Informational: "var(--info)",
};
export const STATE_COLOR = {
  completed: "var(--ok)", failed: "var(--danger)", cancelled: "var(--warn)",
  running: "var(--primary)", starting: "var(--primary)", queued: "var(--text-faint)",
};

const fmtInt = (n) => Number(n).toLocaleString();
const pct = (v, total) => total ? Math.round((v / total) * 100) : 0;

// ---- donut (annular sectors, real geometry, 2px surface gaps) ---------------
// data: [{label, value, color}]. opts: {centerTop, centerBottom, size, thickness}
export function donut(data, opts = {}) {
  const items = data.filter((d) => d.value > 0);
  const total = items.reduce((a, d) => a + d.value, 0);
  const size = opts.size || 168, thickness = opts.thickness || 26;
  const cx = size / 2, cy = size / 2, R = size / 2 - 2, r = R - thickness;

  const svg = s("svg", { viewBox: `0 0 ${size} ${size}`, class: "donut-svg", role: "img" });
  const pt = (rad, a) => [cx + rad * Math.cos(a), cy + rad * Math.sin(a)];
  const segHover = (d) => ({
    onmousemove: (ev) => showTip(`<b>${d.label}</b><br>${fmtInt(d.value)} · ${pct(d.value, total)}%`, ev),
    onmouseenter: (ev) => { ev.target.classList.add("hot"); svg.classList.add("dim"); },
    onmouseleave: (ev) => { ev.target.classList.remove("hot"); svg.classList.remove("dim"); hideTip(); },
  });

  if (!total) {
    svg.append(s("circle", { cx, cy, r: (R + r) / 2, fill: "none", stroke: "var(--border)",
      "stroke-width": thickness }));
  } else if (items.length === 1) {
    // a single slice is a full ring — a zero-length arc path draws nothing.
    svg.append(s("circle", { cx, cy, r: (R + r) / 2, fill: "none", stroke: items[0].color,
      "stroke-width": thickness, class: "donut-seg", ...segHover(items[0]) }));
  } else {
    const gap = 0.018; // small angular breath; the 2px surface stroke does the rest
    let a = -Math.PI / 2; // start at 12 o'clock
    items.forEach((d) => {
      const frac = d.value / total;
      let a0 = a + gap / 2;
      let a1 = a + frac * 2 * Math.PI - gap / 2;
      if (a1 < a0) a1 = a0;
      a += frac * 2 * Math.PI;
      const [x0, y0] = pt(R, a0), [x1, y1] = pt(R, a1);
      const [x2, y2] = pt(r, a1), [x3, y3] = pt(r, a0);
      const large = a1 - a0 > Math.PI ? 1 : 0;
      svg.append(s("path", {
        d: `M ${x0} ${y0} A ${R} ${R} 0 ${large} 1 ${x1} ${y1} L ${x2} ${y2} A ${r} ${r} 0 ${large} 0 ${x3} ${y3} Z`,
        fill: d.color, class: "donut-seg", ...segHover(d),
      }));
    });
  }

  const center = el("div", "donut-center",
    el("div", "donut-total", opts.centerTop != null ? opts.centerTop : fmtInt(total)),
    opts.centerBottom ? el("div", "donut-sub", opts.centerBottom) : null);

  const legend = el("div", "chart-legend",
    ...items.map((d) => el("div", "leg-item",
      Object.assign(el("span", "leg-dot"), { style: `background:${d.color}` }),
      el("span", "leg-label", d.label),
      el("span", "leg-val", `${fmtInt(d.value)}`))));

  return el("div", "donut-wrap", el("div", "donut-plot", svg, center), (items.length && !opts.noLegend) ? legend : null);
}

// ---- horizontal magnitude bars (single hue) ---------------------------------
// data: [{label, value}]. opts: {color, unit, max, fmt}
export function barsH(data, opts = {}) {
  const rows = data.slice();
  const max = opts.max || Math.max(1, ...rows.map((d) => d.value));
  const color = opts.color || "var(--primary)";
  const fmt = opts.fmt || fmtInt;
  const wrap = el("div", "bars");
  if (!rows.length) return el("div", "chart-empty", "No data yet");
  rows.forEach((d) => {
    const w = Math.max(2, (d.value / max) * 100);
    const fill = el("div", "bar-fill");
    Object.assign(fill.style, { width: w + "%", background: color });
    const track = el("div", "bar-track", fill);
    const row = el("div", "bar-row",
      el("div", "bar-label", d.label),
      track,
      el("div", "bar-val", fmt(d.value) + (opts.unit || "")));
    row.addEventListener("mousemove", (ev) => showTip(`<b>${d.label}</b><br>${fmt(d.value)}${opts.unit || ""}`, ev));
    row.addEventListener("mouseleave", hideTip);
    wrap.append(row);
  });
  return wrap;
}

// ---- stat tile (hero number) ------------------------------------------------
// opts: {label, value, sub, accent}
export function statTile({ label, value, sub, accent }) {
  return el("div", "stat-tile" + (accent ? " accent" : ""),
    el("div", "stat-label", label),
    el("div", "stat-value", value),
    sub ? el("div", "stat-sub", sub) : null);
}

// ---- card shell -------------------------------------------------------------
export function chartCard(title, body, sub) {
  return el("div", "chart-card",
    el("div", "chart-head", el("h3", "chart-title", title), sub ? el("span", "chart-sub", sub) : null),
    body);
}
