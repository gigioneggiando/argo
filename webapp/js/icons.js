// Minimal monochrome SVG icon set (feather-style, currentColor) — replaces the
// emoji glyphs so the UI reads as a tool, not an AI demo. One factory, inline
// SVG, no dependency.

const NS = "http://www.w3.org/2000/svg";

const ICONS = {
  alert: [["path", { d: "M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" }],
          ["line", { x1: 12, y1: 9, x2: 12, y2: 13 }], ["line", { x1: 12, y1: 17, x2: 12.01, y2: 17 }]],
  upload: [["path", { d: "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" }],
           ["polyline", { points: "17 8 12 3 7 8" }], ["line", { x1: 12, y1: 3, x2: 12, y2: 15 }]],
  check: [["polyline", { points: "20 6 9 17 4 12" }]],
  plus: [["line", { x1: 12, y1: 5, x2: 12, y2: 19 }], ["line", { x1: 5, y1: 12, x2: 19, y2: 12 }]],
  play: [["polygon", { points: "7 4 20 12 7 20 7 4", fill: "currentColor", stroke: "none" }]],
  sun: [["circle", { cx: 12, cy: 12, r: 4 }],
        ["path", { d: "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" }]],
  moon: [["path", { d: "M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" }]],
  sparkle: [["path", { d: "M12 3l1.6 4.9a2 2 0 0 0 1.3 1.3L20 11l-5.1 1.8a2 2 0 0 0-1.3 1.3L12 19l-1.6-4.9a2 2 0 0 0-1.3-1.3L4 11l5.1-1.8a2 2 0 0 0 1.3-1.3L12 3z", fill: "currentColor", stroke: "none" }]],
  bolt: [["polygon", { points: "13 2 3 14 12 14 11 22 21 10 12 10 13 2", fill: "currentColor", stroke: "none" }]],
};

export function icon(name, size = 16) {
  const e = document.createElementNS(NS, "svg");
  e.setAttribute("viewBox", "0 0 24 24");
  e.setAttribute("width", size); e.setAttribute("height", size);
  e.setAttribute("fill", "none"); e.setAttribute("stroke", "currentColor");
  e.setAttribute("stroke-width", "1.7"); e.setAttribute("stroke-linecap", "round"); e.setAttribute("stroke-linejoin", "round");
  e.setAttribute("aria-hidden", "true"); e.setAttribute("class", "icon");
  for (const [tag, attrs] of (ICONS[name] || [])) {
    const c = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) c.setAttribute(k, String(v));
    e.append(c);
  }
  return e;
}
