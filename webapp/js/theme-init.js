// Set the theme before first paint (kept out of index.html: the CSP forbids inline scripts).
(function () {
  try {
    var t = localStorage.getItem("theme");
    if (t !== "light" && t !== "dark")
      t = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", t);
  } catch (e) { document.documentElement.setAttribute("data-theme", "light"); }
})();
