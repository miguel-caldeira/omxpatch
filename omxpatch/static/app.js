// OMXPatch - comportamento mínimo (sem scripts inline, compatível com CSP)
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });
  var all = document.getElementById("select-all");
  if (all) all.addEventListener("change", function () {
    document.querySelectorAll("input[name=ids]").forEach(function (c) { c.checked = all.checked; });
  });
  document.querySelectorAll("select[data-autosubmit]").forEach(function (s) {
    s.addEventListener("change", function () { s.form.submit(); });
  });
  var kind = document.getElementById("kind");
  function toggleApi() {
    var el = document.getElementById("api-spec");
    if (el && kind) el.hidden = kind.value !== "api";
  }
  if (kind) { kind.addEventListener("change", toggleApi); toggleApi(); }
  var refresh = document.querySelector("[data-refresh]");
  if (refresh) setTimeout(function () { location.reload(); }, parseInt(refresh.dataset.refresh, 10) * 1000);
  document.querySelectorAll("[data-print]").forEach(function (b) { b.addEventListener("click", function () { window.print(); }); });
});

// Timeline do dashboard: cursor vertical + tooltip por período (rato e teclado/toque)
document.addEventListener("DOMContentLoaded", function () {
  var svg = document.querySelector("svg[data-timeline]");
  if (!svg) return;
  var wrap = svg.parentNode, tip = wrap.querySelector(".tooltip"), cross = svg.querySelector(".crosshair");
  var series = [["found", "Encontradas", 1], ["assigned", "Encaminhadas", 2], ["remediated", "Tratadas", 3], ["closed", "Fechadas", 4]];
  function show(rect) {
    var cx = parseFloat(rect.dataset.cx);
    cross.setAttribute("x1", cx); cross.setAttribute("x2", cx); cross.hidden = false;
    tip.textContent = "";
    var h = document.createElement("b"); h.textContent = rect.dataset.label; tip.appendChild(h);
    series.forEach(function (s) {
      var row = document.createElement("div"); row.className = "row";
      var name = document.createElement("span"); var key = document.createElement("i");
      key.className = "key key-" + s[2]; name.appendChild(key); name.appendChild(document.createTextNode(s[1]));
      var val = document.createElement("b"); val.textContent = rect.dataset[s[0]] || "0";
      row.appendChild(name); row.appendChild(val); tip.appendChild(row);
    });
    tip.hidden = false;
    var box = svg.getBoundingClientRect(), scale = box.width / svg.viewBox.baseVal.width;
    var left = cx * scale + 12;
    if (left + tip.offsetWidth > box.width) left = cx * scale - tip.offsetWidth - 12;
    tip.style.left = Math.max(0, left) + "px"; tip.style.top = "8px";
  }
  function hide() { tip.hidden = true; cross.hidden = true; }
  svg.querySelectorAll(".hit").forEach(function (r) {
    r.setAttribute("tabindex", "0");
    r.addEventListener("mouseenter", function () { show(r); });
    r.addEventListener("focus", function () { show(r); });
    r.addEventListener("touchstart", function () { show(r); }, { passive: true });
  });
  svg.addEventListener("mouseleave", hide);
});

// Integrações: só os campos do produto escolhido são enviados
document.querySelectorAll('input[name="kind"]').forEach(function (r) {
  r.addEventListener("change", function () {
    r.form.querySelectorAll("[data-kind]").forEach(function (el) { el.disabled = el.dataset.kind !== r.value; });
  });
});

// Tooltip genérico dos gráficos (rato, teclado e toque): elementos com data-tip
(function () {
  var tip = document.querySelector(".viz-tip");
  if (!tip) return;
  function show(el, x, y) {
    tip.textContent = el.getAttribute("data-tip"); tip.hidden = false;
    var w = tip.offsetWidth, left = x + 14;
    if (left + w > window.innerWidth - 8) left = x - w - 14;
    tip.style.left = Math.max(8, left) + "px"; tip.style.top = (y + 14) + "px";
  }
  document.querySelectorAll("[data-tip]").forEach(function (el) {
    el.addEventListener("mousemove", function (e) { show(el, e.clientX, e.clientY); });
    el.addEventListener("focus", function () { var r = el.getBoundingClientRect(); show(el, r.left + r.width / 2, r.top); });
    el.addEventListener("touchstart", function () { var r = el.getBoundingClientRect(); show(el, r.left, r.top); }, { passive: true });
    el.addEventListener("mouseleave", function () { tip.hidden = true; });
    el.addEventListener("blur", function () { tip.hidden = true; });
  });
})();

// Confirmação em botões individuais (ex.: "Repor por omissão")
document.querySelectorAll("button[data-confirm]").forEach(function (b) {
  b.addEventListener("click", function (e) { if (!window.confirm(b.getAttribute("data-confirm"))) e.preventDefault(); });
});

// Aviso de licença: abre como janela modal (foco preso no aviso até ser fechado)
document.querySelectorAll("dialog.license-notice[open]").forEach(function (d) {
  if (typeof d.showModal === "function") { d.close(); d.showModal(); }
});
