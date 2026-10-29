/* Interface behaviour: quick jump, keyboard, table sort and filters, copy, side panel, sign-in hints.
   Plain script, no dependencies, no inline handlers (CSP script-src 'self'). Every feature is optional:
   without this file every page still works through ordinary links and forms. */
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  var store = {
    get: function (k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { window.localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  };
  var typing = function (el) {
    return el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
  };

  /* ---------------------------------------------------------------- toast */
  var toastTimer = null;
  function toast(text) {
    var t = $(".toast");
    if (!t) { t = document.createElement("div"); t.className = "toast"; t.setAttribute("role", "status"); document.body.appendChild(t); }
    t.textContent = text;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 1600);
  }

  /* ---------------------------------------------------------------- density */
  if (store.get("density") === "compact") document.body.classList.add("compact");
  $$("[data-density]").forEach(function (b) {
    var sync = function () { b.textContent = document.body.classList.contains("compact") ? "Обычные строки" : "Плотные строки"; };
    sync();
    b.addEventListener("click", function () {
      document.body.classList.toggle("compact");
      store.set("density", document.body.classList.contains("compact") ? "compact" : "normal");
      sync();
    });
  });

  /* ---------------------------------------------------------------- menus: close on outside click / Escape */
  document.addEventListener("click", function (e) {
    $$("details.scope[open], details.user[open]").forEach(function (d) { if (!d.contains(e.target)) d.open = false; });
  });

  /* ---------------------------------------------------------------- quick jump */
  var jump = $("#jump");
  var jumpInput = jump && $("input", jump);
  var jumpItems = jump ? $$("li", jump) : [];
  var jumpNone = jump && $(".none", jump);
  var jumpSel = 0;
  function visibleJump() { return jumpItems.filter(function (li) { return !li.hidden; }); }
  function markJump() {
    var vis = visibleJump();
    jumpItems.forEach(function (li) { li.classList.remove("on"); });
    if (vis.length) {
      jumpSel = Math.max(0, Math.min(jumpSel, vis.length - 1));
      vis[jumpSel].classList.add("on");
      vis[jumpSel].scrollIntoView({ block: "nearest" });
    }
    if (jumpNone) jumpNone.hidden = vis.length > 0;
  }
  function filterJump() {
    var q = jumpInput.value.trim().toLowerCase();
    var words = q.split(/\s+/).filter(Boolean);
    jumpItems.forEach(function (li) {
      var hay = li.getAttribute("data-t");
      li.hidden = !words.every(function (w) { return hay.indexOf(w) !== -1; });
    });
    jumpSel = 0;
    markJump();
  }
  function openJump() {
    if (!jump || typeof jump.showModal !== "function") return;
    if (!jump.open) jump.showModal();
    jumpInput.value = "";
    filterJump();
    jumpInput.focus();
  }
  if (jump) {
    jumpItems.forEach(function (li) { li.setAttribute("data-t", li.textContent.toLowerCase()); });
    jumpInput.addEventListener("input", filterJump);
    jumpInput.addEventListener("keydown", function (e) {
      var vis = visibleJump();
      if (e.key === "ArrowDown") { jumpSel = Math.min(jumpSel + 1, vis.length - 1); markJump(); e.preventDefault(); }
      else if (e.key === "ArrowUp") { jumpSel = Math.max(jumpSel - 1, 0); markJump(); e.preventDefault(); }
      else if (e.key === "Enter") { var a = vis[jumpSel] && $("a", vis[jumpSel]); if (a) { window.location.href = a.href; } e.preventDefault(); }
    });
    jump.addEventListener("click", function (e) { if (e.target === jump) jump.close(); });
  }
  $$("[data-jump]").forEach(function (b) { b.addEventListener("click", openJump); });

  /* ---------------------------------------------------------------- keys help */
  var keys = $("#keys");
  if (keys) keys.addEventListener("click", function (e) { if (e.target === keys || e.target.hasAttribute("data-close")) keys.close(); });

  /* ---------------------------------------------------------------- side panel (drawer) */
  var drawer = $("#drawer");
  var veil = $("#veil");
  var lastFocus = null;
  function closeDrawer() {
    if (!drawer || drawer.hidden) return;
    drawer.hidden = true; veil.hidden = true;
    $$(".t tr.on").forEach(function (tr) { tr.classList.remove("on"); });
    if (lastFocus) lastFocus.focus();
  }
  function openDrawer(a) {
    lastFocus = a;
    var body = $(".drawer-b", drawer);
    $(".drawer-title", drawer).textContent = a.getAttribute("data-drawer") || "";
    $(".drawer-full", drawer).href = a.href;
    body.textContent = "Загрузка…";
    drawer.hidden = false; veil.hidden = false;
    var tr = a.closest("tr");
    $$(".t tr.on").forEach(function (x) { x.classList.remove("on"); });
    if (tr) tr.classList.add("on");
    fetch(a.href, { headers: { "HX-Request": "true" }, credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.text(); })
      .then(function (html) { body.innerHTML = html; $(".drawer-close", drawer).focus(); })
      .catch(function () { body.textContent = "Не удалось загрузить. Откройте страницу целиком."; });
  }
  if (drawer) {
    $(".drawer-close", drawer).addEventListener("click", closeDrawer);
    veil.addEventListener("click", closeDrawer);
    document.addEventListener("click", function (e) {
      var a = e.target.closest && e.target.closest("a[data-drawer]");
      if (!a || e.ctrlKey || e.metaKey || e.shiftKey || e.button !== 0) return;
      e.preventDefault();
      openDrawer(a);
    });
  }

  /* ---------------------------------------------------------------- tables: sort */
  function cellValue(tr, idx) {
    var td = tr.children[idx];
    if (!td) return "";
    return td.hasAttribute("data-v") ? td.getAttribute("data-v") : td.textContent.trim();
  }
  $$(".t th[data-sort]").forEach(function (th) {
    th.setAttribute("tabindex", "0");
    var sort = function () {
      var table = th.closest("table");
      var tbody = table.tBodies[0];
      var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
      var asc = th.getAttribute("aria-sort") !== "ascending";
      $$("th[aria-sort]", table).forEach(function (x) { x.removeAttribute("aria-sort"); });
      th.setAttribute("aria-sort", asc ? "ascending" : "descending");
      var num = th.getAttribute("data-sort") === "num";
      var rows = $$("tr", tbody).filter(function (tr) { return !tr.querySelector("td.empty"); });
      rows.sort(function (a, b) {
        var x = cellValue(a, idx), y = cellValue(b, idx);
        var r = num ? (parseFloat(x) || 0) - (parseFloat(y) || 0) : x.localeCompare(y, "ru", { numeric: true });
        return asc ? r : -r;
      });
      rows.forEach(function (tr) { tbody.appendChild(tr); });
    };
    th.addEventListener("click", sort);
    th.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { sort(); e.preventDefault(); } });
  });

  /* ---------------------------------------------------------------- tables: filters (status counters + text) */
  function params() { return new URLSearchParams(window.location.search); }
  function setParam(k, v) {
    var p = params();
    if (v) p.set(k, v); else p.delete(k);
    var qs = p.toString();
    window.history.replaceState(null, "", window.location.pathname + (qs ? "?" + qs : "") + window.location.hash);
  }
  function applyFilters(table) {
    var seg = $(".seg[data-for='" + table.id + "']");
    var input = $("input.filter[data-for='" + table.id + "']");
    var f = seg ? (seg.getAttribute("data-value") || "all") : "all";
    var q = input ? input.value.trim().toLowerCase() : "";
    var shown = 0;
    $$("tbody tr", table).forEach(function (tr) {
      if (tr.classList.contains("group") || tr.querySelector("td.empty")) return;
      var s = (tr.getAttribute("data-s") || "").split(" ");
      var ok = (f === "all" || s.indexOf(f) !== -1) && (!q || tr.textContent.toLowerCase().indexOf(q) !== -1);
      tr.hidden = !ok;
      if (ok) shown += 1;
    });
    // group headers follow their rows
    var group = null, any = false;
    $$("tbody tr", table).forEach(function (tr) {
      if (tr.classList.contains("group")) { if (group) group.hidden = !any; group = tr; any = false; }
      else if (!tr.hidden) any = true;
    });
    if (group) group.hidden = !any;
    var none = $("[data-none='" + table.id + "']");
    if (none) none.hidden = shown > 0;
  }
  $$(".seg[data-for]").forEach(function (seg) {
    var table = document.getElementById(seg.getAttribute("data-for"));
    if (!table) return;
    var key = seg.getAttribute("data-param") || "f";
    var initial = params().get(key) || (params().get("q") ? "all" : seg.getAttribute("data-default")) || "all";
    var buttons = $$("button[data-f]", seg);
    var select = function (v, push) {
      if (!buttons.some(function (b) { return b.getAttribute("data-f") === v; })) v = "all";
      seg.setAttribute("data-value", v);
      buttons.forEach(function (b) { b.setAttribute("aria-pressed", b.getAttribute("data-f") === v ? "true" : "false"); });
      if (push) setParam(key, v === (seg.getAttribute("data-default") || "all") ? "" : v);
      applyFilters(table);
    };
    buttons.forEach(function (b) { b.addEventListener("click", function () { select(b.getAttribute("data-f"), true); }); });
    seg.hidden = false;
    select(initial, false);
  });
  $$("input.filter[data-for]").forEach(function (input) {
    var table = document.getElementById(input.getAttribute("data-for"));
    if (!table) return;
    input.hidden = false;
    var q = params().get("q");
    if (q) input.value = q;
    input.addEventListener("input", function () { setParam("q", input.value.trim()); applyFilters(table); });
    applyFilters(table);
  });

  /* ---------------------------------------------------------------- tables: row keys j/k + Enter */
  // The active table is the one the user last clicked in; before any click, the page's main table
  // (marked data-keys) or the first table with links.
  var rowTable = null;
  var rowIdx = -1;
  function rowsOf(table) {
    return table ? $$("tbody tr", table).filter(function (tr) { return !tr.hidden && !tr.classList.contains("group") && tr.querySelector("a"); }) : [];
  }
  function activeTable() {
    if (!rowTable || !document.contains(rowTable)) {
      rowTable = $(".t[data-keys]") || $$(".t").filter(function (t) { return rowsOf(t).length; })[0] || null;
      rowIdx = -1;
    }
    return rowTable;
  }
  function rows() { return rowsOf(activeTable()); }
  document.addEventListener("click", function (e) {
    var tr = e.target.closest && e.target.closest(".t tbody tr");
    if (!tr) return;
    var table = tr.closest(".t");
    if (table !== rowTable) { $$("tr.on", rowTable || document).forEach(function (x) { x.classList.remove("on"); }); rowTable = table; }
    rowIdx = rowsOf(table).indexOf(tr);
  });
  function moveRow(d) {
    var r = rows();
    if (!r.length) return;
    rowIdx = Math.max(0, Math.min(rowIdx + d, r.length - 1));
    r.forEach(function (tr) { tr.classList.remove("on"); });
    r[rowIdx].classList.add("on");
    r[rowIdx].scrollIntoView({ block: "nearest" });
  }

  /* ---------------------------------------------------------------- copy */
  document.addEventListener("click", function (e) {
    var el = e.target.closest && e.target.closest(".copy");
    if (!el || !navigator.clipboard) return;
    var text = el.getAttribute("data-copy") || el.textContent.trim();
    navigator.clipboard.writeText(text).then(function () { toast("Скопировано: " + (text.length > 40 ? text.slice(0, 40) + "…" : text)); });
  });
  $$(".copy").forEach(function (el) { if (!el.title) el.title = "Нажмите, чтобы скопировать"; });

  /* ---------------------------------------------------------------- keyboard */
  var gPending = false, gTimer = null;
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { closeDrawer(); return; }
    if (e.ctrlKey || e.metaKey || e.altKey || typing(document.activeElement)) return;
    if (document.querySelector("dialog[open]")) return;
    if (gPending) {
      gPending = false; clearTimeout(gTimer);
      var target = document.body.getAttribute("data-go-" + e.key);
      if (target) { window.location.href = target; e.preventDefault(); }
      return;
    }
    if (e.key === "/") { openJump(); e.preventDefault(); }
    else if (e.key === "?") { if (keys) keys.showModal(); e.preventDefault(); }
    else if (e.key === "g") { gPending = true; gTimer = setTimeout(function () { gPending = false; }, 1200); }
    else if (e.key === "j") { moveRow(1); }
    else if (e.key === "k") { moveRow(-1); }
    else if (e.key === "Enter" && activeTable() && rowIdx >= 0) {
      var r = rows()[rowIdx];
      var a = r && $("a", r);
      if (a) { a.click(); e.preventDefault(); }
    }
  });

  /* ---------------------------------------------------------------- sign-in: reveal, Caps Lock, keyboard layout */
  $$(".pw").forEach(function (box) {
    var input = $("input", box), btn = $(".reveal", box);
    btn.hidden = false;
    btn.addEventListener("click", function () {
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "скрыть" : "показать";
      btn.setAttribute("aria-pressed", show ? "true" : "false");
      input.focus();
    });
  });
  var caps = $("#caps");
  $$("input[data-caps]").forEach(function (input) {
    var check = function (e) { if (caps && e.getModifierState) caps.hidden = !e.getModifierState("CapsLock"); };
    input.addEventListener("keydown", check);
    input.addEventListener("keyup", check);
  });
  var layout = $("#layout");
  $$("input[data-latin]").forEach(function (input) {
    input.addEventListener("input", function () { if (layout) layout.hidden = !/[а-яё]/i.test(input.value); });
  });
})();
