// Diagnostics: the "N of N passed" strip and the Run checks button follow
// the check rows as they resolve; the log box filters the loaded lines by
// text and level, and toggles wrapping.
(function () {
  'use strict';
  var root = document.getElementById('diagnostics');
  if (!root) return;
  var lq = document.getElementById('lq'), lb = document.getElementById('logbody');
  var wrap = document.getElementById('lwrap'), run = document.getElementById('runchk');
  var level = '', started = Date.now(), wasRunning = true;

  function toast(message, type) { htmx.trigger(document.body, 'showToast', { message: message, type: type || 'success' }); }
  function esc(s) { return s.replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function hl(s, t) {
    if (!t) return esc(s);
    var out = '', low = s.toLowerCase(), i = 0, j;
    while ((j = low.indexOf(t, i)) >= 0) { out += esc(s.slice(i, j)) + '<mark>' + esc(s.slice(j, j + t.length)) + '</mark>'; i = j + t.length; }
    return out + esc(s.slice(i));
  }

  function checks() {
    var rows = root.querySelectorAll('#checks .row'), pass = 0, pending = 0;
    rows.forEach(function (r) {
      if (r.querySelector('.dot.spin')) pending++;
      else if (r.querySelector('.dot.on')) pass++;
    });
    document.getElementById('d-pass').textContent = pass;
    document.getElementById('d-total').textContent = rows.length;
    run.disabled = pending > 0;
    if (pending > 0) { if (!wasRunning) started = Date.now(); wasRunning = true; return; }
    if (wasRunning && rows.length) {
      wasRunning = false;
      var secs = ((Date.now() - started) / 1000).toFixed(1);
      toast(pass + ' of ' + rows.length + ' passed in ' + secs + ' s', pass === rows.length ? 'success' : 'error');
    }
  }

  // Text of a highlighted element, kept once so highlighting is redone
  // from the original.
  function orig(el) { if (el.dataset.o === undefined) el.dataset.o = el.textContent; return el.dataset.o; }

  function logs() {
    var t = lq.value.trim().toLowerCase(), shown = 0;
    var lines = lb.querySelectorAll('.ll');
    lines.forEach(function (l) {
      var hit = (!level || l.dataset.l === level) && (!t || (l.dataset.s || '').indexOf(t) >= 0);
      l.hidden = !hit;
      if (!hit) return;
      shown++;
      l.querySelectorAll('.m, .a .v').forEach(function (el) {
        if (t || el.dataset.h) { el.innerHTML = hl(orig(el), t); el.dataset.h = t ? '1' : ''; }
      });
    });
    var empty = document.getElementById('lempty');
    if (empty) empty.hidden = shown > 0 || !lines.length;
    lb.classList.toggle('wrap', wrap.checked);
  }

  lq.addEventListener('input', logs);
  wrap.addEventListener('change', logs);
  root.querySelectorAll('.lvl button').forEach(function (b) {
    b.addEventListener('click', function () {
      root.querySelectorAll('.lvl button').forEach(function (x) { x.classList.toggle('on', x === b); });
      level = b.dataset.l;
      logs();
    });
  });
  run.addEventListener('click', function () { started = Date.now(); wasRunning = true; });
  document.addEventListener('keydown', function (ev) {
    var a = document.activeElement;
    if (ev.key === '/' && a !== lq && !/INPUT|TEXTAREA|SELECT/.test(a.tagName) && !a.isContentEditable) { ev.preventDefault(); lq.focus(); lq.select(); }
    if (ev.key === 'Escape' && a === lq) { lq.value = ''; logs(); lq.blur(); }
  });
  document.body.addEventListener('htmx:afterSettle', function (e) {
    var elt = e.detail.elt;
    if (!elt || !root.contains(elt) && !elt.id) return;
    if (elt.id === 'logbody' || elt === lb) logs();
    else checks();
  });
  checks();
})();
