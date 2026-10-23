// Dashboard: polls /api/activity every 2 s while "live" is on and the tab
// is visible; prepends new matched answers to the feed (60 rows kept, new
// ones flash), redraws the last-hour bars and the strip.
(function () {
  'use strict';
  var root = document.getElementById('dashboard');
  if (!root) return;
  var live = document.getElementById('live');
  var feed = document.getElementById('feed');
  var feedn = document.getElementById('feedn');
  var ROWS = 60, EVERY = 2000;
  var seq = 0, first = true, timer = null, busy = false;

  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function fmt(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, '<i class="k"></i>'); }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  // Queries from the router itself (Keenetic's connectivity checks, local tools) arrive from loopback.
  function clientLabel(c) { if (!c) return '-'; return (c === '127.0.0.1' || c === '::1') ? 'router' : c; }
  function hms(iso) { var d = new Date(iso); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); }

  // The part of the name the rule does not cover (the "www." before a
  // suffix rule) is dimmed.
  function name(e) {
    var d = e.d, n = e.dim || 0;
    return (n > 0 ? '<em>' + esc(d.slice(0, n)) + '</em>' : '') + esc(d.slice(n));
  }

  function row(e, fresh) {
    var el = document.createElement('div');
    el.className = 'fr' + (fresh ? ' new' : '');
    var title = e.q ? e.q + ' via ' + e.d : e.d;
    el.innerHTML = '<span class="t">' + hms(e.t) + '</span><span class="c">' + esc(clientLabel(e.c)) + '</span>' +
      '<span class="d" title="' + esc(title) + '">' + name(e) + '</span><span class="badge" title="' + esc(e.s) + '">' + esc(e.s) + '</span>';
    return el;
  }

  function bars(id, list) {
    var el = document.getElementById(id);
    if (!list.length) { el.innerHTML = '<div class="empty">Nothing in the last hour.</div>'; return; }
    var max = list[0].n || 1;
    el.innerHTML = list.map(function (r) {
      return '<div class="br"><span class="n" title="' + esc(r.name) + '">' + esc(clientLabel(r.name)) + '</span><span class="b"><i style="width:' +
        Math.max(1, Math.round(100 * r.n / max)) + '%"></i></span><span class="v">' + fmt(r.n) + '</span></div>';
    }).join('');
  }

  function strip(st) {
    root.querySelectorAll('#dash-strip [data-k]').forEach(function (b) {
      var v = st[b.dataset.k];
      if (v !== undefined) b.innerHTML = fmt(v);
    });
  }

  function apply(data) {
    if (data.seq < seq) { // daemon restarted: start the feed over
      feed.innerHTML = '';
      first = true;
    }
    var entries = data.entries || [];
    if (entries.length) {
      var empty = feed.querySelector('.empty');
      if (empty) empty.remove();
      var frag = document.createDocumentFragment();
      entries.forEach(function (e) { frag.appendChild(row(e, !first)); });
      feed.insertBefore(frag, feed.firstChild);
      while (feed.children.length > ROWS) feed.removeChild(feed.lastChild);
    }
    seq = data.seq;
    first = false;
    var shown = feed.querySelectorAll('.fr').length;
    feedn.innerHTML = data.held ? 'last ' + shown + ' of ' + fmt(data.held) : '';
    bars('bars', data.shunts || []);
    bars('clients', data.clients || []);
    strip(data.stats || {});
  }

  function poll() {
    if (busy || !live.checked || document.visibilityState !== 'visible') return;
    busy = true;
    fetch('/api/activity?since=' + seq, { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(apply)
      .catch(function () { /* next tick retries */ })
      .then(function () { busy = false; });
  }

  function start() { if (!timer) timer = setInterval(poll, EVERY); poll(); }
  function stop() { clearInterval(timer); timer = null; }

  live.addEventListener('change', function () { if (live.checked) start(); else stop(); });
  document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'visible' && live.checked) poll(); });
  start();
})();
