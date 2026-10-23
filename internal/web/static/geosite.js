// Geosite page: client-side search over the category names ("/" focuses,
// Esc clears), the "only used" filter, and rows that expand into a lazily
// loaded preview of their domains. The content is re-rendered by "Update
// now", so everything is looked up on use.
(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }
  function esc(s) { return s.replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function hl(s, t) {
    if (!t) return esc(s);
    var i = s.toLowerCase().indexOf(t);
    if (i < 0) return esc(s);
    return esc(s.slice(0, i)) + '<mark>' + esc(s.slice(i, i + t.length)) + '</mark>' + esc(s.slice(i + t.length));
  }

  function fmt(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, '<i class="k"></i>'); }

  function render() {
    var list = $('glist'), q = $('gq'), used = $('gused');
    if (!list || !q) return;
    var t = q.value.trim().toLowerCase(), only = used && used.checked, shown = 0, rows = list.children;
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i], name = r.dataset.name || '', u = r.dataset.used || '';
      var hit = (!t || name.toLowerCase().indexOf(t) >= 0 || (u && u.toLowerCase().indexOf(t) >= 0)) && (!only || u);
      r.classList.toggle('hidden', !hit);
      if (hit) shown++;
      var el = r.querySelector('.name .t');
      if (t || el.dataset.hl) { el.innerHTML = hl(name, t); el.dataset.hl = t ? '1' : ''; }
    }
    $('gempty').hidden = shown > 0;
    list.classList.toggle('none', shown === 0);
    $('gcount').innerHTML = (t || only) ? '<b>' + fmt(shown) + '</b> of ' + fmt(rows.length) : '';
  }

  document.addEventListener('input', function (ev) { if (ev.target.id === 'gq') render(); });
  document.addEventListener('change', function (ev) { if (ev.target.id === 'gused') render(); });

  document.addEventListener('click', function (ev) {
    var head = ev.target.closest('#glist .head');
    if (!head) return;
    if (ev.target.closest('a, button')) return; // Add as shunt / In shunts
    var row = head.parentNode, panel = row.querySelector('.panel');
    var open = !row.classList.contains('open');
    row.classList.toggle('open', open);
    if (open && !panel.dataset.loaded) {
      panel.dataset.loaded = '1';
      panel.innerHTML = '<div class="chips"><span class="none">Loading domains... <span class="spinner"></span></span></div>';
      htmx.ajax('GET', '/geosite/categories/' + encodeURIComponent(row.dataset.name) + '/entries', { target: panel, swap: 'innerHTML' })
        .catch(function () { delete panel.dataset.loaded; });
    }
  });

  document.addEventListener('keydown', function (ev) {
    var q = $('gq'), a = document.activeElement;
    if (!q) return;
    if (ev.key === '/' && a !== q && !/INPUT|TEXTAREA|SELECT/.test(a.tagName) && !a.isContentEditable) {
      ev.preventDefault(); q.focus(); q.select();
    }
    if (ev.key === 'Escape' && a === q) { q.value = ''; render(); q.blur(); }
  });

  // A swapped row (added as shunt) or a re-rendered page keeps the filter.
  document.body.addEventListener('htmx:afterSettle', function (e) {
    var elt = e.detail.elt;
    if (elt && (elt.id === 'geosite-content' || (elt.classList && elt.classList.contains('row')))) render();
  });
  window.addEventListener('pageshow', render);
  render();
})();
