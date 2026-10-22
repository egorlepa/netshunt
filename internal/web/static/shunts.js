// Shunts page: client-side search, expand state, drag-and-drop reordering,
// the optimistic toggle and the row flash. Every change goes to the server
// through htmx (or fetch for the order); this file only keeps the page in
// step with the responses.
(function () {
  'use strict';
  var page = document.getElementById('shunts-page');
  if (!page) return;
  var q = document.getElementById('q');
  var expandBtn = document.getElementById('expand-all');
  var open = new Set(); // names of expanded rows, survives list re-renders
  var allOpen = false;

  function list() { return document.getElementById('shunt-list'); }
  function rows() {
    var l = list();
    return l ? Array.prototype.filter.call(l.children, function (el) { return el.classList.contains('row'); }) : [];
  }
  function esc(s) { return s.replace(/[&<>]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]; }); }
  function hl(s, term) {
    if (!term) return esc(s);
    var i = s.toLowerCase().indexOf(term);
    if (i < 0) return esc(s);
    return esc(s.slice(0, i)) + '<mark>' + esc(s.slice(i, i + term.length)) + '</mark>' + esc(s.slice(i + term.length));
  }
  function fmt(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ' '); }
  function term() { return q.value.trim().toLowerCase(); }
  function toast(message, type) { htmx.trigger(document.body, 'showToast', { message: message, type: type || 'success' }); }
  function flash(row) { row.classList.remove('flash'); void row.offsetWidth; row.classList.add('flash'); }

  // Entries of manual shunts are in the DOM and searchable; geosite chips
  // are loaded lazily and only filtered inside their own panel.
  function entriesHit(row, t) {
    if (!t) return false;
    var chips = row.querySelectorAll('.chips:not(.ro) .chip');
    for (var i = 0; i < chips.length; i++) {
      if (chips[i].dataset.v.toLowerCase().indexOf(t) >= 0) return true;
    }
    return false;
  }

  function filterEntries(row, t) {
    t = (t || '').trim().toLowerCase();
    var chips = row.querySelectorAll('.chip'), n = 0;
    chips.forEach(function (c) {
      var v = c.dataset.v, hit = !t || v.toLowerCase().indexOf(t) >= 0;
      c.hidden = !hit;
      if (hit) n++;
      c.firstElementChild.innerHTML = t && hit ? hl(v, t).replace(/<mark>/g, '<em>').replace(/<\/mark>/g, '</em>') : esc(v);
    });
    var ec = row.querySelector('[data-role=ecount]');
    if (ec) ec.textContent = t ? n + ' of ' + fmt(chips.length) : '';
  }

  // An open row's entry filter takes the global search term when the term
  // matches its entries, and lets go of it when the search moves on.
  function syncFilter(row, t) {
    var ef = row.querySelector('[data-act=efilter]');
    if (!ef) return;
    if (t && entriesHit(row, t)) {
      ef.value = t;
      ef.dataset.inherited = '1';
      filterEntries(row, t);
    } else if (ef.dataset.inherited) {
      ef.value = '';
      delete ef.dataset.inherited;
      filterEntries(row, '');
    }
  }

  function setOpen(row, on) {
    row.classList.toggle('open', on);
    if (on) open.add(row.dataset.name); else open.delete(row.dataset.name);
    if (on) syncFilter(row, term());
  }

  // refresh re-applies the search and recomputes the strip and positions.
  function refresh(fromSearch) {
    var t = term(), all = rows(), shown = 0, on = 0, entries = 0;
    all.forEach(function (row, i) {
      var name = row.dataset.name || '', desc = row.dataset.desc || '', src = row.dataset.source || '';
      var hit = !t || name.toLowerCase().indexOf(t) >= 0 || desc.toLowerCase().indexOf(t) >= 0 ||
        src.toLowerCase().indexOf(t) >= 0 || entriesHit(row, t);
      row.classList.toggle('hidden', !hit);
      if (hit) shown++;
      if (row.classList.contains('on')) on++;
      var c = row.querySelector('.head .count');
      entries += c ? +c.dataset.n || 0 : 0;
      row.querySelector('.name .t').innerHTML = hl(name, t);
      var d = row.querySelector('.head .desc');
      d.innerHTML = desc ? hl(desc, t) : (d.classList.contains('src') ? hl(src, t) : '');
      var pos = row.querySelector('[data-role=pos]');
      if (pos) pos.textContent = (i + 1) + ' of ' + all.length;
      if (fromSearch && row.classList.contains('open')) syncFilter(row, t);
    });
    document.getElementById('n-on').textContent = on;
    document.getElementById('n-all').textContent = all.length;
    document.getElementById('n-entries').textContent = fmt(entries);
    document.getElementById('n-match').hidden = !t;
    document.getElementById('n-match-v').textContent = shown;
    var nothing = all.length > 0 && shown === 0;
    document.getElementById('empty').hidden = !nothing;
    if (list()) list().classList.toggle('none', nothing);
  }
  var refreshTimer = null;
  function scheduleRefresh() {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(function () { refresh(false); }, 0);
  }

  function toggleForm(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var show = el.hidden;
    page.querySelectorAll('.sp-form').forEach(function (f) { f.hidden = true; });
    el.hidden = !show;
    if (show) {
      var f = el.querySelector('input, textarea');
      if (f) f.focus();
    }
  }

  function autosize(ta) {
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight + 2, 200) + 'px';
  }

  page.addEventListener('click', function (ev) {
    var fb = ev.target.closest('[data-form]');
    if (fb) { toggleForm(fb.dataset.form); return; }
    var row = ev.target.closest('.row');
    if (!row) return;
    var actEl = ev.target.closest('[data-act]'), act = actEl ? actEl.dataset.act : '';
    if (act === 'tg') return; // the checkbox change does the work
    if (act === 'drag') { ev.preventDefault(); return; }
    var head = ev.target.closest('.head');
    if (head && head.parentNode === row) { setOpen(row, !row.classList.contains('open')); return; }
    if (act === 'arm') { actEl.parentNode.classList.add('arm'); return; }
    if (act === 'disarm') { actEl.closest('.danger').classList.remove('arm'); return; }
  });

  // Optimistic toggle: the switch and the row state flip at once; the swap
  // of the server's toggle confirms it, a failed request reverts it.
  page.addEventListener('change', function (ev) {
    if (!ev.target.matches('.tg input')) return;
    var row = ev.target.closest('.row');
    ev.target.closest('.tg').classList.add('pending');
    row.classList.toggle('on', ev.target.checked);
    refresh(false);
  });

  page.addEventListener('input', function (ev) {
    var t = ev.target;
    if (t === q) { refresh(true); return; }
    if (t.dataset.act === 'efilter') {
      delete t.dataset.inherited;
      filterEntries(t.closest('.row'), t.value);
      return;
    }
    if (t.matches('.add textarea')) autosize(t);
  });

  page.addEventListener('keydown', function (ev) {
    var t = ev.target, act = t.dataset ? t.dataset.act : '';
    if (act === 'rename' || act === 'redesc') {
      if (ev.key === 'Enter') { ev.preventDefault(); t.blur(); }
      if (ev.key === 'Escape') { t.value = t.defaultValue; t.blur(); }
      return;
    }
    if (ev.key === 'Enter' && !ev.shiftKey && t.matches('.add textarea')) {
      ev.preventDefault();
      if (t.value.trim()) t.form.requestSubmit();
    }
  });

  expandBtn.addEventListener('click', function () {
    allOpen = !allOpen;
    rows().forEach(function (row) { if (!row.classList.contains('hidden')) setOpen(row, allOpen); });
    var label = allOpen ? 'Collapse all' : 'Expand all';
    expandBtn.querySelector('.btn-text').textContent = label;
    expandBtn.title = label;
  });

  document.addEventListener('keydown', function (ev) {
    var a = document.activeElement;
    if (ev.key === '/' && a !== q && !/INPUT|TEXTAREA|SELECT/.test(a.tagName) && !a.isContentEditable) {
      ev.preventDefault(); q.focus(); q.select();
    }
    if (ev.key === 'Escape' && a === q) { q.value = ''; refresh(true); q.blur(); }
  });

  // htmx: keep expand state, the optimistic toggle and the strip in step
  // with the swapped markup.
  var refocusAdd = null;
  document.body.addEventListener('htmx:beforeRequest', function (e) {
    var elt = e.detail.elt;
    if (elt.matches && elt.matches('.add')) refocusAdd = elt.closest('.row').dataset.name;
  });
  document.body.addEventListener('htmx:beforeSwap', function (e) {
    // A deleted row is swapped for nothing; no settle event names it.
    if (e.detail.target && e.detail.target.classList && e.detail.target.classList.contains('row')) scheduleRefresh();
  });
  document.body.addEventListener('htmx:afterRequest', function (e) {
    var elt = e.detail.elt;
    if (!e.detail.successful && elt && elt.matches) {
      if (elt.matches('.tg input') && elt.isConnected) {
        elt.checked = !elt.checked;
        elt.closest('.tg').classList.remove('pending');
        elt.closest('.row').classList.toggle('on', elt.checked);
      } else if (elt.matches('.meta form')) {
        elt.reset();
      }
    }
    scheduleRefresh();
  });
  document.body.addEventListener('htmx:afterSettle', function (e) {
    var elt = e.detail.elt;
    if (!elt || !elt.closest || !page.contains(elt)) return;
    if (elt.id === 'shunt-list') {
      rows().forEach(function (row) { if (open.has(row.dataset.name)) row.classList.add('open'); });
      refresh(true);
      return;
    }
    var row = elt.classList.contains('row') ? elt : elt.closest('.row');
    if (!row) return;
    if (row === elt) {
      if (row.classList.contains('open')) open.add(row.dataset.name);
      syncFilter(row, term());
      if (refocusAdd === row.dataset.name) {
        refocusAdd = null;
        var ta = row.querySelector('.add textarea');
        if (ta) ta.focus();
      }
    } else if (elt.classList.contains('tg')) {
      row.classList.toggle('on', elt.querySelector('input').checked);
    } else if (elt.classList.contains('chips')) {
      var ef = row.querySelector('[data-act=efilter]');
      filterEntries(row, ef ? ef.value : '');
      if (ef && elt.classList.contains('ro')) ef.placeholder = 'Filter ' + fmt(elt.querySelectorAll('.chip').length) + ' entries';
    }
    flash(row);
    refresh(false);
  });

  // Drag and drop (pointer events, vertical list): the ghost follows the
  // pointer, the row itself is the empty slot, the other rows slide (FLIP).
  var drag = null, swallowClick = false;
  // The click the browser fires after a drag lands on a row head and would toggle it.
  page.addEventListener('click', function (ev) {
    if (swallowClick) { ev.stopPropagation(); ev.preventDefault(); swallowClick = false; }
  }, true);
  page.addEventListener('pointerdown', function (ev) {
    var h = ev.target.closest('[data-act=drag]');
    if (!h || ev.button !== 0) return;
    ev.preventDefault();
    var row = h.closest('.row');
    if (row.classList.contains('open')) setOpen(row, false);
    var r = row.getBoundingClientRect();
    var ghost = document.createElement('div');
    ghost.className = 'sp sp-ghost';
    ghost.style.width = r.width + 'px';
    var inner = document.createElement('div');
    inner.className = 'row' + (row.classList.contains('on') ? ' on' : '') + (row.classList.contains('nodata') ? ' nodata' : '');
    var head = row.querySelector('.head').cloneNode(true);
    head.querySelectorAll('[id]').forEach(function (el) { el.removeAttribute('id'); });
    inner.appendChild(head);
    ghost.appendChild(inner);
    document.body.appendChild(ghost);
    drag = { row: row, ghost: ghost, dx: ev.clientX - r.left, dy: ev.clientY - r.top, from: rows().indexOf(row) };
    row.classList.add('dragging');
    document.body.classList.add('sp-dragging');
    place(ev);
  });
  function place(ev) { drag.ghost.style.transform = 'translate(' + (ev.clientX - drag.dx) + 'px,' + (ev.clientY - drag.dy) + 'px)'; }
  document.addEventListener('pointermove', function (ev) {
    if (!drag) return;
    place(ev);
    var top = page.querySelector('.toolbar').getBoundingClientRect().bottom + 24;
    if (ev.clientY < top) window.scrollBy(0, -10); else if (ev.clientY > innerHeight - 56) window.scrollBy(0, 10);
    var l = list();
    var others = rows().filter(function (el) { return el !== drag.row && !el.classList.contains('hidden'); });
    var target = null, before = true;
    for (var i = 0; i < others.length; i++) {
      var rr = others[i].getBoundingClientRect();
      if (ev.clientY < rr.top + rr.height / 2) { target = others[i]; before = true; break; }
      target = others[i]; before = false;
    }
    if (!target) return;
    var ref = before ? target : target.nextSibling;
    if (ref === drag.row || drag.row.nextSibling === ref) return;
    // FLIP: remember where every row is, move the slot, then slide the rows
    // from their old place into the new one.
    var first = others.map(function (el) { return el.getBoundingClientRect().top; });
    l.insertBefore(drag.row, ref);
    others.forEach(function (el, k) {
      var d = first[k] - el.getBoundingClientRect().top;
      if (!d) return;
      el.classList.remove('shift');
      el.style.transform = 'translateY(' + d + 'px)';
      void el.offsetWidth;
      el.classList.add('shift');
      el.style.transform = '';
    });
  });
  function endDrag() {
    if (!drag) return;
    var d = drag;
    drag = null;
    swallowClick = true;
    setTimeout(function () { swallowClick = false; }, 0);
    d.row.classList.remove('dragging');
    document.body.classList.remove('sp-dragging');
    d.ghost.remove();
    rows().forEach(function (el) { el.classList.remove('shift'); el.style.transform = ''; });
    var all = rows(), to = all.indexOf(d.row);
    if (to === d.from) return;
    refresh(false);
    saveOrder(all, d.row, to);
  }
  document.addEventListener('pointerup', endDrag);
  document.addEventListener('pointercancel', endDrag);

  function saveOrder(all, moved, to) {
    var body = new URLSearchParams();
    all.forEach(function (row) { body.append('names', row.dataset.name); });
    fetch('/shunts/order', { method: 'PUT', body: body }).then(function (res) {
      if (res.ok) {
        flash(moved);
        toast('Order saved: ' + moved.dataset.name + ' moved to #' + (to + 1));
        return;
      }
      var msg = 'Saving the order failed (HTTP ' + res.status + ')';
      try { msg = JSON.parse(res.headers.get('HX-Trigger')).showToast.message || msg; } catch (e) { /* keep the generic message */ }
      throw new Error(msg);
    }).catch(function (err) {
      toast(err.message || 'Saving the order failed', 'error');
      htmx.ajax('GET', '/shunts', { target: '#shunt-list', select: '#shunt-list', swap: 'outerHTML' });
    });
  }

  refresh(true);
})();
