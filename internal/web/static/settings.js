// Settings: the save bar turns "dirty" when any field differs from the
// loaded values; Discard resets the form, a successful save makes the
// saved values the new baseline. The Maintenance group is not compared.
(function () {
  'use strict';
  var form = document.getElementById('sform');
  if (!form) return;
  var bar = document.getElementById('savebar');

  function fields() {
    return Array.prototype.filter.call(form.querySelectorAll('input, select, textarea'), function (e) { return e.name; });
  }
  function initial(e) {
    if (e.tagName === 'SELECT') {
      for (var i = 0; i < e.options.length; i++) if (e.options[i].defaultSelected) return e.options[i].value;
      return e.options.length ? e.options[0].value : '';
    }
    if (e.type === 'checkbox') return String(e.defaultChecked);
    return e.defaultValue;
  }
  function current(e) { return e.type === 'checkbox' ? String(e.checked) : e.value; }
  function dirty() {
    var d = fields().some(function (e) { return current(e).replace(/\r\n/g, '\n') !== initial(e).replace(/\r\n/g, '\n'); });
    bar.classList.toggle('dirty', d);
  }
  // A successful save: the current values become the defaults Discard
  // resets to.
  function commit() {
    fields().forEach(function (e) {
      if (e.tagName === 'SELECT') { Array.prototype.forEach.call(e.options, function (o) { o.defaultSelected = o.selected; }); }
      else if (e.type === 'checkbox') e.defaultChecked = e.checked;
      else e.defaultValue = e.value;
    });
    dirty();
  }

  form.addEventListener('input', dirty);
  form.addEventListener('change', dirty);
  document.getElementById('discard').addEventListener('click', function () { form.reset(); dirty(); });
  document.body.addEventListener('htmx:afterRequest', function (e) {
    if (e.detail.elt === form && e.detail.successful) commit();
    if (e.detail.elt && e.detail.elt.dataset && e.detail.elt.dataset.act === 'flush') e.detail.elt.closest('.danger').classList.remove('arm');
  });

  // Inline confirm for the danger zone.
  form.addEventListener('click', function (ev) {
    var a = ev.target.closest('[data-act]');
    if (!a) return;
    if (a.dataset.act === 'arm') a.parentNode.classList.add('arm');
    if (a.dataset.act === 'disarm') a.closest('.danger').classList.remove('arm');
  });
  // Browsers restore edited values on back/forward navigation.
  window.addEventListener('pageshow', dirty);
  dirty();
})();
