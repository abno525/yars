// Theme: an explicit choice lives in data-theme on <html> and in
// localStorage; without one the system setting applies. The account's saved
// theme (set on <html> by the server) wins over localStorage. Runs in
// <head>, so the theme is set before the page paints.
(function () {
  var root = document.documentElement;
  try {
    var server = root.getAttribute('data-theme');
    if (server === 'light' || server === 'dark') { localStorage.setItem('yars-theme', server); return; }
    // the account follows the system: a choice left in this browser is stale
    if (root.hasAttribute('data-theme-save')) { localStorage.removeItem('yars-theme'); return; }
    var t = localStorage.getItem('yars-theme');
    if (t === 'light' || t === 'dark') root.setAttribute('data-theme', t);
  } catch (e) { /* storage blocked: follow the server or the system */ }
})();

function yarsTheme() {
  var root = document.documentElement;
  var cur = root.getAttribute('data-theme');
  if (!cur) cur = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  var next = cur === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  try { localStorage.setItem('yars-theme', next); } catch (e) { /* not remembered */ }
  if (root.hasAttribute('data-theme-save') && window.fetch) {
    // the account remembers it too (same origin, so the CSRF check passes)
    fetch('/settings/theme', {method: 'POST', body: new URLSearchParams({theme: next}), credentials: 'same-origin'}).catch(function () {});
  }
}

// yarsListIdle tells whether the findings board may refresh itself: not
// while rows are picked or more rows were loaded (both would be lost).
function yarsListIdle() {
  var list = document.getElementById('findings');
  if (!list) return false;
  if (list.querySelector('input[name="id"]:checked')) return false;
  var shown = list.querySelectorAll('tbody tr[data-fid]').length;
  return shown <= Number(list.getAttribute('data-rows') || 0);
}

// yarsToast shows a short message in #toasts; click or wait to dismiss.
function yarsToast(text, err) {
  var box = document.getElementById('toasts');
  if (!box) return;
  var t = document.createElement('div');
  t.className = 'toast' + (err ? ' err' : '');
  t.setAttribute('role', err ? 'alert' : 'status');
  t.textContent = text;
  t.addEventListener('click', function () { t.remove(); });
  box.appendChild(t);
  while (box.children.length > 4) box.firstChild.remove();
  setTimeout(function () { t.remove(); }, err ? 8000 : 4000);
}

// Errors that htmx does not swap (403, 500, …) become visible as a toast.
document.addEventListener('htmx:responseError', function (evt) {
  var xhr = evt.detail.xhr;
  if (xhr && xhr.status === 401) { yarsExpired(); return; }
  var text = (xhr && xhr.responseText || '').trim();
  if (/^\s*</.test(text)) {
    // DOMParser runs no scripts or handlers; only the text is kept
    var doc = new DOMParser().parseFromString(text, 'text/html');
    text = (doc.body && doc.body.textContent || '').trim();
  }
  if (text.length > 300) text = text.slice(0, 300) + '…';
  yarsToast(text || ('Error ' + (xhr ? xhr.status : '')), true);
});
document.addEventListener('htmx:sendError', function () { yarsToast('Connection lost', true); });

// The export picker's head counts the ticked findings ("2 of 5"); the head
// comes before the table, so it is counted here rather than in CSS.
function yarsPickCount(panel) {
  var out = panel && panel.querySelector('.selof');
  if (!out) return;
  var n = panel.querySelectorAll('input[name="finding"]:checked').length;
  out.textContent = n + ' of ' + out.getAttribute('data-of');
}
document.addEventListener('change', function (evt) {
  if (evt.target.name === 'finding') yarsPickCount(evt.target.closest('.pickpanel'));
});
// boxes the browser restores itself (reload, back/forward) fire no change
function yarsPickCountAll() {
  document.querySelectorAll('.pickpanel').forEach(yarsPickCount);
}
document.addEventListener('DOMContentLoaded', yarsPickCountAll);
window.addEventListener('pageshow', yarsPickCountAll);

// A select marked data-choose acts on an explicit choice only: a click on
// an option, or Enter. Moving through the options with the keyboard
// changes the value without acting. Its form is submitted, or one with
// hx-trigger="yars:choose" is sent by htmx.
function yarsChoose(sel) {
  var form = sel.form;
  if (!form) return;
  if (form.hasAttribute('hx-post') || form.hasAttribute('hx-get')) htmx.trigger(form, 'yars:choose');
  else form.submit();
}
document.addEventListener('keydown', function (e) {
  var s = e.target;
  if (!s.matches || !s.matches('select[data-choose]')) return;
  if (e.key === 'Enter') {
    e.preventDefault();
    s.removeAttribute('data-keyed');
    yarsChoose(s);
  } else if (e.altKey || e.key === ' ' || e.key === 'F4') {
    // keys that open the list: an option picked there is a choice
    s.removeAttribute('data-keyed');
  } else if (e.key !== 'Tab' && e.key !== 'Shift') {
    // Tab leaves the flag to focusout, which restores the saved value
    s.setAttribute('data-keyed', '');
  }
});
// a value moved through with the keys and never chosen does not stay: on
// leaving the select it shows what the page holds again
document.addEventListener('focusout', function (e) {
  var s = e.target;
  if (!s.matches || !s.matches('select[data-choose]') || !s.hasAttribute('data-keyed')) return;
  s.removeAttribute('data-keyed');
  for (var i = 0; i < s.options.length; i++) {
    if (s.options[i].defaultSelected) { s.selectedIndex = i; return; }
  }
  s.selectedIndex = 0;
});
document.addEventListener('pointerdown', function (e) {
  var s = e.target.closest && e.target.closest('select[data-choose]');
  if (s) s.removeAttribute('data-keyed');
});
document.addEventListener('change', function (e) {
  var s = e.target;
  if (!s.matches || !s.matches('select[data-choose]')) return;
  if (s.hasAttribute('data-keyed')) return; // moved with the keys: not chosen yet
  yarsChoose(s);
});

// Radios marked data-choose (the retest result) act the same way: a click,
// Space or Enter chooses; the arrow keys move the selection without
// acting, and on leaving the group unchosen it shows the saved one again.
// The keyed flag sits on the radios' form (one per group); their change
// events never act.
var yarsArrows = ['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight'];
// A keyboard save reloads the page (the retest result feeds the workflow
// bar): the group's name is kept for the next page, which puts the focus
// back on its checked radio.
var yarsRadioFocus = 'yars-radio-focus';
document.addEventListener('DOMContentLoaded', function () {
  var name = null;
  try { name = sessionStorage.getItem(yarsRadioFocus); sessionStorage.removeItem(yarsRadioFocus); } catch (e) { return; }
  if (!name) return;
  var r = document.querySelector('input[type=radio][data-choose][name="' + name + '"]:checked');
  if (r) r.focus();
});
function yarsRadio(t) {
  return t && t.matches && t.matches('input[type=radio][data-choose]') ? t : null;
}
document.addEventListener('keydown', function (e) {
  var r = yarsRadio(e.target);
  if (!r || !r.form) return;
  if (e.key === ' ' || e.key === 'Enter') {
    // Space on the radio already checked by the arrows fires no change:
    // choose here, and keep the browser from choosing a second time
    e.preventDefault();
    r.checked = true;
    r.form.removeAttribute('data-keyed');
    try { sessionStorage.setItem(yarsRadioFocus, r.name); } catch (err) { /* focus not kept */ }
    yarsChoose(r);
  } else if (yarsArrows.indexOf(e.key) >= 0) {
    r.form.removeAttribute('data-pointer');
    r.form.setAttribute('data-keyed', '');
  }
});
// a click chooses, the one already checked included (after the arrows);
// the click browsers send for an arrow key has no pointer before it
document.addEventListener('pointerdown', function (e) {
  var l = e.target.closest && e.target.closest('label');
  var r = yarsRadio(e.target) || (l && yarsRadio(l.querySelector('input')));
  if (r && r.form) r.form.setAttribute('data-pointer', '');
});
document.addEventListener('click', function (e) {
  var r = yarsRadio(e.target);
  if (!r || !r.form || !r.form.hasAttribute('data-pointer')) return;
  r.form.removeAttribute('data-pointer');
  r.form.removeAttribute('data-keyed');
  yarsChoose(r);
});
document.addEventListener('focusout', function (e) {
  var r = yarsRadio(e.target);
  if (!r || !r.form || !r.form.hasAttribute('data-keyed')) return;
  if (e.relatedTarget && r.form.contains(e.relatedTarget)) return; // still in the group
  r.form.removeAttribute('data-keyed');
  r.form.querySelectorAll('input[type=radio][data-choose]').forEach(function (x) { x.checked = x.defaultChecked; });
});

// Login lockout: the alert counts down (m:ss) from the seconds the server
// gave (not the browser's clock); at 0 it goes and the form works again,
// without a reload. Another username is not locked: the form works for it.
function yarsLockout() {
  var box = document.querySelector('[data-lock-secs]');
  var form = document.querySelector('form[data-locked]');
  if (!box || !form) return;
  var end = performance.now() + 1000 * Number(box.getAttribute('data-lock-secs'));
  var name = box.getAttribute('data-lock-name');
  var left = box.querySelector('[data-lock-left]');
  var user = form.querySelector('input[name="username"]');
  var done = false;
  function locked(on) {
    box.hidden = !on;
    form.querySelectorAll('input[name="password"], button').forEach(function (el) { el.disabled = on; });
  }
  user.addEventListener('input', function () { if (!done) locked(user.value === name); });
  function tick() {
    var s = Math.max(0, Math.round((end - performance.now()) / 1000));
    left.textContent = Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
    if (s > 0) { setTimeout(tick, 1000); return; }
    done = true;
    locked(false);
    box.remove();
  }
  tick();
}
document.addEventListener('DOMContentLoaded', yarsLockout);
document.addEventListener('htmx:afterSettle', yarsPickCountAll);

document.addEventListener('click', function (evt) {
  var el = evt.target.closest && evt.target.closest('[data-theme-toggle], [data-copy], [data-check-all]');
  if (!el) return;
  if (el.hasAttribute('data-theme-toggle')) { yarsTheme(); return; }
  if (el.hasAttribute('data-check-all')) {
    // "Add everyone": tick every box of that name in the form
    var form = el.closest('form');
    if (form) form.querySelectorAll('input[type=checkbox][name="' + el.getAttribute('data-check-all') + '"]').forEach(function (c) { c.checked = true; });
    return;
  }
  var src = document.getElementById(el.getAttribute('data-copy'));
  if (!src || !navigator.clipboard) return;
  navigator.clipboard.writeText(src.textContent.trim()).then(function () { yarsToast('Copied'); });
});

// yarsComment points the chat composer at a section and focuses it.
function yarsComment(section) {
  var sel = document.getElementById('chat-section');
  var txt = document.getElementById('chat-text');
  if (!sel || !txt) return;
  sel.value = section;
  txt.focus();
  txt.scrollIntoView({block: 'center', behavior: 'smooth'});
}

// Comment buttons and confirm buttons are wired here (no inline handlers:
// the page's script policy allows none).
document.addEventListener('click', function (evt) {
  if (!evt.target.closest) return;
  var c = evt.target.closest('[data-comment]');
  if (c) { yarsComment(c.getAttribute('data-comment')); return; }
  var q = evt.target.closest('[data-confirm]');
  if (q && !window.confirm(q.getAttribute('data-confirm'))) evt.preventDefault();
});
// The findings list refreshes itself on a live event only while idle
// (nothing ticked, no extra rows loaded): see yarsListIdle.
document.addEventListener('htmx:beforeRequest', function (evt) {
  var el = evt.detail.elt;
  var ev = evt.detail.requestConfig && evt.detail.requestConfig.triggeringEvent;
  if (el && el.id === 'findings' && ev && String(ev.type).indexOf('sse:') === 0 && !yarsListIdle()) evt.preventDefault();
});
// The findings search box (#fq) keeps what is typed in it when the list it
// sits in is swapped: the answer echoes the search as it was sent (or a live
// refresh echoes the last one), and a letter typed since must not be lost.
// Restored at once after the swap (not after the settle delay, when the next
// key may already be in the new box); a text that differs from the answer's
// is searched again (the old box's pending search went with it).
var yarsFq = null, yarsFqAgain = false;
document.addEventListener('htmx:beforeSwap', function (evt) {
  var fq = document.getElementById('fq');
  yarsFq = (evt.detail.target && evt.detail.target.id === 'findings' && fq && fq === document.activeElement) ?
    {value: fq.value, start: fq.selectionStart, end: fq.selectionEnd} : null;
});
document.addEventListener('htmx:afterSwap', function () {
  var fq = document.getElementById('fq');
  var was = yarsFq;
  yarsFq = null;
  if (!was || !fq) return;
  if (fq.value !== was.value) { fq.value = was.value; yarsFqAgain = true; }
  if (document.activeElement !== fq) fq.focus();
  try { fq.setSelectionRange(was.start, was.end); } catch (e) {}
});
// the new box's trigger is wired once the swap settled: search the kept text
// (its "search" trigger; "input changed" took the kept text as unchanged)
document.addEventListener('htmx:afterSettle', function () {
  var fq = document.getElementById('fq');
  if (!yarsFqAgain || !fq) return;
  yarsFqAgain = false;
  fq.dispatchEvent(new Event('search', {bubbles: true}));
});
// Enter in a [data-enter] box sends it (yars:enter) instead of submitting
// the form; a click on a [data-rowclick] row opens it (yars:rowclick),
// except on a link inside it. htmx evaluates no trigger filters.
document.addEventListener('keydown', function (evt) {
  if (evt.key !== 'Enter' || !evt.target.matches || !evt.target.matches('[data-enter]')) return;
  evt.preventDefault();
  if (window.htmx) htmx.trigger(evt.target, 'yars:enter');
});
document.addEventListener('click', function (evt) {
  if (!evt.target.closest || evt.target.closest('a')) return;
  var row = evt.target.closest('[data-rowclick]');
  if (row && window.htmx) htmx.trigger(row, 'yars:rowclick');
});

// Live refreshes must never wipe a half-typed reply or reason: skip the
// background refresh of #chat-list or #workflow while a text box inside has
// focus or text, or the reviewer picker is open. (Posting a reply/resolve
// still swaps, because that request is a POST.)
document.addEventListener('htmx:beforeSwap', function (evt) {
  var t = evt.detail.target;
  if (!t || (t.id !== 'chat-list' && t.id !== 'workflow' && t.id !== 'checks') || evt.detail.requestConfig.verb !== 'get') return;
  var busy = Array.prototype.some.call(t.querySelectorAll('input[name=text], input[name=reason], textarea'), function (i) {
    return i.value !== '' || i === document.activeElement;
  }) || (t.id === 'workflow' && !!t.querySelector('details[open], .wfpanel:not([hidden])')) ||
    (t.id === 'checks' && !!t.querySelector('.dismissrow:not([hidden])'));
  if (busy) evt.detail.shouldSwap = false;
});

// Checks strip: the server opens it while a check runs or the author's
// draft has errors; a click on its head is the user's choice, kept for this
// finding in this tab and re-applied after live refreshes (never against a
// running check, which stays open).
function yarsChecksKey() { return 'yars-checks:' + location.pathname; }
function yarsChecksApply() {
  var d = document.getElementById('checks');
  if (!d || d.tagName !== 'DETAILS' || d.hasAttribute('data-running')) return;
  var want = null;
  try { want = sessionStorage.getItem(yarsChecksKey()); } catch (e) { return; }
  if (want === 'open') d.open = true;
  if (want === 'closed') d.open = false;
}
document.addEventListener('click', function (evt) {
  var s = evt.target.closest && evt.target.closest('#checks > summary');
  if (!s) return;
  // the click toggles after this handler: the state it leads to
  try { sessionStorage.setItem(yarsChecksKey(), s.parentNode.open ? 'closed' : 'open'); } catch (e) { /* not kept */ }
});
// D3: the bar's state ("2 errors to fix") opens the strip where they are
// listed, and that is kept as the user's choice
document.addEventListener('click', function (evt) {
  var b = evt.target.closest && evt.target.closest('[data-open-checks]');
  if (!b) return;
  var d = document.getElementById('checks');
  if (!d) return;
  d.open = true;
  try { sessionStorage.setItem(yarsChecksKey(), 'open'); } catch (e) { /* not kept */ }
  d.scrollIntoView({block: 'nearest'});
});
document.addEventListener('DOMContentLoaded', yarsChecksApply);
document.addEventListener('htmx:afterSwap', function (evt) {
  if (evt.detail.target && evt.detail.target.id === 'checks') yarsChecksApply();
});

// Team board: a live refresh (sse:…) waits while something is being typed
// or a menu is open there; the user's own clicks always swap.
document.addEventListener('htmx:beforeSwap', function (evt) {
  var t = evt.detail.target;
  var ev = evt.detail.requestConfig && evt.detail.requestConfig.triggeringEvent;
  if (!t || t.id !== 'board' || !ev || String(ev.type).indexOf('sse:') !== 0) return;
  var busy = Array.prototype.some.call(t.querySelectorAll('textarea, input:not([type=hidden]), select'), function (i) {
    return i === document.activeElement || (i.value !== undefined && i.defaultValue !== undefined && i.value !== i.defaultValue);
  }) || !!t.querySelector('details[open]');
  if (busy) evt.detail.shouldSwap = false;
});
// Quote request: a request block goes into the reply at the cursor.
document.addEventListener('click', function (evt) {
  var b = evt.target.closest && evt.target.closest('[data-quote]');
  if (!b) return;
  var ta = b.closest('form') && b.closest('form').querySelector('textarea[name=text]');
  if (!ta) return;
  var s = ta.selectionStart || 0, e = ta.selectionEnd || 0, v = ta.value, q = b.getAttribute('data-quote');
  var pre = s > 0 && v.charAt(s - 1) !== '\n' ? '\n' : '';
  ta.value = v.slice(0, s) + pre + q + v.slice(e);
  ta.selectionStart = ta.selectionEnd = s + pre.length + q.length;
  ta.focus();
});

/* ---------- findings list and director inbox: bulk state change ---------- */

// The bar counts the ticked rows, enables Set state and Assign reviewers
// only with a selection, and each Set state entry only when a ticked row
// can take it (the row's data-acts). Each table's select all ticks the
// pickable rows of that table only (the inbox has two).
function yarsBulkSync(form) {
  var picks = Array.prototype.slice.call(form.querySelectorAll('input[name=id]'));
  var on = picks.filter(function (c) { return c.checked; });
  var acts = {};
  picks.forEach(function (c) {
    var tr = c.closest('tr');
    if (!tr) return;
    tr.classList.toggle('sel', c.checked && !tr.classList.contains('skip'));
    if (c.checked) (tr.getAttribute('data-acts') || '').split(' ').forEach(function (a) { if (a) acts[a] = true; });
  });
  var n = form.querySelector('[data-nsel]');
  if (n) n.textContent = on.length + ' selected';
  form.querySelectorAll('[data-bulk-menu]').forEach(function (b) {
    b.disabled = on.length === 0;
    if (b.disabled) yarsBulkMenu(b, false);
  });
  form.querySelectorAll('.bmenu [data-act]').forEach(function (b) { b.disabled = !acts[b.getAttribute('data-act')]; });
  // Clear also clears a run's summary and skipped rows
  var sum = form.querySelector('.bsum');
  var ran = (sum && sum.textContent.trim() !== '') || form.querySelector('tr.skip') !== null;
  form.querySelectorAll('[data-bulk-clear]').forEach(function (clear) { clear.disabled = on.length === 0 && !ran; });
  form.querySelectorAll('[data-pick-all]').forEach(function (all) {
    var scope = all.closest('table') || form;
    var mine = scope.querySelectorAll('input[name=id]');
    var ticked = scope.querySelectorAll('input[name=id]:checked').length;
    all.checked = ticked > 0 && ticked === mine.length;
    all.indeterminate = ticked > 0 && ticked < mine.length;
    all.disabled = mine.length === 0;
  });
  var dlg = form.querySelector('.bdlg');
  if (dlg && !dlg.hidden) {
    if (on.length === 0) yarsBulkReason(form, null);
    else yarsBulkHead(form);
  }
}
function yarsBulkMenu(btn, open) {
  var menu = btn.parentNode.querySelector('.bmenu');
  if (!menu) return;
  menu.hidden = !open;
  btn.setAttribute('aria-expanded', open ? 'true' : 'false');
}
function yarsBulkCloseMenus(except) {
  document.querySelectorAll('.fbulk [data-bulk-menu][aria-expanded=true]').forEach(function (b) { if (b !== except) yarsBulkMenu(b, false); });
}
function yarsBulkHead(form) {
  var dlg = form.querySelector('.bdlg');
  var n = form.querySelectorAll('input[name=id]:checked').length;
  var head = dlg.querySelector('[data-bulk-head]');
  if (head) head.textContent = (dlg.getAttribute('data-verb') || 'Return') + ' ' + n + (n === 1 ? ' finding' : ' findings');
}
// yarsBulkReason opens the reason panel for a Return or Withdraw entry (or
// closes it, item null); the reason only goes with the form while it is open.
function yarsBulkReason(form, item) {
  var dlg = form.querySelector('.bdlg');
  if (!dlg) return;
  var ta = dlg.querySelector('textarea[name=reason]');
  var go = dlg.querySelector('[data-bulk-go]');
  if (!item) {
    dlg.hidden = true;
    if (ta) ta.disabled = true;
    return;
  }
  var verb = item.getAttribute('data-act') === 'withdraw' ? 'Withdraw' : 'Return';
  dlg.setAttribute('data-verb', verb);
  if (go) { go.value = item.getAttribute('data-act'); go.textContent = verb; }
  yarsBulkHead(form);
  dlg.hidden = false;
  if (ta) { ta.disabled = false; ta.focus(); }
}
document.addEventListener('change', function (evt) {
  var form = evt.target.closest && evt.target.closest('.fbulkform');
  if (!form) return;
  if (evt.target.hasAttribute('data-pick-all')) {
    var to = evt.target.checked;
    (evt.target.closest('table') || form).querySelectorAll('input[name=id]').forEach(function (c) { c.checked = to; });
  }
  if (evt.target.matches('input[name=id], [data-pick-all]')) yarsBulkSync(form);
});
document.addEventListener('click', function (evt) {
  if (!evt.target.closest) return;
  var form = evt.target.closest('.fbulkform');
  var menuBtn = evt.target.closest('[data-bulk-menu]');
  yarsBulkCloseMenus(menuBtn || evt.target.closest('.bdd') && evt.target.closest('.bdd').querySelector('[data-bulk-menu]'));
  if (!form) return;
  if (menuBtn) { yarsBulkMenu(menuBtn, menuBtn.getAttribute('aria-expanded') !== 'true'); return; }
  var reason = evt.target.closest('[data-bulk-reason]');
  if (reason) { yarsBulkCloseMenus(null); yarsBulkReason(form, reason); return; }
  if (evt.target.closest('[data-bulk-cancel]')) { yarsBulkReason(form, null); return; }
  if (evt.target.closest('[data-bulk-clear]')) {
    form.querySelectorAll('input[name=id]').forEach(function (c) { c.checked = false; });
    form.querySelectorAll('tr.skip').forEach(function (tr) { tr.classList.remove('skip'); tr.removeAttribute('title'); });
    var sum = form.querySelector('.bsum');
    if (sum) sum.textContent = '';
    yarsBulkReason(form, null);
    yarsBulkSync(form);
  }
});
document.addEventListener('keydown', function (evt) {
  if (evt.key !== 'Escape') return;
  yarsBulkCloseMenus(null);
  document.querySelectorAll('.fbulkform').forEach(function (f) { yarsBulkReason(f, null); });
});
// While a run is out every bar button is disabled (hx-disabled-elt), so a
// double click sends one request; a refused run (403, 422: a toast, no swap)
// gets the bar's own enabling back.
document.addEventListener('htmx:afterRequest', function (evt) {
  var f = evt.detail.elt && evt.detail.elt.closest && evt.detail.elt.closest('.fbulkform');
  if (f && f.isConnected) setTimeout(function () { yarsBulkSync(f); }, 0);
});
document.addEventListener('htmx:load', function (evt) {
  var root = evt.detail.elt;
  if (!root.querySelectorAll) return;
  var forms = root.matches && root.matches('.fbulkform') ? [root] : root.querySelectorAll('.fbulkform');
  Array.prototype.forEach.call(forms, yarsBulkSync);
  // rows from Load more join the form already there
  var f = root.closest && root.closest('.fbulkform');
  if (f) yarsBulkSync(f);
});

/* ---------- Go to (Ctrl-K) ---------- */

// The palette searches findings as you type (htmx fills #goto-results);
// Up and Down move the selection, Enter opens it, Esc closes.
function yarsGotoOpen() {
  var dlg = document.getElementById('goto');
  if (!dlg || !dlg.showModal || dlg.open) return;
  dlg.showModal();
  var btn = document.querySelector('[data-goto]');
  if (btn) btn.setAttribute('aria-expanded', 'true');
  var inp = dlg.querySelector('input[name=q]');
  if (inp) { inp.focus(); inp.select(); }
}
function yarsGotoMove(step) {
  var rows = Array.prototype.slice.call(document.querySelectorAll('#goto-results .res'));
  if (!rows.length) return;
  var i = rows.findIndex(function (r) { return r.classList.contains('sel'); });
  var next = Math.min(rows.length - 1, Math.max(0, i + step));
  rows.forEach(function (r, k) { r.classList.toggle('sel', k === next); r.setAttribute('aria-selected', k === next ? 'true' : 'false'); });
  rows[next].scrollIntoView({block: 'nearest'});
}
document.addEventListener('keydown', function (evt) {
  if ((evt.ctrlKey || evt.metaKey) && !evt.altKey && (evt.key === 'k' || evt.key === 'K')) {
    evt.preventDefault();
    yarsGotoOpen();
    return;
  }
  var dlg = document.getElementById('goto');
  if (!dlg || !dlg.open) return;
  if (evt.key === 'ArrowDown' || evt.key === 'ArrowUp') {
    evt.preventDefault();
    yarsGotoMove(evt.key === 'ArrowDown' ? 1 : -1);
  } else if (evt.key === 'Enter') {
    var sel = dlg.querySelector('#goto-results .res.sel');
    evt.preventDefault();
    if (sel) window.location.href = sel.getAttribute('href');
  }
});
document.addEventListener('click', function (evt) {
  if (!evt.target.closest) return;
  if (evt.target.closest('[data-goto]')) { yarsGotoOpen(); return; }
  var dlg = document.getElementById('goto');
  // a click on the backdrop (the dialog box itself, outside its content)
  if (dlg && dlg.open && evt.target === dlg) dlg.close();
});
document.addEventListener('mousemove', function (evt) {
  var r = evt.target.closest && evt.target.closest('#goto-results .res');
  if (!r || r.classList.contains('sel')) return;
  document.querySelectorAll('#goto-results .res.sel').forEach(function (x) { x.classList.remove('sel'); });
  r.classList.add('sel');
});
document.addEventListener('close', function (evt) {
  if (evt.target && evt.target.id === 'goto') {
    var btn = document.querySelector('[data-goto]');
    if (btn) btn.setAttribute('aria-expanded', 'false');
  }
}, true);

/* ---------- finding page ---------- */

// Workflow bar: Return and Withdraw open their reason form under the bar
// (one at a time); Cancel closes it. A popover (details.pop) closes when
// another opens or on a click outside it.
document.addEventListener('click', function (evt) {
  if (!evt.target.closest) return;
  var tog = evt.target.closest('[data-reason-toggle]');
  var cancel = evt.target.closest('[data-reason-cancel]');
  if (tog || cancel) {
    var id = tog ? tog.getAttribute('aria-controls') : cancel.getAttribute('data-reason-cancel');
    var bar = document.getElementById('workflow');
    if (!bar) return;
    var opening = !!tog && tog.getAttribute('aria-expanded') !== 'true';
    bar.querySelectorAll('.wfpanel').forEach(function (p) { p.hidden = !(opening && p.id === id); });
    bar.querySelectorAll('[data-reason-toggle]').forEach(function (b) {
      b.setAttribute('aria-expanded', opening && b.getAttribute('aria-controls') === id ? 'true' : 'false');
    });
    if (opening) {
      var ta = document.querySelector('#' + id + ' textarea');
      if (ta) ta.focus();
    }
    return;
  }
  var inPop = evt.target.closest('details.pop');
  document.querySelectorAll('details.pop[open]').forEach(function (d) { if (d !== inPop) d.open = false; });
});

// Checks: Dismiss opens the violation's reason form under its row (one at
// a time); Cancel closes it.
document.addEventListener('click', function (evt) {
  if (!evt.target.closest) return;
  var tog = evt.target.closest('[data-dismiss-toggle]');
  var cancel = evt.target.closest('[data-dismiss-cancel]');
  if (!tog && !cancel) return;
  var panel = document.getElementById('checks');
  if (!panel) return;
  var id = tog ? tog.getAttribute('aria-controls') : cancel.getAttribute('data-dismiss-cancel');
  var opening = !!tog && tog.getAttribute('aria-expanded') !== 'true';
  panel.querySelectorAll('.dismissrow').forEach(function (r) { r.hidden = !(opening && r.id === id); });
  panel.querySelectorAll('[data-dismiss-toggle]').forEach(function (b) {
    b.setAttribute('aria-expanded', opening && b.getAttribute('aria-controls') === id ? 'true' : 'false');
  });
  if (opening) {
    var inp = document.querySelector('#' + id + ' input[name=reason]');
    if (inp) inp.focus();
  }
});

// Rule bench (Run on engagement): a hit marked as a false positive is
// struck through and counted in the head.
document.addEventListener('change', function (evt) {
  var cb = evt.target;
  if (!cb.matches || !cb.matches('input[data-fp]')) return;
  var row = cb.closest('tr');
  if (row) row.classList.toggle('fp', cb.checked);
  var out = cb.closest('.benchout');
  var cnt = out && out.querySelector('[data-fp-count]');
  if (!cnt) return;
  var n = out.querySelectorAll('input[data-fp]:checked').length;
  cnt.textContent = n + (n === 1 ? ' false positive' : ' false positives');
});

// Section editor: Write | Split | Preview. The choice is remembered per
// browser; Split is the default.
function yarsEditorMode(editor, mode) {
  if (['write', 'split', 'preview'].indexOf(mode) < 0) return;
  editor.setAttribute('data-view', mode);
  var form = editor.closest('form');
  if (!form) return;
  form.querySelectorAll('[data-mode]').forEach(function (b) {
    b.setAttribute('aria-pressed', b.getAttribute('data-mode') === mode ? 'true' : 'false');
  });
}
document.addEventListener('click', function (evt) {
  var b = evt.target.closest && evt.target.closest('[data-mode]');
  if (b) {
    var form = b.closest('form');
    var ed = form && form.querySelector('.editor');
    if (!ed) return;
    var mode = b.getAttribute('data-mode');
    yarsEditorMode(ed, mode);
    try { localStorage.setItem('yars-editor-mode', mode); } catch (e) { /* not remembered */ }
    return;
  }
  var th = evt.target.closest && evt.target.closest('[data-theirs]');
  if (th) {
    var box = document.getElementById(th.getAttribute('data-theirs'));
    if (!box) return;
    box.hidden = !box.hidden;
    th.setAttribute('aria-pressed', box.hidden ? 'false' : 'true');
  }
});
document.addEventListener('htmx:load', function (evt) {
  var mode = null;
  try { mode = localStorage.getItem('yars-editor-mode'); } catch (e) { /* default */ }
  if (!mode) return;
  var root = evt.detail.elt;
  var eds = root.matches && root.matches('.editor') ? [root] : root.querySelectorAll ? root.querySelectorAll('.editor') : [];
  Array.prototype.forEach.call(eds, function (ed) { yarsEditorMode(ed, mode); });
});

// Unsaved-changes guard for editors (form[data-guard]): a text box differs
// from what the server sent (defaultValue), or the server returned the
// user's own text after a conflict (data-dirty).
function yarsDirty(scope) {
  return Array.prototype.some.call(scope.querySelectorAll('form[data-guard] textarea, form[data-guard] input[type=text]'), function (i) {
    return i.hasAttribute('data-dirty') || i.value !== i.defaultValue;
  });
}
window.addEventListener('beforeunload', function (evt) {
  if (!yarsDirty(document)) return;
  evt.preventDefault();
  evt.returnValue = '';
});
document.addEventListener('htmx:confirm', function (evt) {
  var el = evt.detail.elt;
  if (!el || !el.hasAttribute || !el.hasAttribute('data-guard-cancel')) return;
  var form = el.closest('form[data-guard]');
  if (!form || !yarsDirty(form.parentNode)) return;
  evt.preventDefault();
  if (window.confirm('Discard changes?')) evt.detail.issueRequest(true);
});

/* ---------- section editor states ---------- */

// Unsaved: the editor's heading shows a dot while its text differs.
document.addEventListener('input', function (evt) {
  var form = evt.target.closest && evt.target.closest('form[data-guard]');
  if (form) form.classList.toggle('dirty', yarsDirty(form.parentNode));
});

// Presence: an open editor tells the server every 20 s that it is still
// open (the server forgets it after 60 s without one).
setInterval(function () {
  if (document.hidden) return;
  document.querySelectorAll('form[data-presence]').forEach(function (f) {
    fetch(f.getAttribute('data-presence'), {method: 'POST', credentials: 'same-origin', headers: {'HX-Request': 'true'}})
      .then(function (r) { if (r.status === 401) yarsExpired(); })
      .catch(function () { /* offline: the next beat tries again */ });
  });
}, 20000);

// Session expired (an htmx request or a heartbeat got 401): every editor's
// unsaved text is kept in localStorage under "yars-draft:<save URL>", and
// the editor offers it back (Restore) when it is opened again.
function yarsDraftKey(form) { return 'yars-draft:' + (form.getAttribute('hx-post') || ''); }
function yarsDraft(form) {
  try { var d = JSON.parse(localStorage.getItem(yarsDraftKey(form)) || 'null'); return d && typeof d.text === 'string' ? d : null; } catch (e) { return null; }
}
var yarsExpiredAt = 0;
function yarsExpired() {
  document.querySelectorAll('form[data-guard]').forEach(function (form) {
    var ta = form.querySelector('textarea[name=body]');
    if (!ta || !yarsDirty(form.parentNode)) return;
    try { localStorage.setItem(yarsDraftKey(form), JSON.stringify({text: ta.value, at: Date.now()})); } catch (e) { /* not kept */ }
    var st = form.querySelector('[data-pstate]');
    if (st) { st.textContent = 'Session expired · not saved'; st.classList.add('error'); }
  });
  if (Date.now() - yarsExpiredAt > 10000) { yarsExpiredAt = Date.now(); yarsToast('Session expired', true); }
}
function yarsDraftOffer(root) {
  var forms = root.matches && root.matches('form[data-guard]') ? [root] : root.querySelectorAll ? root.querySelectorAll('form[data-guard]') : [];
  Array.prototype.forEach.call(forms, function (form) {
    form.classList.toggle('dirty', yarsDirty(form.parentNode));
    var btn = form.querySelector('[data-draft-restore]');
    var ta = form.querySelector('textarea[name=body]');
    if (!btn || !ta) return;
    var d = yarsDraft(form);
    if (!d || d.text === ta.value) return;
    btn.classList.remove('invisible');
    var st = form.querySelector('[data-pstate]');
    if (st && !st.textContent) st.textContent = 'Draft ' + new Date(d.at).toTimeString().slice(0, 5);
  });
}
document.addEventListener('htmx:load', function (evt) { yarsDraftOffer(evt.detail.elt); });
document.addEventListener('click', function (evt) {
  var b = evt.target.closest && evt.target.closest('[data-draft-restore]');
  if (!b) return;
  var form = b.closest('form');
  var ta = form && form.querySelector('textarea[name=body]');
  var d = form && yarsDraft(form);
  if (!ta || !d) return;
  ta.value = d.text;
  ta.setAttribute('data-dirty', '');
  form.classList.add('dirty');
  b.classList.add('invisible');
  if (window.htmx) htmx.trigger(ta, 'keyup');
});
// a saved or cancelled editor drops its draft. The editor is swapped out by
// then, so htmx fires afterRequest on an ancestor: the key rides on the xhr.
document.addEventListener('htmx:beforeRequest', function (evt) {
  var el = evt.detail.elt;
  if (!el || !el.matches || !evt.detail.xhr) return;
  var form = el.matches('form[data-guard]') ? el : el.hasAttribute('data-guard-cancel') ? el.closest('form[data-guard]') : null;
  if (form) evt.detail.xhr.yarsDraftKey = yarsDraftKey(form);
});
document.addEventListener('htmx:afterRequest', function (evt) {
  var k = evt.detail.xhr && evt.detail.xhr.yarsDraftKey;
  if (!evt.detail.successful || !k) return;
  try { localStorage.removeItem(k); } catch (e) { /* none kept */ }
});

/* ---------- keyboard: E edits a section, Ctrl+S saves it ---------- */

// The templates mark the controls: Edit buttons carry aria-keyshortcuts="E",
// editor Save buttons "Control+S". A section is a section.panel with an id
// (finding page, report tab, template page); the one last clicked, focused
// or linked to (#s-…) is remembered by id, since htmx swaps the element.
var yarsLastPanel = '';
var yarsFocusAfter = ''; // the section to put focus back into after its swap

function yarsPanelOf(el) {
  return el && el.closest ? el.closest('section.panel[id]') : null;
}
function yarsRemember(el) {
  var p = yarsPanelOf(el);
  if (p) yarsLastPanel = p.id;
}
document.addEventListener('pointerdown', function (evt) { yarsRemember(evt.target); }, true);
document.addEventListener('focusin', function (evt) { yarsRemember(evt.target); });
window.addEventListener('hashchange', function () {
  if (location.hash.length > 1) yarsRemember(document.getElementById(decodeURIComponent(location.hash.slice(1))));
});

// yarsTyping: the key goes into a field, so single-key shortcuts stay out.
function yarsTyping(t) {
  return !!(t && (t.isContentEditable || (t.closest && t.closest('input, textarea, select, [contenteditable]'))));
}

// yarsFirstField focuses an open editor's first field (or its own autofocus).
function yarsFirstField(p) {
  var f = p.querySelector('[autofocus]') || p.querySelector('textarea, input:not([type=hidden]), select');
  if (f) f.focus();
}

// E: the focused section, else the one last selected, else the first text
// section. An already open editor gets focus back instead.
function yarsEdit() {
  var cands = [yarsPanelOf(document.activeElement), yarsLastPanel ? document.getElementById(yarsLastPanel) : null];
  for (var i = 0; i < cands.length; i++) {
    var p = cands[i];
    if (!p) continue;
    if (p.classList.contains('editing')) { yarsFirstField(p); return true; }
    var b = p.querySelector('button[aria-keyshortcuts~="E"]:not(:disabled)');
    if (b) { yarsFocusAfter = p.id; b.click(); return true; }
  }
  var first = document.querySelector('section.panel[id^="s-"] button[aria-keyshortcuts~="E"]:not(:disabled)');
  if (!first) return false;
  yarsFocusAfter = yarsPanelOf(first).id;
  first.click();
  return true;
}

// Ctrl+S: the open editor holding focus, else the one last selected, else
// the only one open. It presses that editor's own Save button (never a
// first submit button such as Clear vector); a disabled Save does nothing.
function yarsSave() {
  var open = Array.prototype.filter.call(document.querySelectorAll('section.panel.editing[id]'), function (p) {
    return !!p.querySelector('button[aria-keyshortcuts~="Control+S"]');
  });
  var a = yarsPanelOf(document.activeElement);
  var l = yarsLastPanel ? document.getElementById(yarsLastPanel) : null;
  var p = open.indexOf(a) >= 0 ? a : open.indexOf(l) >= 0 ? l : open.length === 1 ? open[0] : null;
  if (!p) return;
  var btn = p.querySelector('button[aria-keyshortcuts~="Control+S"]');
  var form = btn.form;
  if (!form || btn.disabled) return;
  yarsLastPanel = yarsFocusAfter = p.id;
  if (form.requestSubmit) form.requestSubmit(btn); else btn.click();
}

document.addEventListener('keydown', function (evt) {
  if ((evt.ctrlKey || evt.metaKey) && !evt.altKey && (evt.key === 's' || evt.key === 'S')) {
    // never the browser's "Save page" dialog on a YARS page
    evt.preventDefault();
    if (!evt.repeat && !document.querySelector('dialog[open]')) yarsSave();
    return;
  }
  if (evt.key !== 'e' && evt.key !== 'E') return;
  if (evt.ctrlKey || evt.metaKey || evt.altKey || evt.shiftKey || evt.isComposing || evt.repeat || evt.defaultPrevented) return;
  if (yarsTyping(evt.target) || document.querySelector('dialog[open]')) return;
  if (yarsEdit()) evt.preventDefault();
});

// After a keyboard edit or save the section keeps focus: an open editor on
// its first field, a saved section on its Edit button.
document.addEventListener('htmx:afterSettle', function (evt) {
  var t = evt.detail.target;
  if (!yarsFocusAfter || !t || t.id !== yarsFocusAfter) return;
  var p = document.getElementById(yarsFocusAfter);
  yarsFocusAfter = '';
  if (!p) return;
  if (p.classList.contains('editing')) { yarsFirstField(p); return; }
  var b = p.querySelector('button[aria-keyshortcuts~="E"]');
  if (b) { b.focus({preventScroll: true}); return; }
  p.setAttribute('tabindex', '-1');
  p.focus({preventScroll: true});
});
document.addEventListener('htmx:responseError', function () { yarsFocusAfter = ''; });

// Attachments: Add file uploads into the finding's attachments/ (images go
// through Redact first, so a redacted original never reaches the server);
// Insert puts the Markdown link at the cursor.
function yarsInsert(form, text) {
  var ta = form && form.querySelector('textarea[name=body]');
  if (!ta) return;
  var s = ta.selectionStart || 0, e = ta.selectionEnd || 0, v = ta.value;
  var pre = s > 0 && v.charAt(s - 1) !== '\n' ? '\n' : '';
  ta.value = v.slice(0, s) + pre + text + '\n' + v.slice(e);
  ta.selectionStart = ta.selectionEnd = s + pre.length + text.length + 1;
  ta.focus();
  form.classList.add('dirty');
  if (window.htmx) htmx.trigger(ta, 'keyup');
}
function yarsUpload(strip, url, blob, name, insert) {
  var fd = new FormData();
  fd.append('file', blob, name);
  return fetch(url, {method: 'POST', body: fd, credentials: 'same-origin', headers: {'HX-Request': 'true'}}).then(function (r) {
    return r.text().then(function (t) {
      if (r.status === 401) { yarsExpired(); return false; }
      if (!r.ok) { yarsToast(name + ': ' + (t.trim() || ('Error ' + r.status)), true); return false; }
      var form = strip.closest('form');
      // the server's own template output (all values escaped)
      var tmp = document.createElement('div');
      tmp.innerHTML = t;
      var fresh = tmp.querySelector('.attstrip');
      if (fresh) {
        strip.replaceWith(fresh);
        if (window.htmx) htmx.process(fresh);
        // a redacted copy has a new ?v=: images of it elsewhere on the page
        // (preview, other sections) follow, so the original is not shown
        fresh.querySelectorAll('.thumb img').forEach(function (n) {
          var src = n.getAttribute('src') || '', path = src.split('?')[0];
          document.querySelectorAll('img').forEach(function (i) {
            var s = i.getAttribute('src') || '';
            if (i !== n && s !== src && s.split('?')[0] === path) i.setAttribute('src', src);
          });
        });
      }
      var md = r.headers.get('X-Yars-Insert');
      if (insert && md) yarsInsert(form, md);
      return true;
    });
  }).catch(function () { yarsToast('Connection lost', true); return false; });
}
document.addEventListener('change', function (evt) {
  var inp = evt.target;
  if (!inp.matches || !inp.matches('input[data-file]')) return;
  var strip = inp.closest('.attstrip');
  var f = inp.files && inp.files[0];
  inp.value = '';
  if (!strip || !f) return;
  if (f.size > 10 * 1024 * 1024) { yarsToast(f.name + ': larger than 10 MB', true); return; }
  if (/^image\/(png|jpeg|gif|webp|bmp)$/.test(f.type)) {
    yarsRedactOpen({file: f, name: f.name, type: f.type, strip: strip, url: strip.getAttribute('data-upload'), upload: true});
    return;
  }
  yarsUpload(strip, strip.getAttribute('data-upload'), f, f.name, true);
});
document.addEventListener('click', function (evt) {
  var b = evt.target.closest && evt.target.closest('[data-insert], [data-redact]');
  if (!b) return;
  if (b.hasAttribute('data-insert')) { yarsInsert(b.closest('form'), b.getAttribute('data-insert')); return; }
  var name = b.getAttribute('data-name') || '';
  var type = /\.jpe?g$/i.test(name) ? 'image/jpeg' : /\.webp$/i.test(name) ? 'image/webp' : 'image/png';
  yarsRedactOpen({src: b.getAttribute('data-src'), name: name, type: type, strip: b.closest('.attstrip'), url: b.getAttribute('data-redact'), upload: false});
});

// Redact: draw black boxes on the image in a canvas; Save sends the
// redacted copy (or, for a new file without boxes, the file itself).
var yarsRx = null;
function yarsRedactDraw() {
  var r = yarsRx;
  var ctx = r.cv.getContext('2d');
  ctx.drawImage(r.img, 0, 0);
  ctx.fillStyle = '#000000';
  r.boxes.forEach(function (b) { ctx.fillRect(b.x, b.y, b.w, b.h); });
  if (r.drag) {
    ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#F26B1D';
    ctx.lineWidth = Math.max(2, r.cv.width / 400);
    ctx.setLineDash([8, 6]);
    ctx.strokeRect(r.drag.x, r.drag.y, r.drag.w, r.drag.h);
    ctx.setLineDash([]);
  }
  r.dlg.querySelector('[data-redact-count]').textContent = r.boxes.length + (r.boxes.length === 1 ? ' box' : ' boxes');
}
function yarsRedactClose() {
  if (!yarsRx) return;
  if (yarsRx.objURL) URL.revokeObjectURL(yarsRx.objURL);
  if (yarsRx.dlg.open) yarsRx.dlg.close();
  yarsRx = null;
}
function yarsRedactOpen(o) {
  var dlg = document.getElementById('redact');
  if (!dlg || !dlg.showModal) {
    if (o.upload) yarsUpload(o.strip, o.url, o.file, o.name, true);
    return;
  }
  var img = new Image();
  var objURL = o.file ? URL.createObjectURL(o.file) : '';
  img.onload = function () {
    var cv = dlg.querySelector('[data-redact-canvas]');
    cv.width = img.naturalWidth;
    cv.height = img.naturalHeight;
    yarsRx = {o: o, img: img, cv: cv, dlg: dlg, boxes: [], drag: null, objURL: objURL};
    dlg.querySelector('[data-redact-name]').textContent = o.name;
    dlg.querySelector('[data-redact-error]').textContent = '';
    dlg.querySelector('[data-redact-save]').disabled = false;
    yarsRedactDraw();
    dlg.showModal();
  };
  img.onerror = function () { if (objURL) URL.revokeObjectURL(objURL); yarsToast(o.name + ': not an image', true); };
  img.src = objURL || (o.src + (o.src.indexOf('?') < 0 ? '?' : '&') + 't=' + Date.now());
}
function yarsRedactPoint(evt) {
  var cv = yarsRx.cv, rect = cv.getBoundingClientRect();
  return {x: (evt.clientX - rect.left) * cv.width / rect.width, y: (evt.clientY - rect.top) * cv.height / rect.height};
}
document.addEventListener('pointerdown', function (evt) {
  if (!yarsRx || evt.target !== yarsRx.cv) return;
  var p = yarsRedactPoint(evt);
  yarsRx.start = p;
  yarsRx.drag = {x: p.x, y: p.y, w: 0, h: 0};
  yarsRx.cv.setPointerCapture(evt.pointerId);
});
document.addEventListener('pointermove', function (evt) {
  if (!yarsRx || !yarsRx.drag) return;
  var p = yarsRedactPoint(evt), s = yarsRx.start;
  yarsRx.drag = {x: Math.min(s.x, p.x), y: Math.min(s.y, p.y), w: Math.abs(p.x - s.x), h: Math.abs(p.y - s.y)};
  yarsRedactDraw();
});
document.addEventListener('pointerup', function () {
  if (!yarsRx || !yarsRx.drag) return;
  var d = yarsRx.drag;
  yarsRx.drag = null;
  if (d.w > 2 && d.h > 2) yarsRx.boxes.push(d);
  yarsRedactDraw();
});
document.addEventListener('click', function (evt) {
  if (!yarsRx || !evt.target.closest) return;
  if (evt.target.closest('[data-redact-undo]')) { yarsRx.boxes.pop(); yarsRedactDraw(); return; }
  if (evt.target.closest('[data-redact-cancel]')) { yarsRedactClose(); return; }
  var save = evt.target.closest('[data-redact-save]');
  if (!save) return;
  var r = yarsRx;
  var done = function (ok) { if (ok) yarsRedactClose(); else save.disabled = false; };
  save.disabled = true;
  if (r.o.upload && r.boxes.length === 0) { yarsUpload(r.o.strip, r.o.url, r.o.file, r.o.name, true).then(done); return; }
  r.cv.toBlob(function (blob) {
    if (!blob) { r.dlg.querySelector('[data-redact-error]').textContent = 'Not saved'; save.disabled = false; return; }
    yarsUpload(r.o.strip, r.o.url, blob, r.o.name, r.o.upload).then(done);
  }, r.o.type || 'image/png', 0.92);
});
document.addEventListener('close', function (evt) {
  if (yarsRx && evt.target === yarsRx.dlg) yarsRedactClose();
}, true);
