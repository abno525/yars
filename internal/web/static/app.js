// Theme: the account's choice (Settings › Preferences) is set on <html> by
// the server and kept in localStorage for the pages before login; without
// one the system setting applies. Runs in <head>, so the theme is set before
// the page paints.
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

// Hide chat (the finding page): the choice lives in localStorage and is set
// on <html> as data-chat before the page paints, so the panels take the
// whole width without a jump.
(function () {
  try {
    if (localStorage.getItem('yars-chat') === 'hidden') document.documentElement.setAttribute('data-chat', 'hidden');
  } catch (e) { /* storage blocked: the chat is shown */ }
})();

// yarsChat shows (true) or hides (false) the chat column and remembers it.
function yarsChat(show) {
  var root = document.documentElement;
  if (show) root.removeAttribute('data-chat'); else root.setAttribute('data-chat', 'hidden');
  try {
    if (show) localStorage.removeItem('yars-chat'); else localStorage.setItem('yars-chat', 'hidden');
  } catch (e) { /* not remembered */ }
  yarsChatState();
}

// yarsChatHidden tells whether the chat column is hidden.
function yarsChatHidden() {
  return document.documentElement.getAttribute('data-chat') === 'hidden';
}

// yarsChatState tells the toggle whether the chat is shown.
function yarsChatState() {
  var shown = yarsChatHidden() ? 'false' : 'true';
  Array.prototype.forEach.call(document.querySelectorAll('[data-chat-toggle]'), function (b) { b.setAttribute('aria-expanded', shown); });
}
document.addEventListener('DOMContentLoaded', yarsChatState);

// yarsListIdle tells whether the findings board may refresh itself: not
// while rows are picked or more rows were loaded (both would be lost).
function yarsListIdle() {
  var list = document.getElementById('findings');
  if (!list) return false;
  if (list.querySelector('input[name="id"]:checked')) return false;
  var shown = list.querySelectorAll('tbody tr[data-fid]').length;
  return shown <= Number(list.getAttribute('data-rows') || 0);
}

// yarsToast shows a short message in #toasts; click or wait to dismiss. It
// hands the toast back: in the page while it shows.
function yarsToast(text, err) {
  var box = document.getElementById('toasts');
  if (!box) return null;
  var t = document.createElement('div');
  t.className = 'toast' + (err ? ' err' : '');
  t.setAttribute('role', err ? 'alert' : 'status');
  t.textContent = text;
  t.addEventListener('click', function () { t.remove(); });
  box.appendChild(t);
  while (box.children.length > 4) box.firstChild.remove();
  setTimeout(function () { t.remove(); }, err ? 8000 : 4000);
  return t;
}

// Errors that htmx does not swap (403, 500, …) become visible as a toast.
document.addEventListener('htmx:responseError', function (evt) {
  var xhr = evt.detail.xhr;
  // a request a live event sent (sse:poll, sse:chat, …) is not the user's own
  var ev = evt.detail.requestConfig && evt.detail.requestConfig.triggeringEvent;
  var live = ev && String(ev.type).indexOf('sse:') === 0;
  if (xhr && xhr.status === 401) { yarsExpired(!live); return; }
  var text = (xhr && xhr.responseText || '').trim();
  if (/^\s*</.test(text)) {
    // DOMParser runs no scripts or handlers; only the text is kept
    var doc = new DOMParser().parseFromString(text, 'text/html');
    text = (doc.body && doc.body.textContent || '').trim();
  }
  if (text.length > 300) text = text.slice(0, 300) + '…';
  text = text || ('Error ' + (xhr ? xhr.status : ''));
  // a server error names its request, as the service log does
  var req = xhr && xhr.status >= 500 && xhr.getResponseHeader('X-Request-ID');
  if (req && text.indexOf(req) < 0) text += '\nRequest ' + req;
  yarsToast(text, true);
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
// Back to a page: the engagement picker shows the server's choice again, not
// the one picked to leave (the browser's saved state or cache), so picking
// the shown engagement is a change and opens it
window.addEventListener('pageshow', function () { document.querySelectorAll('.engpick select').forEach(yarsSelectReset); });

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
  var el = evt.target.closest && evt.target.closest('[data-copy], [data-check-all]');
  if (!el) return;
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

// yarsComment points the chat composer at a section and focuses it (showing
// the chat first when it is hidden).
function yarsComment(section) {
  var sel = document.getElementById('chat-section');
  var txt = document.getElementById('chat-text');
  if (!sel || !txt) return;
  if (yarsChatHidden()) yarsChat(true);
  sel.value = section;
  txt.focus();
  txt.scrollIntoView({block: 'center', behavior: 'smooth'});
}

// yarsConfirm asks text in the page's own dialog (#confirm), its OK button
// labelled ok, and runs done when that is pressed; Cancel or Esc keep things
// as they are (a click outside does nothing: the second click of a
// double-click would land there). A page without the dialog (none signed
// in) falls back to the browser's. safe: the question came up while typing
// (the team board's search), so the next key lands on Cancel, not OK. no,
// if given, runs on Cancel or Esc.
function yarsConfirm(text, ok, done, safe, no) {
  var d = document.getElementById('confirm');
  if (!d || !d.showModal) {
    if (window.confirm(text)) done(); else if (no) no();
    return;
  }
  d.querySelector('[data-confirm-text]').textContent = text;
  var b = d.querySelector('[data-confirm-ok]');
  b.textContent = ok || 'OK';
  d.returnValue = '';
  d.onclose = function () { d.onclose = null; if (d.returnValue === 'ok') done(); else if (no) no(); };
  // after the event that asked: an Esc that cancelled an editor would close
  // a dialog opened during it
  var f = safe ? d.querySelector('button[value=cancel]') || b : b;
  setTimeout(function () { d.showModal(); f.focus(); }, 0);
}

// Comment buttons and confirm buttons are wired here (no inline handlers:
// the page's script policy allows none). A data-confirm button asks first
// and is pressed again once confirmed.
document.addEventListener('click', function (evt) {
  if (!evt.target.closest) return;
  var c = evt.target.closest('[data-comment]');
  if (c) { yarsComment(c.getAttribute('data-comment')); return; }
  if (evt.target.closest('[data-chat-toggle]')) { yarsChat(yarsChatHidden()); return; }
  c = evt.target.closest('[data-confirm]');
  if (!c) return;
  if (c.yarsConfirmed) { c.yarsConfirmed = false; return; }
  evt.preventDefault();
  yarsConfirm(c.getAttribute('data-confirm'), c.textContent.trim(), function () { c.yarsConfirmed = true; c.click(); });
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
    (t.id === 'checks' && t.open && !!t.querySelector('.dismissrow:not([hidden])'));
  if (busy) evt.detail.shouldSwap = false;
});

// Checks strip: the server opens it while a check runs or the author's
// draft has errors; a click on its head is the user's choice, kept for this
// finding in this tab and re-applied after live refreshes (never against a
// running check or fix, which stays open). A button in the head (Fix with
// AI) is pressed, not the head.
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
  if (!s || evt.target.closest('button')) return;
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
// a Dismiss or Restore sent from the open strip keeps it open: its answer
// may have no errors left, which the server would show closed
document.addEventListener('submit', function (evt) {
  var d = evt.target.closest && evt.target.closest('#checks');
  if (!d || !d.open) return;
  try { sessionStorage.setItem(yarsChecksKey(), 'open'); } catch (e) { /* not kept */ }
});
// Retest: the Original starts closed; the user's choice is kept for this
// finding in this tab (setting the result reloads the page)
function yarsOrigKey() { return 'yars-orig:' + location.pathname; }
function yarsOrigApply() {
  var d = document.querySelector('#retest details.orig');
  if (!d) return;
  try { if (sessionStorage.getItem(yarsOrigKey()) === 'open') d.open = true; } catch (e) { /* not kept */ }
}
document.addEventListener('toggle', function (evt) {
  var d = evt.target;
  if (!d.matches || !d.matches('#retest details.orig')) return;
  try { sessionStorage.setItem(yarsOrigKey(), d.open ? 'open' : 'closed'); } catch (e) { /* not kept */ }
}, true); // toggle does not bubble
document.addEventListener('DOMContentLoaded', yarsOrigApply);
document.addEventListener('htmx:afterSwap', function (evt) {
  if (evt.detail.target && evt.detail.target.id === 'retest') yarsOrigApply();
});
document.addEventListener('DOMContentLoaded', yarsChecksApply);
document.addEventListener('htmx:afterSwap', function (evt) {
  // the strip's own swap, or the copy sent out of band with the bar (Check,
  // Retry), whose event carries the bar's request
  if ((evt.detail.target && evt.detail.target.id === 'checks') || (evt.target && evt.target.id === 'checks')) yarsChecksApply();
});

// Team board: a live refresh (sse:…) waits while something is being typed
// or a menu is open there; the user's own clicks always swap.
document.addEventListener('htmx:beforeSwap', function (evt) {
  var t = evt.detail.target;
  var ev = evt.detail.requestConfig && evt.detail.requestConfig.triggeringEvent;
  if (!t || t.id !== 'board' || !ev || String(ev.type).indexOf('sse:') !== 0) return;
  var busy = Array.prototype.some.call(t.querySelectorAll('textarea, input:not([type=hidden]), select'), function (i) {
    // text the server sent back with an error is unsaved too (yarsChanged)
    return i === document.activeElement || (i.value !== undefined && i.defaultValue !== undefined && yarsChanged(i));
  }) || !!t.querySelector('details[open]');
  if (busy) evt.detail.shouldSwap = false;
});
// Team board: Back (or Forward) while a reply or new lead is typed asks
// first. htmx restores the board in its popstate handler with no event
// before it to cancel, so that handler is wrapped once htmx set it (htmx's
// DOMContentLoaded runs first: it loads before this file). Discard lets
// htmx restore; Cancel keeps the board and puts its address back
// (yarsHere: the URL the board showed last).
var yarsHere = location.href;
['htmx:pushedIntoHistory', 'htmx:replacedInHistory', 'htmx:historyRestore'].forEach(function (n) {
  document.addEventListener(n, function () { yarsHere = location.href; });
});
document.addEventListener('DOMContentLoaded', function () {
  var restore = window.onpopstate;
  if (!restore) return;
  window.onpopstate = function (evt) {
    var b = document.getElementById('board');
    if (!evt.state || !evt.state.htmx || !b || !yarsDirty(b)) { restore.call(window, evt); yarsHere = location.href; return; }
    var was = yarsHere;
    yarsConfirm('Discard changes?', 'Discard', function () { restore.call(window, evt); yarsHere = location.href; },
      false, function () { history.pushState({htmx: true}, '', was); });
  };
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
// Range select (K7): yarsRangeFrom is the row checkbox the user last
// clicked in a bulk list. yarsRange gives cb the state to and, with Shift
// (a Shift+click here, Shift+Space on a focused row in keys.js), every
// checkbox of the same table between the two the same state.
var yarsRangeFrom = null;
function yarsRange(cb, to) {
  var form = cb.closest('.fbulkform');
  if (!form) return;
  cb.checked = to;
  var from = yarsRangeFrom;
  if (from && from !== cb && from.isConnected) {
    var list = Array.prototype.slice.call((cb.closest('table') || form).querySelectorAll('input[name=id]'));
    var a = list.indexOf(from), b = list.indexOf(cb);
    if (a >= 0 && b >= 0) {
      list.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(function (c) { if (!c.disabled) c.checked = to; });
    }
  }
  yarsRangeFrom = cb;
  yarsBulkSync(form);
}
document.addEventListener('click', function (evt) {
  var cb = evt.target;
  if (!cb.matches || !cb.matches('.fbulkform input[name=id]')) return;
  // the box has already flipped: its new state is the range's
  if (evt.shiftKey) yarsRange(cb, cb.checked);
  else yarsRangeFrom = cb;
});
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
// yarsBulkVerbs name the reason panel's action for each entry that needs a
// reason.
var yarsBulkVerbs = {'return': 'Return', 'withdraw': 'Withdraw', 'reopen': 'Revert', 'unreport': 'Revert'};
// yarsBulkReason opens the reason panel for a Return, Withdraw or Revert
// entry (or closes it, item null); the reason only goes with the form while
// it is open.
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
  var verb = yarsBulkVerbs[item.getAttribute('data-act')] || 'Return';
  dlg.setAttribute('data-verb', verb);
  if (go) {
    go.value = item.getAttribute('data-act'); go.textContent = verb;
    // red for Return and Withdraw, secondary for a Revert (as on the bar)
    var red = verb !== 'Revert';
    go.classList.toggle('danger', red);
    go.classList.toggle('secondary', !red);
  }
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
  // Esc closes the topmost thing: an open dialog (Go to) is the browser's
  if (evt.key !== 'Escape' || evt.isComposing || document.querySelector('dialog[open]')) return;
  yarsBulkCloseMenus(null);
  document.querySelectorAll('.fbulkform').forEach(function (f) { yarsBulkReason(f, null); });
});
// Enter on a checkbox of a list (a bulk row, Select all, the bulk picker, an
// export pick) or of the workflow bar's reviewer picker never submits its
// form: the browser's implicit submission would press the form's first
// enabled button, the first Set state entry or Assign all.
document.addEventListener('keydown', function (evt) {
  // plain Enter only: Ctrl+Enter in the picker presses its Save (keys.js)
  if (evt.key === 'Enter' && !evt.ctrlKey && !evt.metaKey && evt.target.matches && evt.target.matches('.fbulkform input[type=checkbox], input[type=checkbox][data-nav], .picker input[type=checkbox]')) evt.preventDefault();
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
// yarsLetter is the key a shortcut is matched by: evt.key, so every Latin
// layout keeps its own letters (Dvorak, AZERTY). On a layout without Latin
// letters (Cyrillic, Greek) a letter key gives a character no shortcut
// names; it then counts as the Latin letter of its place (evt.code KeyA to
// KeyZ). Not with AltGr: there the character is what was meant.
function yarsLetter(evt) {
  var k = evt.key;
  if (k && k.length === 1 && k.charCodeAt(0) > 127 && /^Key[A-Z]$/.test(evt.code || '') &&
      !(evt.getModifierState && evt.getModifierState('AltGraph'))) return evt.code.charAt(3);
  return k;
}
document.addEventListener('keydown', function (evt) {
  var gk = yarsLetter(evt);
  if ((evt.ctrlKey || evt.metaKey) && !evt.altKey && (gk === 'k' || gk === 'K')) {
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
    if (evt.isComposing) return; // the Enter that ends an input method's composition
    var sel = dlg.querySelector('#goto-results .res.sel');
    var inp = dlg.querySelector('input[name=q]'), head = dlg.querySelector('#goto-results .gh');
    evt.preventDefault();
    // the list names the query it answers (data-q): typed on since, the
    // rows are an earlier query's and Enter opens none of them
    if (sel && inp && head && head.getAttribute('data-q') === inp.value) window.location.href = sel.getAttribute('href');
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

// yarsFocusToggle gives focus back to the button that opened the form id
// (the form is hidden, so the field or Cancel that had focus is gone).
function yarsFocusToggle(id) {
  var t = document.querySelector('[aria-controls="' + id + '"]');
  if (t) t.focus();
}

// Workflow bar: Return, Withdraw and Revert open their reason form under
// the bar (one at a time); Cancel closes it. A popover (details.pop) closes when
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
    } else if (cancel) {
      yarsFocusToggle(id);
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
  } else if (cancel) {
    yarsFocusToggle(id);
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
// user's own text after a conflict (data-dirty), or the server says the
// form as drawn is not what is saved (data-unsaved: rows removed).
function yarsDirty(scope) {
  if ((scope.matches && scope.matches('form[data-guard][data-unsaved]')) || scope.querySelector('form[data-guard][data-unsaved]')) return true;
  // an input with no type is a text box too (the team board's new lead)
  return Array.prototype.some.call(scope.querySelectorAll('form[data-guard] textarea, form[data-guard] input[type=text], form[data-guard] input:not([type])'), function (i) {
    return yarsChanged(i);
  });
}
// yarsChanged: a text box holds something unsaved. One the server sent back
// (data-dirty: a conflict, a refused reply or new lead) does while any text is
// left in it; emptied (or refused empty) there is nothing to lose.
function yarsChanged(i) {
  return i.hasAttribute('data-dirty') ? i.value.trim() !== '' : i.value !== i.defaultValue;
}
// yarsLeaving: the page's own dialog already asked (a key that leaves the
// page, keys.js yarsPress), so the browser's leave warning does not ask again
var yarsLeaving = false;
// Back to a page kept in the browser's cache: its text is there again, so
// leaving it warns again
window.addEventListener('pageshow', function () { yarsLeaving = false; });
window.addEventListener('beforeunload', function (evt) {
  if (yarsLeaving || !yarsDirty(document)) return;
  evt.preventDefault();
  evt.returnValue = '';
});
// An editor's Cancel with unsaved text, and any hx-confirm (Clear vector,
// Take theirs), ask in the page's dialog; the request goes once confirmed.
document.addEventListener('htmx:confirm', function (evt) {
  var el = evt.detail.elt;
  var q = evt.detail.question, ok = el && el.textContent ? el.textContent.trim() : '';
  if (el && el.hasAttribute && el.hasAttribute('data-guard-cancel')) {
    var form = el.closest('form[data-guard]');
    if (form && yarsDirty(form.parentNode)) {
      q = 'Discard changes?';
      ok = 'Discard';
    }
  }
  // the team board's reply or new lead being typed: any request of the
  // user's that swaps the board (a filter, the search, another lead, Cancel,
  // n, Make finding, Dismiss, Set state, the severity) asks first, except
  // posting that text (a POST from the guarded form itself); a live refresh
  // waits instead (htmx:beforeSwap)
  var tg = evt.detail.target, live = evt.detail.triggeringEvent && String(evt.detail.triggeringEvent.type).indexOf('sse:') === 0;
  if (!q && tg && tg.id === 'board' && !live && !(evt.detail.verb !== 'get' && el && el.closest && el.closest('form[data-guard]')) && yarsDirty(tg)) {
    q = 'Discard changes?';
    ok = 'Discard';
  }
  if (!q) return;
  evt.preventDefault();
  // asked while typing in the search box: the next key lands on Cancel
  var typing = evt.detail.triggeringEvent && evt.detail.triggeringEvent.type === 'input';
  // a picked severity shows its saved value again unless confirmed
  var sel = el && el.querySelector && el.tagName === 'FORM' ? el.querySelector('select[data-choose]') : null, chosen = sel ? sel.value : '';
  if (sel) yarsSelectReset(sel);
  yarsConfirm(q, ok, function () { if (sel) sel.value = chosen; evt.detail.issueRequest(true); }, typing);
});

// yarsSelectReset shows a select's value as the server sent it.
function yarsSelectReset(s) {
  for (var i = 0; i < s.options.length; i++) {
    if (s.options[i].defaultSelected) { s.selectedIndex = i; return; }
  }
  s.selectedIndex = 0;
}

/* ---------- section editor states ---------- */

// Unsaved: the editor's heading shows a dot while its text differs.
document.addEventListener('input', function (evt) {
  var form = evt.target.closest && evt.target.closest('form[data-guard]');
  if (form) form.classList.toggle('dirty', yarsDirty(form.parentNode));
});

// Presence: an open editor tells the server every 20 s that it is still
// open, in a hidden tab too: the text is as open there. A hidden tab's
// timers run once a minute at most, so the server forgets an editor only
// after 150 s without a beat.
setInterval(function () {
  document.querySelectorAll('form[data-presence]').forEach(function (f) {
    fetch(f.getAttribute('data-presence'), {method: 'POST', credentials: 'same-origin', headers: {'HX-Request': 'true'}})
      .then(function (r) { if (r.status === 401) yarsExpired(); else if (r.ok) yarsExpiredSaid = false; })
      .catch(function () { /* offline: the next beat tries again */ });
  });
}, 20000);

// Session expired (an htmx request or a heartbeat got 401): every editor's
// unsaved text is kept in localStorage under "yars-draft:<user>:<save URL>",
// and the editor offers it back (Restore) when it is opened again. The key
// names the account, so another account on this browser is never offered
// it; Log out removes the account's drafts (an expired session does not:
// that is when a draft is written), and a draft older than 14 days goes at
// the next page load, whoever is signed in.
function yarsUser() { return document.documentElement.getAttribute('data-user') || ''; }
function yarsDraftKey(form) { return 'yars-draft:' + yarsUser() + ':' + (form.getAttribute('hx-post') || ''); }
// yarsForget removes the entries whose key starts with prefix from
// localStorage, or from st (sessionStorage) when given.
function yarsForget(prefix, st) {
  try {
    st = st || localStorage;
    for (var i = st.length - 1; i >= 0; i--) {
      var k = st.key(i);
      if (k && k.indexOf(prefix) === 0) st.removeItem(k);
    }
  } catch (e) { /* no storage: nothing kept */ }
}
// Left by an earlier version: htmx's page snapshots (none are kept now:
// historyCacheSize 0) and drafts stored without an account ("yars-draft:"
// followed by the save URL's "/").
try { localStorage.removeItem('htmx-history-cache'); } catch (e) { /* no storage */ }
yarsForget('yars-draft:/');
// A draft is kept 14 days from the time it carries. Each page load removes
// the older ones of every account, so the draft of an account that never
// comes back to this browser does not stay for good.
var yarsDraftDays = 14;
function yarsDraftSweep() {
  try {
    for (var i = localStorage.length - 1; i >= 0; i--) {
      var k = localStorage.key(i);
      if (!k || k.indexOf('yars-draft:') !== 0) continue;
      var d = null;
      try { d = JSON.parse(localStorage.getItem(k)); } catch (e) { /* not a draft: goes */ }
      if (!d || typeof d.at !== 'number' || Date.now() - d.at > yarsDraftDays * 86400000) localStorage.removeItem(k);
    }
  } catch (e) { /* no storage: nothing kept */ }
}
yarsDraftSweep();
document.addEventListener('submit', function (evt) {
  if (!evt.target.matches || !evt.target.matches('form[action="/logout"]')) return;
  try { localStorage.removeItem('htmx-history-cache'); } catch (e) { /* no storage */ }
  if (yarsUser()) yarsForget('yars-draft:' + yarsUser() + ':');
  yarsForget('yars-list:' + yarsUser() + ':', sessionStorage);
});

// Findings list: its filter, sort and search are in its address only. The
// list page keeps that query for this tab, account and engagement
// (sessionStorage "yars-list:<user>:<engagement>"), and the links that lead
// back to the list (data-list: the crumb, Findings in the top bar, the
// Findings tab, Cancel of a new finding or retest) get it on every other page. On the list itself they stay
// bare: a click there is the way to the whole list. Log out forgets them.
function yarsListKey(eng) { return 'yars-list:' + yarsUser() + ':' + eng; }
// yarsOnList: the engagement whose findings list this page is, else ''.
function yarsOnList() {
  var m = /^\/e\/([^\/]+)$/.exec(location.pathname);
  return m && document.getElementById('findings') ? m[1] : '';
}
function yarsListKeep() {
  var eng = yarsOnList();
  if (!eng) return;
  try {
    // offset and keep are a page of the list, not the list
    var q = new URLSearchParams(location.search);
    q.delete('offset');
    q.delete('keep');
    var s = q.toString();
    sessionStorage.setItem(yarsListKey(eng), s ? '?' + s : '');
  } catch (e) { /* not kept */ }
}
// the link's own path with the kept query: what is stored never becomes a
// path or another address
function yarsListLinks(root) {
  if (yarsOnList() || !root || !root.querySelectorAll) return;
  Array.prototype.forEach.call(root.querySelectorAll('a[data-list]'), function (a) {
    var s = null;
    try { s = sessionStorage.getItem(yarsListKey(a.getAttribute('data-list'))); } catch (e) { /* none kept */ }
    if (!s || s.charAt(0) !== '?') return;
    a.setAttribute('href', a.pathname + s);
  });
}
document.addEventListener('DOMContentLoaded', function () { yarsListKeep(); yarsListLinks(document); });
['htmx:pushedIntoHistory', 'htmx:replacedInHistory', 'htmx:historyRestore'].forEach(function (n) {
  document.addEventListener(n, yarsListKeep);
});
// the finding's head swaps itself on live events and brings the bare link
document.addEventListener('htmx:load', function (evt) { yarsListLinks(evt.detail.elt && evt.detail.elt.parentNode || document); });
function yarsDraft(form) {
  try { var d = JSON.parse(localStorage.getItem(yarsDraftKey(form)) || 'null'); return d && typeof d.text === 'string' ? d : null; } catch (e) { return null; }
}
// A 401 nobody asked for (a poll, a presence beat) shows the toast once per
// expiry: a page that polls gets one for each of its live parts every 30 s.
// An answered request (a login in another tab) ends the expiry, so a later
// one is said again. A request the user sent (own) says it again unless the
// toast still shows: the first one may have gone unseen in a hidden tab.
var yarsExpiredSaid = false, yarsExpiredToast = null;
function yarsExpired(own) {
  document.querySelectorAll('form[data-guard]').forEach(function (form) {
    var ta = form.querySelector('textarea[name=body]');
    if (!ta || !yarsDirty(form.parentNode)) return;
    // with the base the editor was opened with: restored later, the text is
    // saved against it, so a colleague's newer text shows as a conflict
    var base = form.querySelector('input[name=base]');
    try { localStorage.setItem(yarsDraftKey(form), JSON.stringify({text: ta.value, base: base ? base.value : '', at: Date.now()})); } catch (e) { /* not kept */ }
    var st = form.querySelector('[data-pstate]');
    if (st) { st.textContent = 'Session expired · not saved'; st.classList.add('error'); }
  });
  var shown = yarsExpiredToast && yarsExpiredToast.isConnected;
  if (own ? shown : yarsExpiredSaid) return;
  yarsExpiredSaid = true;
  yarsExpiredToast = yarsToast('Session expired', true);
}
document.addEventListener('htmx:afterRequest', function (evt) {
  var x = evt.detail.xhr;
  if (x && x.status >= 200 && x.status < 400) yarsExpiredSaid = false;
});
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
  // the draft's own base, not this editor's: the text was written over what
  // that one names. A draft kept by an earlier version has none; an empty
  // base would save unchecked, so it gets one that matches no text and the
  // conflict view decides.
  var base = form.querySelector('input[name=base]');
  if (base) base.value = typeof d.base === 'string' && d.base ? d.base : 'none';
  ta.setAttribute('data-dirty', '');
  form.classList.add('dirty');
  b.classList.add('invisible');
  if (window.htmx) htmx.trigger(ta, 'keyup');
});
// a saved or cancelled editor drops its draft. The editor is swapped out by
// then, so htmx fires afterRequest on an ancestor: the key rides on the xhr.
// A conflict (409) or a refused text (400) is swapped in and is no error to
// htmx, but the text is still unsaved: only a 2xx answer drops the draft.
document.addEventListener('htmx:beforeRequest', function (evt) {
  var el = evt.detail.elt;
  if (!el || !el.matches || !evt.detail.xhr) return;
  var form = el.matches('form[data-guard]') ? el : el.hasAttribute('data-guard-cancel') ? el.closest('form[data-guard]') : null;
  if (form) evt.detail.xhr.yarsDraftKey = yarsDraftKey(form);
});
document.addEventListener('htmx:afterRequest', function (evt) {
  var x = evt.detail.xhr, k = x && x.yarsDraftKey;
  if (!k || x.status < 200 || x.status > 299) return;
  try { localStorage.removeItem(k); } catch (e) { /* none kept */ }
});

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
      if (r.status === 401) { yarsExpired(true); return false; }
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
      // a redaction that left a retest's copy as it was (archived, locked)
      // says so; the server escapes it
      var left = r.headers.get('X-Yars-Unredacted');
      if (left) yarsToast(name + ': ' + decodeURIComponent(left), true);
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

// Destinations: Marks reported follows the kind of destination. A service
// (jira, or confluence with an address) marks and a file does not, until the
// box is changed; the hidden mark_for says which kind the box stands for
// (the server does the same for a form saved without this script).
function yarsDestKind(evt) {
  var form = evt.target.closest && evt.target.closest('form.destform');
  if (!form || !evt.target.matches('[name=type], [name=base_url]')) return;
  var e = form.elements, type = e.type.value;
  var kind = type === 'jira' || (type === 'confluence' && e.base_url.value.trim() !== '') ? 'service' : 'file';
  if (!e.mark_for || !e.mark_reported || e.mark_for.value === kind) return;
  e.mark_for.value = kind;
  e.mark_reported.checked = kind === 'service';
}
document.addEventListener('change', yarsDestKind);
document.addEventListener('input', yarsDestKind);
