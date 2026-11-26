/* YARS keyboard (K1–K10): the templates declare what exists (Edit, Save,
   workflow and bulk buttons carry aria-keyshortcuts); one keydown handler finds a rendered,
   enabled control for the key and clicks it. Rights stay on the server: a
   control that is not rendered has no shortcut. */

// yarsKeysOff: shortcuts are switched off for this account.
function yarsKeysOff() { return document.documentElement.getAttribute('data-keys') === 'off'; }

// The templates mark the controls: Edit buttons carry aria-keyshortcuts="E",
// editor Save buttons "Control+S". A section is a section.panel with an id
// (finding page, report tab, template page), kept by id since htmx swaps the
// element.
var yarsFocusAfter = ''; // the section to put focus back into after its swap

function yarsPanelOf(el) {
  return el && el.closest ? el.closest('section.panel[id]') : null;
}

// yarsTyping: the key goes into a field, so single-key shortcuts stay out.
function yarsTyping(t) {
  return !!(t && (t.isContentEditable || (t.closest && t.closest('input, textarea, select, [contenteditable]'))));
}

// yarsFirstField focuses an open editor's first field (or its own autofocus).
function yarsFirstField(p) {
  var f = p.querySelector('[autofocus]') || p.querySelector('textarea, input:not([type=hidden]), select');
  if (f) f.focus();
}

// E (K3): the selected panel only. Its open editor gets focus back; else its
// Edit button is pressed. Nothing selected: nothing.
function yarsEdit() {
  var p = yarsSelected();
  if (!p) return false;
  if (p.classList.contains('editing')) { yarsFirstField(p); return true; }
  var b = p.querySelector('button[aria-keyshortcuts~="E"]:not(:disabled)');
  if (!b) return false;
  yarsFocusAfter = p.id;
  b.click(); // htmx sends the request in the click: beforeRequest moves the id onto it
  yarsFocusAfter = '';
  return true;
}

// Ctrl+S (K3): saves the form holding a focused field, never one marked
// data-nosave (login, setup, set password). In a save conflict it only moves
// focus to Keep mine. In the Redact dialog it presses the dialog's Save.
function yarsSave() {
  var rd = document.querySelector('dialog[open] [data-redact-save]');
  if (rd) { if (!rd.disabled) rd.click(); return; }
  if (document.querySelector('dialog[open]')) return;
  var a = document.activeElement;
  var form = a && a !== document.body && a.closest ? a.closest('form') || a.form : null;
  // nothing being filled in (a focused button, link or row checkbox is not):
  // the findings list's, the team board's or the templates list's search box
  // (no other page's); never from a focused button of a form that saves
  // (nothing, as before), nor with the shortcuts off
  if (!yarsTyping(a) || yarsPick(a)) {
    if (!yarsKeysOff() && !(form && !yarsPick(a) && yarsSaveButton(form))) yarsSearchFocus('#fq, #tb-q, #tpl-q');
    return;
  }
  if (!form || form.hasAttribute('data-nosave')) return;
  var conflict = form.closest('.conflict');
  if (conflict) {
    var keep = conflict.querySelector('.cbar button:not([type=button])');
    if (keep) keep.focus();
    return;
  }
  var btn = yarsSaveButton(form);
  if (!btn || btn.disabled) return;
  var p = yarsPanelOf(form);
  if (p) yarsFocusAfter = p.id;
  btn.click(); // a click, so a confirm on the button still asks
  yarsFocusAfter = ''; // taken by the request, or no request went (a required field)
}

// yarsSaveButton: among the form's own submit buttons (form.elements: one
// outside it with form= counts, a nested one of another form does not), the
// Control+S one; without one, the only submit button, unless it is a
// Control+Enter one (a chat, reply or reason form is sent, not saved). Two
// or more without a Control+S one (a bulk menu, the export cards): none.
function yarsSaveButton(form) {
  var subs = Array.prototype.filter.call(form.elements, function (el) {
    return el.tagName === 'BUTTON' && el.type === 'submit';
  });
  for (var i = 0; i < subs.length; i++) {
    if (yarsHasKey(subs[i], 'Control+S')) return subs[i];
  }
  if (subs.length !== 1 || yarsHasKey(subs[0], 'Control+Enter')) return null;
  return subs[0];
}

// Enter (K3) on a selected panel with no field or control focused presses
// the panel's one button besides Comment and Edit (data-kskip); with none
// or several, nothing. A Settings panel (data-kenter) is gone into instead,
// only with nothing focused: a focused control anywhere (a Save, a nav
// link, a token row) keeps its own Enter.
function yarsEnter() {
  var p = yarsSelected();
  if (!p) return false;
  if (p.hasAttribute('data-kenter')) {
    var cur = document.activeElement;
    if (cur && cur !== document.body && cur !== p) return false;
    return yarsInto(p);
  }
  var a = document.activeElement;
  if (a && a !== document.body && a !== p && a.closest && a.closest('a, button, summary, input, select, textarea, [contenteditable]')) return false;
  // a picked comment: its reply box; a picked duplicate: its Merge
  var t = yarsThread();
  var r = t ? t.querySelector('input[name=text]') : null;
  if (r) { r.focus(); return true; }
  var mg = t ? t.querySelector('[data-merge]') : null;
  if (mg) { mg.click(); return true; }
  var bs = Array.prototype.filter.call(p.querySelectorAll('button:not(:disabled):not([data-kskip]), a.btn:not([data-kskip])'), function (b) {
    return b.getClientRects().length > 0;
  });
  if (bs.length !== 1) return false;
  bs[0].click();
  return true;
}

// yarsInto puts focus in a Settings panel: on its first choice (the checked
// radio of its group), else its first row (Tokens), field or button; true
// when one took it.
function yarsInto(p) {
  var r = p.querySelector('input[type=radio]');
  var f = r ? Array.prototype.filter.call(p.querySelectorAll('input[type=radio]'), function (x) {
    return x.name === r.name && x.checked;
  })[0] || r : null;
  f = f || p.querySelector('[data-nav]') || p.querySelector('input:not([type=hidden]), select, textarea') || p.querySelector('button, a.btn');
  if (!f) return false;
  f.focus();
  return true;
}

// yarsChoiceSave: Enter on a choice (a radio, a checkbox) in a Settings
// panel presses its form's save button, as Enter in a text field does;
// true when it did.
function yarsChoiceSave(t) {
  if (!t || !t.matches || !t.matches('input[type=radio], input[type=checkbox]') || !t.closest('[data-kenter]')) return false;
  var b = t.form ? yarsSaveButton(t.form) : null;
  if (!b || b.disabled) return false;
  b.click();
  return true;
}

// c (K3): a comment on the selected panel (its Comment button's section),
// General when it has none or nothing is selected; finding page only.
function yarsCommentKey() {
  if (!document.getElementById('chat-text')) return false;
  var p = yarsSelected();
  var b = p ? p.querySelector('[data-comment]') : null;
  yarsComment(b ? b.getAttribute('data-comment') : '');
  return true;
}

// yarsKeyOf names a key the way aria-keyshortcuts does: "Shift+A",
// "Control+S", "Control+Enter", "E", "/", "?", "Escape". It reads evt.key
// (never evt.code, so other layouts work), uppercases letters and counts
// Meta as Control. Shift is named for a letter or a named key only: for a
// symbol it is part of the character ("?", not "Shift+?").
function yarsKeyOf(evt) {
  var k = evt.key;
  if (!k || k === 'Unidentified' || k === 'Dead') return '';
  if (k === ' ') k = 'Space';
  var named = k.length > 1;
  if (!named) k = k.toUpperCase();
  var mods = '';
  if (evt.ctrlKey || evt.metaKey) mods += 'Control+';
  if (evt.altKey) mods += 'Alt+';
  if (evt.shiftKey && (named || k.toLowerCase() !== k) && k !== 'Shift') mods += 'Shift+';
  return mods + k;
}

// yarsHasKey: el's aria-keyshortcuts lists key.
function yarsHasKey(el, key) {
  return (el.getAttribute('aria-keyshortcuts') || '').split(/\s+/).indexOf(key) >= 0;
}

// yarsKeyButton: box's own button with key: a form's submit buttons (those
// outside it with form= too), never one of a bulk reason panel (.bdlg)
// inside it, which is its own box.
function yarsKeyButton(box, key) {
  var els = box.tagName === 'FORM' ? box.elements : box.querySelectorAll('button');
  for (var i = 0; i < els.length; i++) {
    var b = els[i];
    if (b.tagName !== 'BUTTON' || !yarsHasKey(b, key)) continue;
    if (box.tagName === 'FORM' && b.closest('.bdlg')) continue;
    return b;
  }
  return null;
}

// yarsPress acts on el as a click would, from a key: a field takes focus
// (n: Add user's Username); a summary opens its popover with focus in its
// first field (d: Dismiss's reason); a link that leaves the page while a
// guarded form holds unsaved text asks first in the page's own dialog (and
// the browser's leave warning then does not ask again).
function yarsPress(el) {
  if (el.matches('input:not([type=checkbox]):not([type=radio]), textarea, select')) { el.focus(); return; }
  if (el.tagName === 'SUMMARY') {
    el.click();
    var box = el.parentNode;
    var f = box && box.open ? box.querySelector('input:not([type=hidden]), textarea') : null;
    if (f) f.focus();
    return;
  }
  if (el.tagName === 'A' && !el.hasAttribute('hx-get') && yarsDirty(document)) {
    yarsConfirm('Discard changes?', 'Discard', function () { yarsLeaving = true; el.click(); });
    return;
  }
  el.click();
}

// yarsFire presses the first rendered, enabled element in scope (default the
// document) whose aria-keyshortcuts lists key; true when one was pressed.
// The bulk menu's entries are yarsBulkFire's.
function yarsFire(key, scope) {
  if (!key) return false;
  var els = (scope || document).querySelectorAll('[aria-keyshortcuts]');
  var cur = yarsRowOf(document.activeElement);
  var curScope = cur && cur.closest ? cur.closest('[data-keys-scope]') : null;
  var curRow = cur && cur.closest ? cur.closest('tr') : null;
  for (var i = 0; i < els.length; i++) {
    var el = els[i];
    // a row's own buttons are yarsRowFire's (the focused row only)
    if (!yarsHasKey(el, key) || el.closest('.bmenu') || el.closest('tr[data-rowkeys]')) continue;
    if (el.offsetParent === null || el.disabled) continue;
    // a section's own key (the inbox's Mark all read): with a row focused,
    // that row's section only
    var own = el.closest('[data-keys-scope]');
    if (own && curScope && own !== curScope) continue;
    // the open lead's m and d: not while another lead's row has focus
    if (el.closest('.tbacts') && curRow && !curRow.classList.contains('sel')) continue;
    yarsPress(el);
    return true;
  }
  return false;
}

// yarsBulkFire (K4): Shift+S, A and P press the bulk Set state entry with
// that key (the menu may be closed) while its form has a ticked row; an entry
// no ticked row can take is disabled, so its key does nothing. On a page with
// a workflow bar the bar's keys win.
function yarsBulkFire(key) {
  if (!key || document.getElementById('workflow')) return false;
  var forms = document.querySelectorAll('.fbulkform');
  for (var i = 0; i < forms.length; i++) {
    if (!forms[i].querySelector('input[name=id]:checked')) continue;
    var items = forms[i].querySelectorAll('.bmenu [aria-keyshortcuts]');
    for (var j = 0; j < items.length; j++) {
      if (!yarsHasKey(items[j], key) || items[j].disabled) continue;
      items[j].click();
      return true;
    }
  }
  return false;
}

// yarsRowFire: a key of the focused row's own buttons, in a row marked
// data-rowkeys (the engagements list: a Archive, r Reopen; Admin › Users: u
// Unlock, r Reset pass, d Disable); never another row's, so with no row
// focused the key does nothing.
function yarsRowFire(key) {
  var row = yarsRowOf(document.activeElement);
  var tr = row && row.closest ? row.closest('tr[data-rowkeys]') : null;
  if (!tr || !key) return false;
  var els = tr.querySelectorAll('[aria-keyshortcuts]');
  for (var i = 0; i < els.length; i++) {
    if (!yarsHasKey(els[i], key) || els[i].disabled || els[i].offsetParent === null) continue;
    yarsKeepRow(els[i], row);
    yarsPress(els[i]);
    return true;
  }
  return false;
}

// A row key's button that posts its own form (d's toggle, r's Revoke or
// Reset pass, a's Archive: not htmx) reloads the page; the next page focuses
// the same row again: by its id, else the row now at its place in the same
// list (a revoked token's row is gone). Kept once the form is sent (a
// cancelled confirm keeps nothing), for the next page of this tab only and
// a few seconds. The list is told by its table's class: Archive from / comes
// back on /engagements, Reset pass on its own URL.
var yarsRowKeep = 'yars-row-keep';
var yarsKeepNext = null; // {form, row}: the form a row key pressed
function yarsKeepRow(el, row) {
  var f = el.tagName === 'BUTTON' && el.type === 'submit' ? el.form : null;
  yarsKeepNext = f && f.method === 'post' && !f.hasAttribute('hx-post') && row.closest('table') ? {form: f, row: row} : null;
}
document.addEventListener('submit', function (evt) {
  // a confirm's OK sends the dialog's own form first, then the row's
  if (evt.target.method === 'dialog') return;
  var k = yarsKeepNext;
  yarsKeepNext = null;
  if (!k || evt.target !== k.form || evt.defaultPrevented) return;
  var table = k.row.closest('table');
  var rows = yarsRows().filter(function (r) { return table.contains(r); });
  try {
    sessionStorage.setItem(yarsRowKeep, JSON.stringify({list: table.className, id: k.row.id, i: rows.indexOf(k.row), at: Date.now()}));
  } catch (e) { /* not kept */ }
});
// a confirm answered Cancel (or Esc) sends nothing (close does not bubble)
document.addEventListener('close', function (evt) {
  if (evt.target.id === 'confirm' && evt.target.returnValue !== 'ok') yarsKeepNext = null;
}, true);
document.addEventListener('DOMContentLoaded', function () {
  var k = null;
  try {
    var raw = sessionStorage.getItem(yarsRowKeep);
    sessionStorage.removeItem(yarsRowKeep);
    k = JSON.parse(raw || 'null');
  } catch (e) { return; }
  if (!k || !(Date.now() - k.at < 10000)) return;
  var a = document.activeElement;
  if (a && a !== document.body) return; // the page put focus somewhere itself
  var table = Array.prototype.filter.call(document.querySelectorAll('table'), function (x) {
    return x.className === k.list;
  })[0];
  if (!table) return;
  var rows = yarsRows().filter(function (r) { return table.contains(r); });
  var el = k.id ? document.getElementById(k.id) : null;
  if (rows.indexOf(el) < 0) el = rows[Math.min(Math.max(k.i, 0), rows.length - 1)];
  if (!el) return;
  // the browser handles a fragment (an address with #panel) after this
  // event: it would jump to the panel and take the focus off the row
  if (location.hash) history.replaceState(history.state, '', location.pathname + location.search);
  el.focus({preventScroll: true});
  // a password shown once (Reset pass) stays in view
  if (el.scrollIntoView && !document.querySelector('.once')) el.scrollIntoView({block: 'nearest'});
});

// A form sent from a page part marked data-keep-place (Settings' panels)
// reloads the page; the next page of this tab, within a few seconds, goes
// back to the same scroll position with the same panel selected and focus
// on the same control (a radio group: its checked radio), so a save never
// jumps. A row a key kept (yarsRowKeep, run first) keeps the focus.
var yarsPlaceKeep = 'yars-place-keep';
document.addEventListener('submit', function (evt) {
  var f = evt.target;
  if (evt.defaultPrevented || f.method === 'dialog' || !f.closest || !f.closest('[data-keep-place]')) return;
  var a = document.activeElement;
  var name = a && a.form === f && a.name ? a.name : '';
  // a checkbox is told by its value too (every Notifications box is "n")
  var value = name && (a.type === 'checkbox' || a.type === 'radio') ? a.value : '';
  try {
    sessionStorage.setItem(yarsPlaceKeep, JSON.stringify({y: window.scrollY, sel: yarsSel, form: f.id, name: name, value: value, at: Date.now()}));
  } catch (e) { /* not kept */ }
});
document.addEventListener('DOMContentLoaded', function () {
  var k = null;
  try {
    var raw = sessionStorage.getItem(yarsPlaceKeep);
    sessionStorage.removeItem(yarsPlaceKeep);
    k = JSON.parse(raw || 'null');
  } catch (e) { return; }
  if (!k || !(Date.now() - k.at < 10000) || !document.querySelector('[data-keep-place]')) return;
  if (location.hash) history.replaceState(history.state, '', location.pathname + location.search);
  // smooth scrolling (html) would animate the way back
  window.scrollTo({top: k.y, behavior: 'instant'});
  var p = k.sel ? document.getElementById(k.sel) : null;
  // with the shortcuts off nothing is selected (its outline would stay)
  if (p && p.hasAttribute('data-kpanel') && !yarsKeysOff()) yarsSelect(p, false);
  var a = document.activeElement;
  if (a && a !== document.body) return;
  var f = k.form ? document.getElementById(k.form) : null;
  if (!f || !k.name) return;
  var els = Array.prototype.filter.call(f.elements, function (x) { return x.name === k.name; });
  // a radio group: its checked radio; a checkbox: the one with that value
  if (k.value) els = els.filter(function (x) { return x.type === 'radio' || x.value === k.value; });
  var el = els.filter(function (x) { return x.type === 'radio' && x.checked; })[0] || els[0];
  if (el) el.focus({preventScroll: true});
});

// yarsPick: a list's row checkbox takes no characters, so the list keys work
// with it focused (a click on it leaves focus there).
function yarsPick(t) {
  return !!(t && t.matches && t.matches('.fbulkform input[type=checkbox][name=id], .fbulkform [data-pick-all], input[type=checkbox][data-nav]'));
}

/* ---------- lists (K7): j/k move the row focus, x ticks, / searches ---------- */

// yarsRows: the rendered, enabled [data-nav] controls (one per row) in
// document order (a disabled export pick cannot take focus).
function yarsRows() {
  return Array.prototype.filter.call(document.querySelectorAll('[data-nav]'), function (el) {
    return !el.disabled && el.getClientRects().length > 0;
  });
}
// yarsRowOf: the [data-nav] control of the row holding el.
function yarsRowOf(el) {
  if (!el || !el.closest) return null;
  var n = el.closest('[data-nav]');
  if (n) return n;
  var tr = el.closest('tr');
  return tr ? tr.querySelector('[data-nav]') : null;
}
// yarsRowStep focuses the next (d = 1) or previous (d = -1) row; with none
// focused, the first.
function yarsRowStep(d) {
  var rows = yarsRows();
  if (!rows.length) return false;
  var i = rows.indexOf(yarsRowOf(document.activeElement));
  var to = i < 0 ? rows[0] : rows[Math.max(0, Math.min(rows.length - 1, i + d))];
  to.focus();
  if (to.scrollIntoView) to.scrollIntoView({block: 'nearest'});
  return true;
}
// yarsRowBox: the checkbox of the focused row of a list (one with data-nav).
function yarsRowBox() {
  var a = document.activeElement;
  if (!yarsRowOf(a)) return null;
  var tr = a && a.closest ? a.closest('tr') : null;
  var cb = tr ? tr.querySelector('input[type=checkbox]') : null;
  return cb && !cb.disabled ? cb : null;
}
// yarsListNav handles the list keys on pages without panels; true when used.
// x ticks the focused row; Shift+Space ticks the range from the row last
// clicked to it (app.js yarsRange; bulk lists only). The digits are the
// state filters' own (aria-keyshortcuts, yarsFire); ↓ ↑ are yarsArrowKey's.
function yarsListNav(key) {
  if (document.querySelector('[data-kpanel]')) return false;
  var cb;
  switch (key) {
  case 'J': return yarsRowStep(1);
  case 'K': return yarsRowStep(-1);
  case 'X':
    if (!(cb = yarsRowBox())) return false;
    cb.click();
    return true;
  case 'Shift+Space':
    if (!(cb = yarsRowBox()) || !cb.closest('.fbulkform') || cb.name !== 'id') return false;
    yarsRange(cb, !cb.checked);
    return true;
  }
  return false;
}
// yarsArrowKey: on a list page ([data-arrows]) ↓ ↑ move the row focus as j k
// do, held down too, and the page does not scroll instead; never in a field,
// an open menu or under a dialog. A table among other things
// (data-arrows="focus": Settings' tokens, Admin's users, rules, webhooks)
// takes them only from one of its rows, and past its first or last row the
// page scrolls again, so what is above and below stays in reach. True when
// used.
function yarsArrowKey(evt, key) {
  if ((key !== 'ArrowDown' && key !== 'ArrowUp') || !document.querySelector('[data-arrows]')) return false;
  if (yarsKeysOff() || evt.isComposing || evt.defaultPrevented || document.querySelector('dialog[open]')) return false;
  var t = evt.target;
  if ((yarsTyping(t) && !yarsPick(t)) || (t.closest && t.closest('.bmenu, [role=menu]'))) return false;
  var d = key === 'ArrowDown' ? 1 : -1;
  var mixed = document.querySelector('[data-arrows=focus]');
  if (mixed) {
    var row = yarsRowOf(document.activeElement);
    if (!row || !mixed.contains(row)) return false;
    var rows = yarsRows(), i = rows.indexOf(row);
    if (i + d < 0 || i + d >= rows.length) return false;
  }
  if (!yarsRowStep(d)) return false; // no rows: the page scrolls
  evt.preventDefault();
  return true;
}
// After Load more (the row tr.more swaps itself for the next rows), focus
// goes to the first new row: only when it was on Load more and is lost in the
// swap (not when the user went on to Search meanwhile).
var yarsMoreAt = null;
document.addEventListener('htmx:beforeSwap', function (evt) {
  var t = evt.detail.target;
  if (t && t.matches && t.matches('tr.more') && evt.detail.shouldSwap && t.contains(document.activeElement)) {
    yarsMoreAt = {prev: t.previousElementSibling, body: t.parentNode};
  }
});
document.addEventListener('htmx:afterSettle', function () {
  var m = yarsMoreAt;
  if (!m) return;
  yarsMoreAt = null;
  var a = document.activeElement;
  if (a && a !== document.body) return;
  var first = m.prev ? m.prev.nextElementSibling : m.body.firstElementChild;
  var nav = first && !first.matches('tr.more') ? first.querySelector('[data-nav]') : null;
  if (nav) nav.focus();
});
// A click on a list row (a table with data-arrows, a row with data-rowkeys)
// outside the row's own controls selects the row as j k do, without a
// scroll, so it is tinted and its keys work; never while text is being
// selected. The team board's rows open on a click instead (app.js).
document.addEventListener('click', function (evt) {
  var t = evt.target;
  if (yarsKeysOff() || evt.defaultPrevented || !t.closest) return;
  var tr = t.closest('tr');
  if (!tr || tr.hasAttribute('data-rowclick') || !(tr.hasAttribute('data-rowkeys') || tr.closest('table[data-arrows]'))) return;
  var on = t.closest('a, button, input, select, textarea, label, summary, details, [tabindex], [contenteditable]');
  if (on && tr.contains(on)) return;
  var s = window.getSelection ? window.getSelection() : null;
  if (s && !s.isCollapsed) return;
  var nav = yarsRowOf(t);
  if (nav && !nav.disabled) nav.focus({preventScroll: true});
});

// ? (K8): the shortcut list of this page: its Finding page group only where
// there are panels, its Lists group only where there are rows, its Chat group
// only where there is a chat, and a row tied to a key ([data-keys-for]) only
// where a control carries that key (rendered for this viewer). Esc closes it
// (the browser's own), as does a click outside it.
function yarsKeysList() {
  var d = document.getElementById('keys');
  if (!d || !d.showModal || d.open) return false;
  var show = function (sel, on) { var g = d.querySelector(sel); if (g) g.hidden = !on; };
  // Settings' panels (data-kenter) have a group of their own
  var kenter = document.querySelector('[data-kenter]');
  show('[data-keys-group="finding"]', document.querySelector('[data-kpanel]') && !kenter);
  show('[data-keys-group="settings"]', kenter);
  show('[data-keys-group="lists"]', document.querySelector('[data-nav]') && !kenter);
  show('[data-keys-group="chat"]', document.getElementById('chat-text'));
  show('[data-keys-group="eng"]', document.querySelector('.etabs'));
  d.querySelectorAll('[data-keys-for]').forEach(function (row) {
    row.hidden = !document.querySelector('[aria-keyshortcuts~="' + row.getAttribute('data-keys-for') + '"]');
  });
  // a row that needs something else on the page (the chat, the Redact
  // dialog, row checkboxes): [data-keys-if] names it
  d.querySelectorAll('[data-keys-if]').forEach(function (row) {
    row.hidden = !document.querySelector(row.getAttribute('data-keys-if'));
  });
  d.showModal();
  return true;
}
document.addEventListener('click', function (evt) {
  var d = document.getElementById('keys');
  if (d && d.open && evt.target === d) d.close();
});

// yarsSearchBox: the page's own search box matching sel (default: any; never
// Go to's), rendered and enabled, or null.
function yarsSearchBox(sel) {
  return Array.prototype.filter.call(document.querySelectorAll(sel || 'input[type=search]'), function (el) {
    return !el.closest('dialog') && !el.disabled && el.getClientRects().length > 0;
  })[0] || null;
}
// yarsSearchFocus puts focus in that search box, its text selected; false
// without one.
function yarsSearchFocus(sel) {
  var s = yarsSearchBox(sel);
  if (!s) return false;
  s.focus();
  s.select();
  return true;
}

// / (K6): the page's search box; without one, Go to.
function yarsSlash() {
  if (yarsSearchFocus()) return true;
  if (!document.getElementById('goto')) return false;
  yarsGotoOpen();
  return true;
}

/* ---------- selection (K2): a click or j/k selects a panel ---------- */

// yarsSel is the selected panel's id (htmx swaps the element; the id stays);
// yarsSideFrom the main panel selected before l or → went to the side panel.
var yarsSel = '';
var yarsSideFrom = '';

// yarsSelected: the selected panel, while it is shown (a hidden chat is not
// selected: no key acts in it)
function yarsSelected() {
  var p = yarsSel ? document.getElementById(yarsSel) : null;
  return p && p.hasAttribute('data-kpanel') && p.getClientRects().length > 0 ? p : null;
}

// yarsSelect marks el selected (null: nothing); a key (scroll true) also
// keeps it in view, a click never scrolls. The mark is an outline, so
// nothing moves. A main panel is remembered for h and ←.
function yarsSelect(el, scroll) {
  document.querySelectorAll('[data-kpanel][data-sel]').forEach(function (p) {
    if (p !== el) p.removeAttribute('data-sel');
  });
  yarsSel = el && el.id ? el.id : '';
  if (!el || el.getAttribute('data-kpanel') !== 'side') yarsThreadMark(null); // a comment is the chat's
  if (!el) return;
  el.setAttribute('data-sel', '');
  if (el.getAttribute('data-kpanel') !== 'side') yarsSideFrom = el.id;
  if (!scroll) return;
  // a key also takes focus off a control left in another panel (a saved
  // panel's Edit button), so Enter and Space act on the selection
  var a = document.activeElement;
  if (a && a !== document.body && !yarsTyping(a) && !el.contains(a) && a.blur) a.blur();
  if (el.scrollIntoView) el.scrollIntoView({block: 'nearest'});
}

document.addEventListener('pointerdown', function (evt) {
  if (yarsKeysOff()) return; // with shortcuts off nothing uses a selection
  var p = evt.target.closest && evt.target.closest('[data-kpanel]');
  if (p) yarsSelect(p, false);
  // a click in the chat picks the comment it is in (or none)
  if (p && p.getAttribute('data-kpanel') === 'side') yarsThreadMark(evt.target.closest(yarsSideItems), false);
}, true);
// a swapped panel (live refresh, editor) keeps its mark: put back on the
// swap, before htmx's settle delay, so it does not blink
function yarsRemark() {
  var p = yarsSelected();
  if (p && !p.hasAttribute('data-sel')) p.setAttribute('data-sel', '');
}
document.addEventListener('htmx:afterSwap', yarsRemark);
document.addEventListener('htmx:afterSettle', yarsRemark);

// yarsMainPanels: the selectable main panels in document order (rendered).
function yarsMainPanels() {
  return Array.prototype.filter.call(document.querySelectorAll('[data-kpanel]:not([data-kpanel="side"])'), function (p) {
    return p.getClientRects().length > 0;
  });
}

// yarsStep selects the next (d = 1) or previous (d = -1) main panel; with
// nothing selected (or the side panel), the first.
function yarsStep(d) {
  var list = yarsMainPanels();
  if (!list.length) return false;
  var i = list.indexOf(yarsSelected());
  if (i < 0) { yarsSelect(list[0], true); return true; }
  yarsSelect(list[Math.max(0, Math.min(list.length - 1, i + d))], true);
  return true;
}

// yarsSide selects the side panel (l, →); yarsBack, from there, returns to
// the main panel selected last (h, ←).
function yarsSide() {
  // the chat, though Possible duplicates sit above it in the same column
  var s = document.querySelector('#chat[data-kpanel="side"]') || document.querySelector('[data-kpanel="side"]');
  if (!s) return false;
  if (yarsChatHidden()) yarsChat(true); // l shows a hidden chat
  yarsSelect(s, true);
  // a duplicate picked before stays behind
  var t = yarsThread();
  if (t && !s.contains(t)) yarsThreadMark(null);
  return true;
}
function yarsBack() {
  var cur = yarsSelected();
  if (!cur || cur.getAttribute('data-kpanel') !== 'side') return false;
  var p = yarsSideFrom ? document.getElementById(yarsSideFrom) : null;
  if (!p || !p.hasAttribute('data-kpanel')) return false;
  yarsSelect(p, true);
  return true;
}

/* ---------- the side column: j k ↓ ↑ pick a duplicate or a comment ---------- */

// yarsThreadSel is the picked item's element id: a possible duplicate's row
// (dup-<ID>) or a comment (t-<its thread's root message>; the chat list is
// swapped by live refreshes, the id stays). An item is picked only while a
// side panel (Possible duplicates, the chat) is selected.
var yarsThreadSel = '';
var yarsSideItems = '#chat-list .thread[data-thread], #dups tr[data-pick]';

// yarsThreads: the side column's rendered items, top to bottom (the
// duplicates, then the comments).
function yarsThreads() {
  return Array.prototype.filter.call(document.querySelectorAll(yarsSideItems), function (t) {
    return t.getClientRects().length > 0;
  });
}
// yarsThread: the picked item, while a side panel is selected.
function yarsThread() {
  var s = yarsSelected();
  if (!yarsThreadSel || !s || s.getAttribute('data-kpanel') !== 'side') return null;
  return document.getElementById(yarsThreadSel);
}
// yarsThreadMark picks t (null: none): tinted as a list row; a key also
// keeps it in view.
function yarsThreadMark(t, scroll) {
  document.querySelectorAll('[data-tsel]').forEach(function (x) {
    if (x !== t) x.removeAttribute('data-tsel');
  });
  yarsThreadSel = t ? t.id : '';
  if (!t) return;
  t.setAttribute('data-tsel', '');
  if (scroll && t.scrollIntoView) t.scrollIntoView({block: 'nearest'});
}
// yarsThreadPick picks t and selects the panel it is in (a step from the
// last duplicate to the first comment moves into the chat).
function yarsThreadPick(t) {
  var p = t.closest('[data-kpanel]');
  if (p && p !== yarsSelected()) yarsSelect(p, false);
  yarsThreadMark(t, true);
}
// yarsThreadStep picks the next (d = 1) or previous (d = -1) item; with
// none picked, the first (↓) or the last (↑).
function yarsThreadStep(d) {
  var list = yarsThreads();
  if (!list.length) return false;
  var i = list.indexOf(yarsThread());
  if (i >= 0) {
    yarsThreadPick(list[Math.max(0, Math.min(list.length - 1, i + d))]);
    return true;
  }
  // nothing picked: start in the selected panel (the chat's first comment
  // after l), else anywhere in the column
  var s = yarsSelected();
  var own = list.filter(function (x) { return s && s.contains(x); });
  var from = own.length ? own : list;
  yarsThreadPick(d > 0 ? from[0] : from[from.length - 1]);
  return true;
}
// yarsResolveKey: r resolves the picked comment (its Resolve button).
function yarsResolveKey() {
  var t = yarsThread();
  var b = t ? t.querySelector('.thread-tools [name=resolves] + button') : null;
  if (!b || b.disabled) return false;
  b.click();
  return true;
}
// yarsWrite: with the chat selected, a character no key took starts
// writing: the picked comment's reply, else a new message, with the
// character in it.
function yarsWrite(evt) {
  var s = yarsSelected();
  if (!s || s.getAttribute('data-kpanel') !== 'side' || !evt.key || evt.key.length !== 1 || evt.key === ' ') return false;
  var t = yarsThread();
  var f = t ? t.querySelector('input[name=text]') : null;
  if (!f) f = document.getElementById('chat-text');
  if (!f || f.disabled) return false;
  f.focus();
  f.setRangeText(evt.key, f.value.length, f.value.length, 'end');
  f.dispatchEvent(new Event('input', {bubbles: true}));
  return true;
}
// a refreshed list keeps the picked comment (gone: none)
document.addEventListener('htmx:afterSwap', function () {
  if (!yarsThreadSel) return;
  var t = document.getElementById(yarsThreadSel);
  if (t) t.setAttribute('data-tsel', '');
  else yarsThreadSel = '';
});

// yarsEscape closes the topmost thing: an open dialog (the browser's own),
// an open popover, a reason or dismiss form, the selected panel's open editor
// (asking before it drops changes), the focus in a field, the selection.
function yarsEscape() {
  if (document.querySelector('dialog[open]')) return;
  var pop = document.querySelector('details.pop[open]');
  if (pop) {
    pop.open = false;
    var sum = pop.querySelector('summary');
    if (sum) sum.focus();
    return;
  }
  var forms = [['.wfpanel', '[data-reason-cancel]'], ['.dismissrow', '[data-dismiss-cancel]'], ['.bdlg', '[data-bulk-cancel]']];
  for (var i = 0; i < forms.length; i++) {
    var open = Array.prototype.filter.call(document.querySelectorAll(forms[i][0]), function (el) { return !el.hidden && el.getClientRects().length > 0; });
    if (open.length) {
      var c = open[0].querySelector(forms[i][1]);
      if (c) { c.click(); return; }
    }
  }
  // the editor holding focus first (Tab moves focus, not the selection);
  // a field outside every editor (the chat composer) is left before the
  // selected editor is cancelled
  var a = document.activeElement;
  var sel = yarsSelected();
  var ed = a && a.closest ? a.closest('[data-kpanel].editing') : null;
  if (!ed && a && a !== document.body && yarsTyping(a)) { a.blur(); return; }
  if (!ed && sel && sel.classList.contains('editing')) ed = sel;
  var cancel = ed ? ed.querySelector('[data-guard-cancel]') : null;
  if (cancel) { cancel.click(); return; }
  if (a && a !== document.body && yarsTyping(a)) { a.blur(); return; }
  // in a Settings panel: out of its row or button, back to the panel
  if (sel && sel.hasAttribute('data-kenter') && a && a !== document.body && sel.contains(a)) { a.blur(); return; }
  if (yarsThread()) { yarsThreadMark(null); return; } // the picked comment, then the chat
  if (sel) yarsSelect(null);
}

// yarsNav handles the navigation keys of the panel pages; true when used.
// j k ↓ ↑ step the main panels (with none selected, the first), or the
// comments while the chat is selected; → goes to the chat from anywhere but
// the chat, ← back from it.
function yarsNav(key) {
  if (!document.querySelector('[data-kpanel]')) return false;
  var sel = yarsSelected();
  var main = !!sel && sel.getAttribute('data-kpanel') !== 'side';
  var side = !!sel && !main;
  switch (key) {
  // in the chat j k h are its own even with nothing to step to (never written)
  case 'J': return side ? yarsThreadStep(1) || true : yarsStep(1);
  case 'K': return side ? yarsThreadStep(-1) || true : yarsStep(-1);
  case 'ArrowDown': return side ? yarsThreadStep(1) : yarsStep(1);
  case 'ArrowUp': return side ? yarsThreadStep(-1) : yarsStep(-1);
  case 'L': return yarsSide();
  case 'ArrowRight': return !side && yarsSide();
  case 'H': return yarsBack() || side;
  case 'ArrowLeft': return side && yarsBack();
  }
  return false;
}

document.addEventListener('keydown', function (evt) {
  var key = yarsKeyOf(evt);
  if (key === 'Control+S') {
    // never the browser's "Save page" dialog on a YARS page
    evt.preventDefault();
    if (!evt.repeat) yarsSave();
    return;
  }
  if (key === 'Control+Z') {
    // the Redact dialog's Undo; elsewhere the browser's own
    var undo = document.querySelector('dialog[open] [data-redact-undo]');
    if (undo) { evt.preventDefault(); undo.click(); }
    return;
  }
  if (key === 'Control+Enter') {
    // the key map's small forms only (chat, reply, the reason forms, the
    // reviewer picker): their Control+Enter button is pressed, so a confirm
    // or a disabled button still holds; anywhere else (a link opens in a new
    // tab) the browser's own
    if (evt.defaultPrevented || evt.isComposing) return;
    var t = evt.target;
    if (!t.closest || t.closest('a')) return;
    var box = t.closest('.bdlg') || t.closest('form');
    var send = box ? yarsKeyButton(box, 'Control+Enter') : null;
    if (!send) return;
    evt.preventDefault();
    if (!evt.repeat && !send.disabled) send.click();
    return;
  }
  if (key === 'Control+H') {
    // hides or shows the chat (the finding page's toggle); anywhere else the
    // browser's own (History)
    var tg = document.querySelector('[data-chat-toggle]');
    if (!tg || yarsKeysOff() || evt.isComposing || document.querySelector('dialog[open]')) return;
    evt.preventDefault();
    if (evt.repeat) return;
    var inChat = yarsSelected() && yarsSelected().getAttribute('data-kpanel') === 'side';
    tg.click();
    // hiding the selected chat goes back to the panel it was entered from
    if (inChat && yarsChatHidden()) {
      var back = yarsSideFrom ? document.getElementById(yarsSideFrom) : null;
      yarsSelect(back && back.hasAttribute('data-kpanel') ? back : null, true);
    }
    return;
  }
  // Esc during IME composition cancels the composition only
  if (key === 'Escape') { if (!evt.isComposing && !evt.repeat) yarsEscape(); return; }
  // Enter on a list's checkbox (app.js keeps it from submitting the form)
  // opens the row, with shortcuts on
  if (key === 'Enter' && yarsPick(evt.target)) {
    if (yarsKeysOff() || evt.repeat || evt.isComposing) return;
    var row = yarsRowOf(evt.target);
    if (row && row.tagName === 'A') row.click();
    return;
  }
  if (key === 'Enter' && !yarsKeysOff() && !evt.repeat && !evt.isComposing && yarsChoiceSave(evt.target)) { evt.preventDefault(); return; }
  if (yarsArrowKey(evt, key)) return;
  // single keys and Shift+key: never into a field, during composition, on
  // repeat, under a modal dialog, or with shortcuts off
  if (yarsKeysOff() || evt.isComposing || evt.repeat || evt.altKey || evt.defaultPrevented ||
      (yarsTyping(evt.target) && !yarsPick(evt.target)) || document.querySelector('dialog[open]')) return;
  if (evt.ctrlKey || evt.metaKey) return; // the browser's own (Ctrl+K is app.js's)
  if (yarsNav(key) || yarsListNav(key)) { evt.preventDefault(); return; }
  if (key === '/') { if (yarsSlash()) evt.preventDefault(); return; }
  if (key === '?') { if (yarsKeysList()) evt.preventDefault(); return; }
  // e edits the selected panel; on a page without panels it is Export's; in
  // the chat it writes
  if (key === 'E') { if (yarsEdit() || yarsRowFire('E') || (!document.querySelector('[data-kpanel]') && yarsFire('E')) || yarsWrite(evt)) evt.preventDefault(); return; }
  if (key === 'Enter') { if (yarsEnter()) evt.preventDefault(); return; }
  // c comments on the finding page; elsewhere it copies the clone command
  if (key === 'C') { if (yarsCommentKey() || yarsFire('C')) evt.preventDefault(); return; }
  // r is the picked comment's (a resolved one: nothing), never written
  if (key === 'R' && (yarsResolveKey() || yarsThread())) { evt.preventDefault(); return; }
  // a key nothing took: in the chat it starts writing
  if (yarsRowFire(key) || yarsFire(key) || yarsBulkFire(key) || yarsWrite(evt)) evt.preventDefault();
});

// After a keyboard edit or save the section keeps focus: an open editor on
// its first field, a saved section on its Edit button. yarsFocusAfter rides
// on the request the key sent (its xhr), so only that answer's swap takes
// focus: never a live refresh of the panel, nor a later swap after a request
// that failed or never went.
document.addEventListener('htmx:afterSettle', function (evt) {
  var xhr = evt.detail.xhr;
  var want = xhr && xhr.yarsFocus;
  var t = evt.detail.target;
  if (!want || !t || t.id !== want) return;
  xhr.yarsFocus = '';
  var p = document.getElementById(want);
  if (!p) return;
  if (p.classList.contains('editing')) { yarsFirstField(p); return; }
  var b = p.querySelector('button[aria-keyshortcuts~="E"]');
  if (b) { b.focus({preventScroll: true}); return; }
  p.setAttribute('tabindex', '-1');
  p.focus({preventScroll: true});
});
document.addEventListener('htmx:beforeRequest', function (evt) {
  var el = evt.detail.elt;
  if (!el || !el.matches) return;
  // a cancelled editor (Esc or a click on Cancel) gives focus back to its
  // panel too; set when the request really goes (not when "Discard
  // changes?" is answered No)
  if (el.matches('[data-guard-cancel]')) {
    var p = el.closest('[data-kpanel][id]');
    if (p) yarsFocusAfter = p.id;
  }
  // the panel's own request is a live refresh, not the key's
  if (!yarsFocusAfter || !evt.detail.xhr || el.id === yarsFocusAfter) return;
  evt.detail.xhr.yarsFocus = yarsFocusAfter;
  yarsFocusAfter = '';
});
