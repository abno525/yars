/* YARS keyboard (K1–K10): the templates declare what exists (Edit, Save,
   workflow and bulk buttons carry aria-keyshortcuts); one keydown handler finds a rendered,
   enabled control for the key and clicks it. Rights stay on the server: a
   control that is not rendered has no shortcut. */

// yarsKeysOff: shortcuts are switched off for this account.
function yarsKeysOff() { return document.documentElement.getAttribute('data-keys') === 'off'; }

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

// E (K3): the selected panel only. Its open editor gets focus back; else its
// Edit button is pressed. Nothing selected: nothing.
function yarsEdit() {
  var p = yarsSelected();
  if (!p) return false;
  if (p.classList.contains('editing')) { yarsFirstField(p); return true; }
  var b = p.querySelector('button[aria-keyshortcuts~="E"]:not(:disabled)');
  if (!b) return false;
  yarsFocusAfter = p.id;
  b.click();
  return true;
}

// Ctrl+S (K3): saves the form holding focus, never one marked data-nosave
// (login, setup, set password). In a save conflict it only moves focus to
// Keep mine. The button is the form's Control+S one (never a first submit
// button such as Clear vector), else its first submit button; a disabled
// one does nothing. In the Redact dialog it presses the dialog's Save.
function yarsSave() {
  var rd = document.querySelector('dialog[open] [data-redact-save]');
  if (rd) { if (!rd.disabled) rd.click(); return; }
  if (document.querySelector('dialog[open]')) return;
  var a = document.activeElement;
  var form = a && a.closest ? a.closest('form') : null;
  if (!form || form.hasAttribute('data-nosave')) return;
  var conflict = form.closest('.conflict');
  if (conflict) {
    var keep = conflict.querySelector('.cbar button:not([type=button])');
    if (keep) keep.focus();
    return;
  }
  var btn = form.querySelector('[aria-keyshortcuts~="Control+S"]') || form.querySelector('button:not([type=button])');
  if (!btn || btn.disabled) return;
  var p = yarsPanelOf(form);
  if (p) yarsLastPanel = yarsFocusAfter = p.id;
  form.requestSubmit(btn);
}

// Enter (K3) on a selected panel with no field or control focused presses
// the panel's one button besides Comment and Edit (data-kskip); with none
// or several, nothing.
function yarsEnter() {
  var p = yarsSelected();
  if (!p) return false;
  var a = document.activeElement;
  if (a && a !== document.body && a !== p && a.closest && a.closest('a, button, summary, input, select, textarea, [contenteditable]')) return false;
  var bs = Array.prototype.filter.call(p.querySelectorAll('button:not(:disabled):not([data-kskip]), a.btn:not([data-kskip])'), function (b) {
    return b.getClientRects().length > 0;
  });
  if (bs.length !== 1) return false;
  bs[0].click();
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

// yarsFire clicks the first rendered, enabled element in scope (default the
// document) whose aria-keyshortcuts lists key; true when one was clicked.
// The bulk menu's entries are yarsBulkFire's.
function yarsFire(key, scope) {
  if (!key) return false;
  var els = (scope || document).querySelectorAll('[aria-keyshortcuts]');
  for (var i = 0; i < els.length; i++) {
    var el = els[i];
    if (!yarsHasKey(el, key) || el.closest('.bmenu')) continue;
    if (el.offsetParent === null || el.disabled) continue;
    el.click();
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

// yarsPick: a list's row checkbox takes no characters, so the list keys work
// with it focused (a click on it leaves focus there).
function yarsPick(t) {
  return !!(t && t.matches && t.matches('.fbulkform input[type=checkbox], input[type=checkbox][data-nav]'));
}

/* ---------- lists (K7): j/k move the row focus, x ticks, / searches ---------- */

// yarsRows: the rendered [data-nav] controls (one per row) in document order.
function yarsRows() {
  return Array.prototype.filter.call(document.querySelectorAll('[data-nav]'), function (el) {
    return el.getClientRects().length > 0;
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
// yarsRowBox: the checkbox of the focused row.
function yarsRowBox() {
  var a = document.activeElement;
  var tr = a && a.closest ? a.closest('tr') : null;
  var cb = tr ? tr.querySelector('input[type=checkbox]') : null;
  return cb && !cb.disabled ? cb : null;
}
// yarsListNav handles the list keys on pages without panels; true when used.
// x ticks the focused row; Shift+Space ticks the range from the row last
// clicked to it (app.js yarsRange; bulk lists only).
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
// After Load more (the row tr.more swaps itself for the next rows), focus
// goes to the first new row.
var yarsMoreAt = null;
document.addEventListener('htmx:beforeSwap', function (evt) {
  var t = evt.detail.target;
  if (t && t.matches && t.matches('tr.more')) yarsMoreAt = {prev: t.previousElementSibling, body: t.parentNode};
});
document.addEventListener('htmx:afterSettle', function () {
  var m = yarsMoreAt;
  if (!m) return;
  yarsMoreAt = null;
  var first = m.prev ? m.prev.nextElementSibling : m.body.firstElementChild;
  var nav = first && !first.matches('tr.more') ? first.querySelector('[data-nav]') : null;
  if (nav) nav.focus();
});

// / (K6): the page's search box; without one, Go to.
function yarsSlash() {
  var s = Array.prototype.filter.call(document.querySelectorAll('input[type=search]'), function (el) {
    return !el.closest('dialog') && !el.disabled && el.getClientRects().length > 0;
  })[0];
  if (s) { s.focus(); s.select(); return true; }
  if (!document.getElementById('goto')) return false;
  yarsGotoOpen();
  return true;
}

/* ---------- selection (K2): a click or j/k selects a panel ---------- */

// yarsSel is the selected panel's id (htmx swaps the element; the id stays);
// yarsSideFrom the main panel selected before l or → went to the side panel.
var yarsSel = '';
var yarsSideFrom = '';

function yarsSelected() {
  var p = yarsSel ? document.getElementById(yarsSel) : null;
  return p && p.hasAttribute('data-kpanel') ? p : null;
}

// yarsSelect marks el selected (null: nothing) and keeps it in view; the
// mark is an outline, so nothing moves.
function yarsSelect(el) {
  document.querySelectorAll('[data-kpanel][data-sel]').forEach(function (p) {
    if (p !== el) p.removeAttribute('data-sel');
  });
  yarsSel = el && el.id ? el.id : '';
  if (!el) return;
  el.setAttribute('data-sel', '');
  if (el.scrollIntoView) el.scrollIntoView({block: 'nearest'});
}

document.addEventListener('pointerdown', function (evt) {
  var p = evt.target.closest && evt.target.closest('[data-kpanel]');
  if (p) yarsSelect(p);
}, true);
// a swapped panel (live refresh, editor) keeps its mark
document.addEventListener('htmx:afterSettle', function () {
  var p = yarsSelected();
  if (p && !p.hasAttribute('data-sel')) p.setAttribute('data-sel', '');
});

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
  if (i < 0) { yarsSelect(list[0]); return true; }
  yarsSelect(list[Math.max(0, Math.min(list.length - 1, i + d))]);
  return true;
}

// yarsSide selects the side panel (l, →), remembering where it came from;
// yarsBack returns there (h, ←).
function yarsSide() {
  var s = document.querySelector('[data-kpanel="side"]');
  if (!s) return false;
  var cur = yarsSelected();
  if (cur && cur !== s) yarsSideFrom = cur.id;
  yarsSelect(s);
  return true;
}
function yarsBack() {
  var p = yarsSideFrom ? document.getElementById(yarsSideFrom) : null;
  if (!p || !p.hasAttribute('data-kpanel')) return false;
  yarsSelect(p);
  return true;
}

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
  var sel = yarsSelected();
  var cancel = sel && sel.classList.contains('editing') ? sel.querySelector('[data-guard-cancel]') : null;
  if (cancel) { cancel.click(); return; }
  var a = document.activeElement;
  if (a && a !== document.body && yarsTyping(a)) { a.blur(); return; }
  if (sel) yarsSelect(null);
}

// yarsNav handles the navigation keys of the panel pages; true when used.
// Arrows act only while a panel is selected (otherwise the page scrolls).
function yarsNav(key) {
  if (!document.querySelector('[data-kpanel]')) return false;
  var sel = !!yarsSelected();
  switch (key) {
  case 'J': return yarsStep(1);
  case 'K': return yarsStep(-1);
  case 'ArrowDown': return sel && yarsStep(1);
  case 'ArrowUp': return sel && yarsStep(-1);
  case 'L': return yarsSide();
  case 'ArrowRight': return sel && yarsSide();
  case 'H': return yarsBack();
  case 'ArrowLeft': return sel && yarsBack();
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
    var f = evt.target.closest && evt.target.closest('form');
    if (f) { evt.preventDefault(); f.requestSubmit(); }
    return;
  }
  if (key === 'Escape') { yarsEscape(); return; }
  // single keys and Shift+key: never into a field, during composition, on
  // repeat, under a modal dialog, or with shortcuts off
  if (yarsKeysOff() || evt.isComposing || evt.repeat || evt.altKey || evt.defaultPrevented ||
      (yarsTyping(evt.target) && !yarsPick(evt.target)) || document.querySelector('dialog[open]')) return;
  if (evt.ctrlKey || evt.metaKey) return; // the browser's own (Ctrl+K is app.js's)
  if (yarsNav(key) || yarsListNav(key)) { evt.preventDefault(); return; }
  if (key === '/') { if (yarsSlash()) evt.preventDefault(); return; }
  if (key === 'E') { if (yarsEdit()) evt.preventDefault(); return; }
  if (key === 'Enter') { if (yarsEnter()) evt.preventDefault(); return; }
  if (key === 'C') { if (yarsCommentKey()) evt.preventDefault(); return; }
  if (yarsFire(key) || yarsBulkFire(key)) evt.preventDefault();
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
