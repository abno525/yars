/* YARS keyboard (K1–K10): the templates declare what exists (Edit and Save
   buttons carry aria-keyshortcuts); one keydown handler finds a rendered,
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

// yarsFire clicks the first rendered, enabled element in scope (default the
// document) whose aria-keyshortcuts lists key; true when one was clicked.
function yarsFire(key, scope) {
  if (!key) return false;
  var els = (scope || document).querySelectorAll('[aria-keyshortcuts]');
  for (var i = 0; i < els.length; i++) {
    var el = els[i];
    if ((el.getAttribute('aria-keyshortcuts') || '').split(/\s+/).indexOf(key) < 0) continue;
    if (el.offsetParent === null || el.disabled) continue;
    el.click();
    return true;
  }
  return false;
}

document.addEventListener('keydown', function (evt) {
  var key = yarsKeyOf(evt);
  if (key === 'Control+S') {
    // never the browser's "Save page" dialog on a YARS page
    evt.preventDefault();
    if (!evt.repeat && !document.querySelector('dialog[open]')) yarsSave();
    return;
  }
  if (key === 'Control+Enter') {
    var f = evt.target.closest && evt.target.closest('form');
    if (f) { evt.preventDefault(); f.requestSubmit(); }
    return;
  }
  if (key === 'Escape') return; // the open dialog's own, for now
  // single keys and Shift+key: never into a field, during composition, on
  // repeat, under a modal dialog, or with shortcuts off
  if (yarsKeysOff() || evt.isComposing || evt.repeat || evt.altKey || evt.defaultPrevented ||
      yarsTyping(evt.target) || document.querySelector('dialog[open]')) return;
  if (evt.ctrlKey || evt.metaKey) return; // the browser's own (Ctrl+K is app.js's)
  if (key === 'E') { if (yarsEdit()) evt.preventDefault(); return; }
  if (yarsFire(key)) evt.preventDefault();
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
