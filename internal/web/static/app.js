// Theme: an explicit choice lives in data-theme on <html> and in
// localStorage; without one the system setting applies. Runs in <head>, so
// the stored theme is set before the page paints.
(function () {
  try {
    var t = localStorage.getItem('yars-theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* storage blocked: follow the system */ }
})();

function yarsTheme() {
  var root = document.documentElement;
  var cur = root.getAttribute('data-theme');
  if (!cur) cur = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  var next = cur === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  try { localStorage.setItem('yars-theme', next); } catch (e) { /* not remembered */ }
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

document.addEventListener('click', function (evt) {
  var el = evt.target.closest && evt.target.closest('[data-theme-toggle], [data-copy]');
  if (!el) return;
  if (el.hasAttribute('data-theme-toggle')) { yarsTheme(); return; }
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

// Live refreshes must never wipe a half-typed reply or reason: skip the
// background refresh of #chat-list or #workflow while a text box inside has
// focus or text, or the reviewer picker is open. (Posting a reply/resolve
// still swaps, because that request is a POST.)
document.addEventListener('htmx:beforeSwap', function (evt) {
  var t = evt.detail.target;
  if (!t || (t.id !== 'chat-list' && t.id !== 'workflow') || evt.detail.requestConfig.verb !== 'get') return;
  var busy = Array.prototype.some.call(t.querySelectorAll('input[name=text], textarea'), function (i) {
    return i.value !== '' || i === document.activeElement;
  }) || (t.id === 'workflow' && !!t.querySelector('details[open], .wfpanel:not([hidden])'));
  if (busy) evt.detail.shouldSwap = false;
});

// Director inbox: the "N selected" count is a CSS counter, which Chrome
// does not recount when the lists are swapped; re-inserting it does.
document.addEventListener('htmx:afterSettle', function () {
  var n = document.querySelector('.bulkform .selcount');
  if (n) n.replaceWith(n.cloneNode(true));
});

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
