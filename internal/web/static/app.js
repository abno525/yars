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
  }) || (t.id === 'workflow' && !!t.querySelector('details[open]'));
  if (busy) evt.detail.shouldSwap = false;
});
