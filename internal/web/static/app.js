// yarsComment points the chat composer at a section and focuses it.
function yarsComment(section) {
  var sel = document.getElementById('chat-section');
  var txt = document.getElementById('chat-text');
  if (!sel || !txt) return;
  sel.value = section;
  txt.focus();
  txt.scrollIntoView({block: 'center', behavior: 'smooth'});
}

// Polling must never wipe a half-typed reply: skip the background refresh of
// #chat-list while any reply box inside it has focus or text. (Posting a
// reply/resolve still swaps, because that request is a POST.)
document.addEventListener('htmx:beforeSwap', function (evt) {
  var t = evt.detail.target;
  if (!t || t.id !== 'chat-list' || evt.detail.requestConfig.verb !== 'get') return;
  var busy = Array.prototype.some.call(t.querySelectorAll('input[name=text]'), function (i) {
    return i.value !== '' || i === document.activeElement;
  });
  if (busy) evt.detail.shouldSwap = false;
});
