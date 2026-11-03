// yarsComment points the chat composer at a section and focuses it.
function yarsComment(section) {
  var sel = document.getElementById('chat-section');
  var txt = document.getElementById('chat-text');
  if (!sel || !txt) return;
  sel.value = section;
  txt.focus();
  txt.scrollIntoView({block: 'center', behavior: 'smooth'});
}
