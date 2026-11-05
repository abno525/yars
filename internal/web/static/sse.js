// Live updates: one EventSource per visible tab, opened when the page has an
// element with data-sse-url. Each event is re-dispatched as "sse:<name>" on
// every element marked data-sse, whose hx-trigger decides what to refetch.
// "push" and "resync" (missed events) become "sse:resync". A hidden tab
// closes its stream (browsers allow few connections per host) and catches
// up when shown again. When the stream keeps failing, the page falls back to
// "sse:poll" every 30 s, paused while the tab is hidden.
(function () {
  var NAMES = ['chat', 'workflow', 'content', 'presence'];
  var RESYNC = ['push', 'resync'];
  var POLL_MS = 30000;
  var MAX_ERRORS = 3;

  var url = null;
  var es = null;
  var pollTimer = null;

  function fire(name) {
    if (!window.htmx) return;
    var els = document.querySelectorAll('[data-sse]');
    for (var i = 0; i < els.length; i++) htmx.trigger(els[i], 'sse:' + name);
  }

  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(function () {
      if (!document.hidden) fire('poll');
    }, POLL_MS);
  }

  function disconnect() {
    if (es) { es.close(); es = null; }
  }

  function connect() {
    if (!window.EventSource) { startPolling(); return; }
    var errors = 0;
    var s = new EventSource(url);
    es = s;
    s.onopen = function () { errors = 0; };
    s.onerror = function () {
      errors++;
      if (errors >= MAX_ERRORS || s.readyState === EventSource.CLOSED) {
        s.close();
        if (es === s) es = null;
        startPolling();
      }
    };
    NAMES.forEach(function (n) {
      s.addEventListener(n, function () { errors = 0; fire(n); });
    });
    RESYNC.forEach(function (n) {
      s.addEventListener(n, function () { errors = 0; fire('resync'); });
    });
  }

  // hidden: let the connection go; shown: reconnect (or poll) and catch up
  function onVisibility() {
    if (!url) return;
    if (document.hidden) {
      disconnect();
    } else if (pollTimer) {
      fire('poll');
    } else if (!es) {
      connect(url);
      fire('resync');
    }
  }

  function start() {
    var host = document.querySelector('[data-sse-url]');
    if (!host) return;
    url = host.getAttribute('data-sse-url');
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('pagehide', disconnect);
    window.addEventListener('pageshow', function (e) { if (e.persisted) onVisibility(); });
    if (!document.hidden) connect();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
