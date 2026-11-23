// Live updates: one EventSource per visible tab, opened when the page has an
// element with data-sse-url. Each event is re-dispatched as "sse:<name>" on
// every element marked data-sse, whose hx-trigger decides what to refetch.
// "push" and "resync" (missed events) become "sse:resync". A hidden tab
// closes its stream (browsers allow few connections per host) and catches
// up when shown again. When the stream keeps failing, the page falls back to
// "sse:poll" every 30 s, paused while the tab is hidden.
(function () {
  var NAMES = ['chat', 'workflow', 'content', 'presence', 'check', 'board'];
  var RESYNC = ['push', 'resync'];
  var POLL_MS = 30000;
  var MAX_ERRORS = 3;

  var url = null;
  var es = null;
  var pollTimer = null;
  // events that came while an element's refetch was in flight, by its id:
  // htmx queues them on that element, and drops them when the answer
  // replaces it (an answer not swapped in leaves the queue to htmx)
  var missed = {};

  function fire(name) {
    if (!window.htmx) return;
    var els = document.querySelectorAll('[data-sse]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.id && el.classList.contains('htmx-request')) (missed[el.id] = missed[el.id] || {})[name] = true;
      htmx.trigger(el, 'sse:' + name);
    }
  }

  // once the answer is in and wired, the element now holding that id gets
  // them: afterRequest is fired on the replaced element, out of the page,
  // and at afterSwap the new one has no listeners yet (htmx wires its
  // hx-trigger when the swap settles)
  document.addEventListener('htmx:afterSettle', function (e) {
    var id = e.detail && e.detail.elt && e.detail.elt.id;
    if (!id || !missed[id]) return;
    var names = missed[id];
    delete missed[id];
    var el = document.getElementById(id);
    if (!el) return;
    for (var n in names) htmx.trigger(el, 'sse:' + n);
  });

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
