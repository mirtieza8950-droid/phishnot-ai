"""JavaScript strings injected into / evaluated by the headless sandbox page."""

INIT_JS = """
(function () {
  var _muts = [];
  var _obs = new MutationObserver(function(recs) {
    for (var r of recs) {
      _muts.push({
        type: r.type,
        target: r.target.tagName || r.target.nodeName || '',
        added: r.addedNodes.length,
        removed: r.removedNodes.length,
        attribute: r.attributeName || null,
        ts: Date.now()
      });
    }
  });
  _obs.observe(document.documentElement, {
    childList: true, subtree: true, attributes: true, characterData: false
  });
  window.__pg_mutations = _muts;

  var _timers = [];
  var _origTO = window.setTimeout;
  var _origTI = window.setInterval;
  window.setTimeout = function() {
    _timers.push({ type: 'timeout', delay: arguments[1] || 0 });
    return _origTO.apply(this, arguments);
  };
  window.setInterval = function() {
    _timers.push({ type: 'interval', delay: arguments[1] || 0 });
    return _origTI.apply(this, arguments);
  };
  window.__pg_timers = _timers;

  var _store = [];
  ['localStorage','sessionStorage'].forEach(function(name) {
    var orig = window[name];
    if (!orig) return;
    try {
      Object.defineProperty(window, name, {
        get: function() {
          return new Proxy(orig, {
            get: function(t, p) {
              if (p === 'setItem') return function(k,v){ _store.push({s:name,op:'set',key:k}); return t.setItem(k,v); };
              if (p === 'getItem') return function(k){ _store.push({s:name,op:'get',key:k}); return t.getItem(k); };
              return typeof t[p]==='function' ? t[p].bind(t) : t[p];
            }
          });
        }
      });
    } catch(e) {}
  });
  window.__pg_store = _store;
})();
"""

COLLECT_JS = """
(function() {
  var forms = [];
  document.querySelectorAll('form').forEach(function(f) {
    var inputs = [];
    f.querySelectorAll('input,textarea,select').forEach(function(i) {
      inputs.push({
        type: i.type || i.tagName.toLowerCase(),
        name: i.name || i.id || '',
        placeholder: i.placeholder || '',
        autocomplete: i.autocomplete || ''
      });
    });
    forms.push({
      action: f.action || '',
      method: (f.method || 'get').toUpperCase(),
      input_count: inputs.length,
      inputs: inputs,
      has_password: inputs.some(function(i){ return i.type==='password'; }),
      has_email: inputs.some(function(i){
        return i.type==='email' || i.name.indexOf('email')>-1 || i.name.indexOf('user')>-1;
      })
    });
  });

  var scripts = [];
  document.querySelectorAll('script[src]').forEach(function(s){ scripts.push(s.src); });

  var iframes = [];
  document.querySelectorAll('iframe').forEach(function(f){
    iframes.push({ src: f.src || (f.srcdoc ? '[srcdoc]' : ''), sandbox: f.sandbox ? f.sandbox.toString() : '' });
  });

  var metaRefresh = [];
  document.querySelectorAll('meta[http-equiv="refresh"]').forEach(function(m){ metaRefresh.push(m.content); });

  var inlineCode = '';
  document.querySelectorAll('script:not([src])').forEach(function(s){ inlineCode += (s.textContent || ''); });

  return {
    title: document.title || '',
    html_length: document.documentElement.outerHTML.length,
    forms: forms,
    external_scripts: scripts,
    iframes: iframes,
    meta_refresh: metaRefresh,
    has_eval:      /\\beval\\s*\\(/.test(inlineCode),
    has_doc_write: /document\\.write\\s*\\(/.test(inlineCode),
    has_base64:    /atob\\s*\\(|btoa\\s*\\(/.test(inlineCode),
    mutations:     (window.__pg_mutations || []).slice(0, 300),
    timers:        (window.__pg_timers   || []).slice(0,  50),
    storage_access:(window.__pg_store    || []).slice(0,  50)
  };
})();
"""
