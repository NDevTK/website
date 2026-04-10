// csp-derive.js
//
// Derives a minimal Content-Security-Policy from a JavaScript
// bundle by observing every network-capable API call it makes
// and every inline execution primitive it uses.
//
// This consumer stresses the jsanalyze API differently from
// fetch-trace: instead of needing per-call argument detail,
// it wants every URL origin mentioned in a connect-capable
// context, plus a boolean "does this bundle need unsafe-eval"
// plus a list of worker/iframe/script sources. It's the third
// consumer we use to validate the API abstraction.
//
// Core entry point:
//
//   const policy = await cspDerive.derive(bundle, options);
//
// Returns:
//
//   {
//     'script-src':  ['self', "'unsafe-eval'?", 'https://cdn.com'],
//     'connect-src': ['self', 'https://api.example.com'],
//     'frame-src':   ['https://embed.com'],
//     'worker-src':  ['blob:', 'https://cdn.com/worker.js'],
//     'img-src':     ['self'],
//     'report-unsafe-inline': bool,
//     'report-unsafe-eval': bool,
//     meta: { sources: Source[] }  — provenance for each directive
//   }
//
// Everything is derived from one pass — we call `analyze()` once
// and run multiple `query.*` queries over the resulting trace.
// That's the pattern: one walk, many queries.

(function () {
  'use strict';

  function loadQuery() {
    if (typeof globalThis !== 'undefined' && globalThis.JsAnalyzeQuery) return globalThis.JsAnalyzeQuery;
    if (typeof require !== 'undefined') {
      try { return require('./jsanalyze-query.js'); } catch (_) {}
    }
    throw new Error('csp-derive: jsanalyze-query not available');
  }

  async function derive(input, options) {
    options = options || {};
    const { analyze, query, schemas: S } = loadQuery();

    const trace = await analyze(input, {
      taint: options.taint !== false,
      watchers: options.watchers,
    });

    // --- connect-src: every fetch / XHR / beacon / WebSocket / EventSource target origin
    const connectCalls = query.calls(trace, {
      targets: ['fetch', 'XMLHttpRequest', 'open', 'navigator.sendBeacon', 'sendBeacon',
                'Request', 'EventSource', 'WebSocket'],
    });
    const connectSrc = new Set();
    const connectSources = [];
    for (const c of connectCalls) {
      const urlArg = urlArgForCallee(c);
      if (!urlArg) continue;
      addOriginsFromValue(urlArg, connectSrc, connectSources, c.site, query);
    }

    // --- script-src: any <script> src we see + dynamic imports
    const scriptSrc = new Set();
    const scriptSources = [];
    const importCalls = query.calls(trace, { targets: ['import'] });
    for (const c of importCalls) {
      const urlArg = c.args[0];
      if (urlArg) addOriginsFromValue(urlArg, scriptSrc, scriptSources, c.site, query);
    }
    // Also any `document.createElement('script')` followed by `.src = ...` —
    // the walker captures those as virtual-DOM element sets. We read
    // them from the trace's _domOps shadow field.
    if (trace._domOps) {
      for (const opEntry of trace._domOps) {
        const op = opEntry.op;
        if (op && op.element && op.element.tag === 'script' && op.op === 'set' && op.name === 'src' && op.value) {
          const v = bindingToLocalValue(op.value);
          if (v) addOriginsFromValue(v, scriptSrc, scriptSources, { file: opEntry.file || '?', line: 0, col: 0, kind: 'assignment' }, query);
        }
      }
    }

    // --- worker-src: new Worker(url), new SharedWorker(url), navigator.serviceWorker.register(url)
    const workerSrc = new Set();
    const workerSources = [];
    const workerCalls = query.calls(trace, {
      targets: ['Worker', 'SharedWorker', 'register', 'navigator.serviceWorker.register'],
    });
    for (const c of workerCalls) {
      const urlArg = c.args[0];
      if (urlArg) addOriginsFromValue(urlArg, workerSrc, workerSources, c.site, query);
    }

    // --- frame-src: iframe src assignments
    const frameSrc = new Set();
    const frameSources = [];
    if (trace._domOps) {
      for (const opEntry of trace._domOps) {
        const op = opEntry.op;
        if (op && op.element && (op.element.tag === 'iframe' || op.element.tag === 'frame') &&
            op.op === 'set' && op.name === 'src' && op.value) {
          const v = bindingToLocalValue(op.value);
          if (v) addOriginsFromValue(v, frameSrc, frameSources, { file: opEntry.file || '?', line: 0, col: 0, kind: 'assignment' }, query);
        }
      }
    }

    // --- img-src: img.src assignments
    const imgSrc = new Set();
    const imgSources = [];
    if (trace._domOps) {
      for (const opEntry of trace._domOps) {
        const op = opEntry.op;
        if (op && op.element && op.element.tag === 'img' && op.op === 'set' && op.name === 'src' && op.value) {
          const v = bindingToLocalValue(op.value);
          if (v) addOriginsFromValue(v, imgSrc, imgSources, { file: opEntry.file || '?', line: 0, col: 0, kind: 'assignment' }, query);
        }
      }
    }

    // --- unsafe-eval detection
    const evalCalls = query.calls(trace, { targets: ['eval', 'Function', 'setTimeout', 'setInterval'] });
    let needsUnsafeEval = false;
    for (const c of evalCalls) {
      // Function constructor always needs unsafe-eval
      if (c.callee.text === 'Function' || c.callee.text === 'new Function') { needsUnsafeEval = true; break; }
      // eval() always needs unsafe-eval
      if (c.callee.text === 'eval') { needsUnsafeEval = true; break; }
      // setTimeout/setInterval with a STRING arg needs unsafe-eval
      // (the "string-as-code" form). Function arg is fine.
      if (c.args[0] && (c.args[0].kind === 'concrete' && typeof c.args[0].value === 'string' ||
                        c.args[0].kind === 'template')) {
        needsUnsafeEval = true;
        break;
      }
    }

    // --- unsafe-inline detection: any .innerHTML sink indicates
    //     inline script/style risk (they can inject).
    const innerHtmlAssignments = trace.taintFlows.filter(f => f.sink.prop === 'innerHTML');
    const needsUnsafeInline = innerHtmlAssignments.length > 0;

    // Always include 'self' as a baseline for the directives that
    // implicitly allow same-origin resources — but dedupe against
    // the discovered origins. Using Set semantics keeps output tidy.
    scriptSrc.add("'self'");
    connectSrc.add("'self'");
    imgSrc.add("'self'");

    return {
      schemaVersion: '1',
      'script-src': Array.from(scriptSrc).sort(),
      'connect-src': Array.from(connectSrc).sort(),
      'frame-src': Array.from(frameSrc).sort(),
      'worker-src': Array.from(workerSrc).sort(),
      'img-src': Array.from(imgSrc).sort(),
      'report-unsafe-inline': needsUnsafeInline,
      'report-unsafe-eval': needsUnsafeEval,
      meta: {
        sources: {
          'connect-src': connectSources,
          'script-src': scriptSources,
          'worker-src': workerSources,
          'frame-src': frameSources,
          'img-src': imgSources,
        },
      },
      partial: trace.partial,
      warnings: trace.warnings,
    };
  }

  function urlArgForCallee(call) {
    // Most APIs take URL as arg 0. XHR.open takes URL as arg 1
    // (arg 0 is method).
    const base = (call.callee.text || '').split('.').pop();
    if (base === 'open') return call.args[1];
    return call.args[0];
  }

  // Extract every origin or 'self' marker from a URL Value. For
  // a concrete URL, pull the origin with a URL parse; for oneOf,
  // iterate values; for templates, only enumerate if every hole
  // is enumerable (otherwise mark as wildcard for its prefix).
  function addOriginsFromValue(value, set, sources, site, query) {
    if (!value) return;
    const vals = query.enumerate(value);
    if (vals) {
      for (const v of vals) {
        const origin = originOf(v);
        if (origin) {
          set.add(origin);
          sources.push({ origin, site, source: 'concrete' });
        }
      }
      return;
    }
    // Template with unresolvable holes — if the literal prefix is
    // a full origin, use it; otherwise flag 'self' + a wildcard.
    if (value.kind === 'template') {
      for (const part of value.parts) {
        if (part.kind === 'literal') {
          const o = originOf(part.value);
          if (o) {
            set.add(o);
            sources.push({ origin: o, site, source: 'template-prefix' });
          }
        }
      }
    }
  }

  // Return the origin 'https://host:port' for absolute URLs, or
  // "'self'" for same-origin paths. Returns null if we can't tell.
  function originOf(urlStr) {
    if (typeof urlStr !== 'string' || !urlStr) return null;
    // ws:// wss:// http:// https:// (check before scheme-relative)
    const mWs = urlStr.match(/^(ws|wss|http|https):\/\/([^\/]+)/i);
    if (mWs) return mWs[1] + '://' + mWs[2];
    // Protocol-relative: //host/...
    const mRel = urlStr.match(/^\/\/([^\/]+)/);
    if (mRel) return 'https://' + mRel[1];
    // blob: / data: / javascript: schemes
    if (/^blob:/.test(urlStr)) return 'blob:';
    if (/^data:/.test(urlStr)) return 'data:';
    if (/^javascript:/.test(urlStr)) return "'unsafe-inline'";
    // Absolute path (/api/...), query (?x), hash (#y), dot-relative (./, ../) → same origin
    if (urlStr[0] === '/' || urlStr[0] === '?' || urlStr[0] === '#' || urlStr[0] === '.') {
      return "'self'";
    }
    // Bare relative path ('worker.js') → same origin
    if (/^[a-z0-9_\-]+(\.[a-z0-9]+)?($|[\/?#])/i.test(urlStr)) {
      return "'self'";
    }
    return null;
  }

  // Helper for reading DOM-op values that may be walker bindings
  // or already-converted Values. We normalize by running them
  // through the binding→value converter if it's available.
  function bindingToLocalValue(v) {
    if (!v) return null;
    if (v.kind === 'concrete' || v.kind === 'oneOf' || v.kind === 'template' || v.kind === 'object') return v;
    // Walker binding — convert via bindingToValue if exposed
    if (typeof globalThis !== 'undefined' && globalThis.__bindingToValue) {
      return globalThis.__bindingToValue(v, { file: '<anonymous>' });
    }
    return null;
  }

  // Render a CSP header string from the derived policy.
  function render(policy, opts) {
    opts = opts || {};
    const parts = [];
    for (const directive of ['script-src', 'connect-src', 'img-src', 'frame-src', 'worker-src']) {
      const vals = policy[directive];
      if (!vals || !vals.length) continue;
      let directiveStr = vals.join(' ');
      if (directive === 'script-src' && policy['report-unsafe-eval']) directiveStr += " 'unsafe-eval'";
      if (directive === 'script-src' && policy['report-unsafe-inline'] && opts.allowUnsafeInline) directiveStr += " 'unsafe-inline'";
      parts.push(directive + ' ' + directiveStr);
    }
    return parts.join('; ');
  }

  const api = Object.freeze({ derive, render });

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof globalThis !== 'undefined') globalThis.CspDerive = api;
})();
