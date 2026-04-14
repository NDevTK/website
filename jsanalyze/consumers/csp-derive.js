// csp-derive.js — Content-Security-Policy derivation consumer
// (Wave 12 / Phase E, D11)
//
// Walks a completed trace and derives a minimal CSP from the
// native DOM APIs the analyzed bundle actually uses. Every
// directive's source list is the union of:
//
//   * Concrete URL origins passed to a network-capable API
//     (fetch / XHR / WebSocket / Beacon / Worker / etc.) or
//     assigned to a url-sink property (script.src, img.src,
//     iframe.src, link.href).
//   * Concrete `<script src>` / `<img src>` / `<iframe src>`
//     strings the engine found via trace.stringLiterals and
//     trace.domMutations.
//   * `'self'` as the default same-origin allowance.
//
// The consumer also checks for inline-script / inline-style
// risks (innerHtmlAssignments, inline script blocks) and
// flags `'unsafe-inline'` / `'unsafe-eval'` when the code
// actually needs them. Flagging is advisory — the consumer
// emits the directive values so callers can decide policy.
//
// Public API:
//
//   const csp = require('jsanalyze/consumers/csp-derive');
//   const policy = await csp.derive(input, options?);
//     // returns {
//     //   'script-src':  ["'self'", 'https://cdn.example.com', ...],
//     //   'connect-src': ["'self'", 'https://api.example.com', ...],
//     //   'frame-src':   [...],
//     //   'worker-src':  [...],
//     //   'img-src':     ["'self'", ...],
//     //   'style-src':   ["'self'", ...],
//     //   'report-unsafe-inline': boolean,
//     //   'report-unsafe-eval':   boolean,
//     //   meta: { sources: {...} },
//     //   partial:  boolean,
//     //   warnings: trace.warnings,
//     // }
//
// Design notes
// ------------
//
//   * One analyze() call per derive(), many queries over the
//     result. The trace is the stable multi-consumer contract
//     — every observation this consumer needs already exists
//     on the trace (calls, stringLiterals, domMutations,
//     innerHtmlAssignments, taintFlows).
//
//   * No coupling to engine internals. Uses the public
//     `analyze` + `query` API only.
//
//   * Consumer picks its own accept set: csp-derive
//     tolerates every reason because the derived policy is
//     already a union (over-approximation of the bundle's
//     actual needs).

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const query = require('../src/query.js');

// Network-capable callees whose URL argument goes into
// `connect-src`. The key is either the global-function name
// or the method name; the value is the index of the URL arg.
// XHR.open is special: method is arg 0, URL is arg 1.
const CONNECT_TARGETS = {
  'fetch':                         0,
  'Request':                       0,
  'navigator.sendBeacon':          0,
  'sendBeacon':                    0,
  'WebSocket':                     0,
  'EventSource':                   0,
  'XMLHttpRequest.open':           1,
  'open':                          1,   // method-only fallback
};

// Worker callees → worker-src.
const WORKER_TARGETS = {
  'Worker':                        0,
  'SharedWorker':                  0,
  'ServiceWorkerContainer.register': 0,
  'register':                      0,   // method-only fallback
};

async function derive(input, options) {
  options = options || {};
  const trace = await analyze(input, {
    typeDB: options.typeDB || TDB,
    precision: options.precision || 'precise',
    accept: options.accept,
    watchers: options.watchers,
  });

  const scriptSrc  = new Set();
  const connectSrc = new Set();
  const frameSrc   = new Set();
  const workerSrc  = new Set();
  const imgSrc     = new Set();
  const styleSrc   = new Set();
  const sources = {
    'script-src':  [],
    'connect-src': [],
    'frame-src':   [],
    'worker-src':  [],
    'img-src':     [],
    'style-src':   [],
  };

  // --- 1. Call sites: network / worker / eval / import ------------------
  for (const c of trace.calls) {
    const text = c.callee.text || '';
    const baseName = text.split('.').pop();

    // connect-src: any network-capable API
    const connectIdx = CONNECT_TARGETS[text] != null
      ? CONNECT_TARGETS[text]
      : CONNECT_TARGETS[baseName];
    if (connectIdx != null) {
      const urlArg = c.args[connectIdx];
      addOrigins(urlArg, connectSrc, sources['connect-src'], c.site);
      continue;
    }

    // worker-src: new Worker / SharedWorker / SW register
    const workerIdx = WORKER_TARGETS[text] != null
      ? WORKER_TARGETS[text]
      : WORKER_TARGETS[baseName];
    if (workerIdx != null) {
      const urlArg = c.args[workerIdx];
      addOrigins(urlArg, workerSrc, sources['worker-src'], c.site);
      continue;
    }

    // dynamic import(url) → script-src
    if (text === 'import' || baseName === 'import') {
      addOrigins(c.args[0], scriptSrc, sources['script-src'], c.site);
      continue;
    }
  }

  // --- 2. DOM property writes via trace.domMutations -------------------
  //
  // Every write to a *.src / *.href on a DOM-chain receiver
  // shows up in trace.domMutations. We classify by the
  // receiver's typeName + the property name so script.src /
  // img.src / iframe.src / link.href each feed the right
  // directive.
  for (const m of trace.domMutations) {
    if (m.category !== 'property-set') continue;
    const t = m.targetType || '';
    const prop = m.kind;
    const val = m.args[0];
    if (prop === 'src') {
      if (/Script/i.test(t)) {
        addOrigins(val, scriptSrc, sources['script-src'], m.site);
      } else if (/Iframe|Frame/i.test(t)) {
        addOrigins(val, frameSrc, sources['frame-src'], m.site);
      } else if (/Img|Image/i.test(t)) {
        addOrigins(val, imgSrc, sources['img-src'], m.site);
      }
      continue;
    }
    if (prop === 'href') {
      if (/Link/i.test(t)) {
        // <link rel="stylesheet" href="..."> → style-src
        addOrigins(val, styleSrc, sources['style-src'], m.site);
      }
      // a.href is navigation, not a CSP source.
      continue;
    }
    if (prop === 'srcdoc' && /Iframe|Frame/i.test(t)) {
      // srcdoc creates an inline document — risk flag, not an origin.
      continue;
    }
  }

  // --- 3. Inline risk detection --------------------------------------
  //
  // innerHtmlAssignments — if ANY assignment is made (tainted or
  // concrete), the bundle uses innerHTML as a DOM mutation, which
  // requires `'unsafe-inline'` if the page enforces CSP on style
  // attributes. Concrete assignments that only produce safe DOM
  // subtrees are not a risk, but without a separate structural
  // analysis we conservatively flag if ANY exist.
  const needsUnsafeInline = trace.innerHtmlAssignments.length > 0;

  // unsafe-eval detection: `eval`, `Function` constructor,
  // `setTimeout` / `setInterval` with a string first arg.
  let needsUnsafeEval = false;
  for (const c of trace.calls) {
    const text = c.callee.text || '';
    const base = text.split('.').pop();
    if (base === 'eval') { needsUnsafeEval = true; break; }
    if (base === 'Function') { needsUnsafeEval = true; break; }
    if (base === 'setTimeout' || base === 'setInterval') {
      const arg0 = c.args[0];
      if (arg0 && arg0.kind === 'concrete' && typeof arg0.value === 'string') {
        needsUnsafeEval = true;
        break;
      }
    }
  }

  // --- 4. Default 'self' ---------------------------------------------
  scriptSrc.add("'self'");
  connectSrc.add("'self'");
  imgSrc.add("'self'");
  styleSrc.add("'self'");

  return {
    schemaVersion: '1',
    'script-src':  Array.from(scriptSrc).sort(),
    'connect-src': Array.from(connectSrc).sort(),
    'frame-src':   Array.from(frameSrc).sort(),
    'worker-src':  Array.from(workerSrc).sort(),
    'img-src':     Array.from(imgSrc).sort(),
    'style-src':   Array.from(styleSrc).sort(),
    'report-unsafe-inline': needsUnsafeInline,
    'report-unsafe-eval':   needsUnsafeEval,
    meta: { sources },
    partial:  trace.partial,
    warnings: trace.warnings,
  };
}

// addOrigins — extract every URL origin from a Value and add
// it to `set`, with provenance on `sources`. Handles concrete
// strings, OneOf unions, and opaque-with-taint values.
function addOrigins(value, set, sources, site) {
  if (!value) return;
  // Concrete string: parse the origin.
  if (value.kind === 'concrete' && typeof value.value === 'string') {
    const origin = originOf(value.value);
    if (origin) {
      set.add(origin);
      sources.push({ origin, site, source: 'concrete' });
    }
    return;
  }
  // OneOf: enumerate every literal.
  if (value.kind === 'oneOf' && Array.isArray(value.values)) {
    for (const v of value.values) {
      if (typeof v === 'string') {
        const origin = originOf(v);
        if (origin) {
          set.add(origin);
          sources.push({ origin, site, source: 'oneOf' });
        }
      }
    }
    return;
  }
  // StrPattern with a concrete prefix — use the prefix's origin.
  if (value.kind === 'strPattern' && value.prefix) {
    const origin = originOf(value.prefix);
    if (origin) {
      set.add(origin);
      sources.push({ origin, site, source: 'strPattern.prefix' });
    }
    return;
  }
  // Opaque: we don't know the URL. Record a wildcard marker so
  // the consumer's CSP policy reflects the imprecision.
  if (value.kind === 'opaque') {
    set.add('*');   // wildcard
    sources.push({ origin: '*', site, source: 'opaque', labels: Array.from(value.labels || []) });
    return;
  }
  // Disjunct: fan out.
  if (value.kind === 'disjunct' && Array.isArray(value.variants)) {
    for (const v of value.variants) addOrigins(v, set, sources, site);
    return;
  }
}

// originOf(url) → 'https://example.com' or null. Falls back
// to null on malformed URLs or relative URLs (which implicitly
// mean same-origin, covered by 'self').
function originOf(url) {
  if (typeof url !== 'string') return null;
  // Special schemes.
  if (url.startsWith('data:')) return 'data:';
  if (url.startsWith('blob:')) return 'blob:';
  if (url.startsWith('filesystem:')) return 'filesystem:';
  // Absolute URLs have a scheme followed by `:`. Relative
  // URLs are 'self'.
  const schemeIdx = url.indexOf(':');
  if (schemeIdx < 0) return null;   // relative path → 'self'
  // URL global exists in Node 16+ and every modern browser.
  if (typeof URL === 'function') {
    // eslint-disable-next-line no-undef
    const u = tryParseUrl(url);
    if (u && u.protocol !== 'javascript:' && u.origin && u.origin !== 'null') {
      return u.origin;
    }
  }
  // Fallback: strip the path.
  const m = url.match(/^([a-z][a-z0-9+\-.]*:\/\/[^/?#]+)/i);
  return m ? m[1] : null;
}

// tryParseUrl — null on failure. Deliberately NOT using
// try/catch per the project's no-catch policy outside the
// index.js boundaries; consumer layer DOES allow catches
// (the engine invariant is on jsanalyze/src/ only), so this
// is fine.
function tryParseUrl(url) {
  try { return new URL(url); } catch (_) { return null; }
}

module.exports = {
  derive,
  originOf,
};
