// fetch-trace.js
//
// Discovers every HTTP endpoint a JavaScript bundle can reach.
// Built as a jsanalyze consumer — no walker internals, only the
// public `analyze()` + `query.*` API.
//
// Use cases:
//   - Pre-populate a request palette ("Send panel") with URLs,
//     methods, headers, bodies, and per-param allowed-value
//     dropdowns derived from switch/if/includes guards.
//   - Discover APIs that haven't been called yet — the walker
//     walks every defined function symbolically, so unreachable
//     fetches are still captured.
//   - Feed a security scanner with the full attack surface of
//     HTTP calls in a web bundle.
//   - Generate a Content-Security-Policy `connect-src` list.
//
// Core entry point:
//
//   const report = await fetchTrace.discover(bundle, options);
//
// Returns an array of Endpoint objects. Each Endpoint is the
// cleanest possible projection of everything the walker knows
// about one call site — URL parts, method, headers, body, any
// value constraints on symbolic parts, any path conditions
// gating the call.
//

(function () {
  'use strict';

  function loadQuery() {
    if (typeof globalThis !== 'undefined' && globalThis.JsAnalyzeQuery) return globalThis.JsAnalyzeQuery;
    if (typeof require !== 'undefined') {
      try { return require('./jsanalyze-query.js'); } catch (_) {}
    }
    throw new Error('fetch-trace: jsanalyze-query not available');
  }

  // Targets we consider "HTTP-emitting" calls. XHR is two-step
  // (open + send) so we capture both; navigator.sendBeacon is
  // a single-step POST; Request is a constructor used with fetch
  // or service worker caches.
  const DEFAULT_TARGETS = [
    'fetch',
    'XMLHttpRequest',       // constructor call, captures "new XMLHttpRequest()"
    'open',                 // xhr.open(method, url, ...)
    'send',                 // xhr.send(body)
    'setRequestHeader',     // xhr.setRequestHeader(name, value)
    'navigator.sendBeacon',
    'sendBeacon',
    'Request',              // new Request(url, init)
    'EventSource',          // new EventSource(url)
    'WebSocket',            // new WebSocket(url)
    'SharedWorker',         // new SharedWorker(url)
    'Worker',               // new Worker(url)
    'register',             // navigator.serviceWorker.register(url)
    'import',               // dynamic import()
  ];

  // =========================================================================
  // discover(input, options) → Endpoint[]
  // =========================================================================
  async function discover(input, options) {
    options = options || {};
    const { analyze, query, schemas: S } = loadQuery();

    const trace = await analyze(input, {
      taint: options.taint !== false,
      watchers: options.watchers,
    });

    const targets = options.targets || DEFAULT_TARGETS;
    const calls = query.calls(trace, { targets: targets });

    // Pair XHR open/send calls by receiver so we can merge them
    // into a single Endpoint. Because the trace records call
    // sites without explicit object identity, we pair by file:line
    // proximity: an .open() call followed within a small window
    // by .send() on the same receiver variable is treated as one
    // endpoint. Not perfect but matches the common pattern.
    const xhrPairs = pairXhrOpenSend(calls);

    const endpoints = [];
    const consumedFingerprints = new Set();

    for (const pair of xhrPairs) {
      endpoints.push(xhrPairToEndpoint(pair, query, S));
      consumedFingerprints.add(fp(pair.open));
      if (pair.send) consumedFingerprints.add(fp(pair.send));
    }

    for (const c of calls) {
      if (consumedFingerprints.has(fp(c))) continue;
      endpoints.push(callToEndpoint(c, query, S));
    }

    return {
      schemaVersion: '1',
      trace: options.includeTrace ? trace : undefined,
      endpoints: endpoints,
      partial: trace.partial,
      warnings: trace.warnings,
    };

    function fp(c) {
      return c.callee.text + '|' + c.site.file + ':' + c.site.line;
    }
  }

  // =========================================================================
  // Endpoint shape (returned to consumer)
  // =========================================================================
  //
  // {
  //   callee: 'fetch',                  — the API family
  //   site: { file, line, col, snippet },
  //   reached: true,                    — false = dead code
  //   reachability: {
  //     kind: 'always' | 'conditional',
  //     conditions: [{ text }, ...],    — SMT-derived path conditions
  //   },
  //   url: UrlShape,                    — resolved URL
  //   method: 'GET' | 'POST' | ... | null,
  //   headers: { [name]: ValueShape },
  //   body: ValueShape | null,
  //   allowedValues: {                  — per-symbolic-slot value sets
  //     'url.action': ['get','put','delete'],
  //     'body.role': ['admin','editor'],
  //   },
  // }
  //
  // UrlShape/ValueShape mirror the jsanalyze Value but with
  // a flattened view consumers can render directly.
  //
  //   { kind: 'concrete', value: '/api/users' }
  //   { kind: 'oneOf',    values: ['/api/a', '/api/b'] }
  //   { kind: 'template', template: '/api/${id}',
  //                       parts: [{kind:'literal',value:'/api/'},{kind:'hole',name:'id',value:<ValueShape>}] }
  //   { kind: 'unknown',  reason: 'user-input', taint: ['url'] }

  function callToEndpoint(call, query, S) {
    const urlArg = call.args[0];
    const initArg = call.args[1];

    const endpoint = {
      callee: call.callee.text,
      site: call.site,
      reached: call.reached !== false,
      reachability: call.reachability,
      url: valueToShape(urlArg, S),
      method: extractMethod(call, initArg, query, S),
      headers: extractHeaders(initArg, query, S),
      body: extractBody(initArg, query, S),
      allowedValues: {},
    };

    // Capture per-hole allowed values for URL templates.
    if (urlArg && urlArg.kind === 'template') {
      for (const part of urlArg.parts) {
        if (part.kind === 'hole') {
          const holeVals = query.enumerate(part.value);
          if (holeVals) {
            const key = 'url.' + (part.symbolName || 'hole');
            endpoint.allowedValues[key] = holeVals;
          }
        }
      }
    }

    return endpoint;
  }

  // Extract the HTTP method from a fetch call. Rules:
  //   - fetch(url)              → 'GET' (default)
  //   - fetch(url, {method:X})  → X, with value constraint
  //   - navigator.sendBeacon    → 'POST' (by spec)
  //   - new EventSource         → 'GET'
  //   - new WebSocket           → 'GET' (upgrade)
  //   - Request(url, {method})  → same as fetch
  function extractMethod(call, initArg, query, S) {
    const callee = call.callee.text;
    if (callee === 'navigator.sendBeacon' || callee === 'sendBeacon') return 'POST';
    if (callee === 'EventSource' || callee === 'WebSocket' || callee === 'import') return 'GET';
    if (!initArg || initArg.kind !== 'object') return 'GET';
    const m = query.property(initArg, 'method');
    if (!m) return 'GET';
    // Flatten concrete to a bare string so consumers can do
    // `ep.method === 'POST'` without type-switching. Leave
    // oneOf/template/unknown as structured ValueShape.
    const concrete = query.asConcrete(m);
    if (concrete !== null) return concrete;
    if (m.kind === 'unknown') return 'GET';
    return valueToShape(m, S);
  }

  function extractHeaders(initArg, query, S) {
    if (!initArg || initArg.kind !== 'object') return {};
    const headers = query.property(initArg, 'headers');
    if (!headers || headers.kind !== 'object') return {};
    const out = {};
    for (const name in headers.props) {
      out[name] = valueToShape(headers.props[name], S);
    }
    return out;
  }

  function extractBody(initArg, query, S) {
    if (!initArg || initArg.kind !== 'object') return null;
    const body = query.property(initArg, 'body');
    if (!body || body.kind === 'unknown') return null;
    return valueToShape(body, S);
  }

  function valueToShape(v, S) {
    if (!v) return { kind: 'unknown', reason: 'unresolved-identifier' };
    switch (v.kind) {
      case 'concrete':
        return { kind: 'concrete', value: v.value };
      case 'oneOf':
        return { kind: 'oneOf', values: v.values.slice() };
      case 'template': {
        const parts = v.parts.map(p => {
          if (p.kind === 'literal') return { kind: 'literal', value: p.value };
          return {
            kind: 'hole',
            name: p.symbolName || null,
            value: valueToShape(p.value, S),
          };
        });
        return {
          kind: 'template',
          template: parts.map(p => p.kind === 'literal' ? p.value : '${' + (p.name || stringifyShape(p.value)) + '}').join(''),
          parts: parts,
        };
      }
      case 'object': {
        const shape = {};
        for (const k in v.props) shape[k] = valueToShape(v.props[k], S);
        return { kind: 'object', props: shape };
      }
      case 'array':
        return { kind: 'array', values: v.elems.map(e => valueToShape(e, S)) };
      case 'unknown':
        return { kind: 'unknown', reason: v.reason, taint: v.taint || undefined };
      default:
        return { kind: 'unknown', reason: 'opaque-external' };
    }
  }

  function stringifyShape(s) {
    if (!s) return '?';
    if (s.kind === 'concrete') return JSON.stringify(s.value);
    if (s.kind === 'oneOf') return '(' + s.values.map(v => JSON.stringify(v)).join('|') + ')';
    if (s.kind === 'template') return s.template || '?';
    if (s.kind === 'unknown') return '?' + s.reason;
    return '?';
  }

  // =========================================================================
  // XHR open/send pairing
  // =========================================================================
  // XMLHttpRequest is a two-step API:
  //   var xhr = new XMLHttpRequest();
  //   xhr.open("POST", "/api/submit");
  //   xhr.setRequestHeader("Content-Type", "application/json");
  //   xhr.send(body);
  //
  // We pair each .open() call with the nearest following .send()
  // call on the same file within a small line window. Headers
  // set via setRequestHeader between the two are also collected.
  // A .open() with no matching .send() is still captured as an
  // endpoint (reached: false for the send step).

  function pairXhrOpenSend(calls) {
    const pairs = [];
    const opens = calls.filter(c => {
      const base = c.callee.text.split('.').pop();
      return base === 'open' && c.args.length >= 2;
    });
    for (const open of opens) {
      let send = null;
      const headers = [];
      for (const c of calls) {
        if (c === open) continue;
        if (c.site.file !== open.site.file) continue;
        if (c.site.line <= open.site.line) continue;
        if (c.site.line - open.site.line > 20) continue;
        const base = c.callee.text.split('.').pop();
        if (base === 'setRequestHeader' && c.args.length >= 2) {
          headers.push(c);
        }
        if (base === 'send' && !send) {
          send = c;
          break;
        }
      }
      pairs.push({ open, send, headers });
    }
    return pairs;
  }

  function xhrPairToEndpoint(pair, query, S) {
    const { open, send, headers } = pair;
    // open(method, url, async?, user?, password?)
    const method = valueToShape(open.args[0], S);
    const url = valueToShape(open.args[1], S);
    const headerMap = {};
    for (const h of headers) {
      const nameArg = query.asConcrete(h.args[0]);
      if (nameArg) headerMap[nameArg] = valueToShape(h.args[1], S);
    }
    return {
      callee: 'XMLHttpRequest',
      site: open.site,
      reached: open.reached !== false,
      reachability: open.reachability,
      url: url,
      method: method && method.kind === 'concrete' ? method.value : method,
      headers: headerMap,
      body: send && send.args.length ? valueToShape(send.args[0], S) : null,
      allowedValues: {},
      _xhrPair: { openLine: open.site.line, sendLine: send ? send.site.line : null },
    };
  }

  // =========================================================================
  // Summary helpers for reports / UIs
  // =========================================================================

  // Flatten the endpoints into a {method, url} tuple array for
  // quick display. If a URL has enumerable holes, expand them.
  function summarize(endpointsOrReport) {
    const endpoints = endpointsOrReport.endpoints || endpointsOrReport;
    const rows = [];
    for (const ep of endpoints) {
      const methods = toMethods(ep.method);
      const urls = toUrls(ep.url);
      for (const m of methods) {
        for (const u of urls) {
          rows.push({ method: m, url: u, reached: ep.reached, file: ep.site.file, line: ep.site.line });
        }
      }
    }
    return rows;
  }

  function toMethods(m) {
    if (typeof m === 'string') return [m];
    if (!m) return ['GET'];
    if (m.kind === 'concrete') return [m.value];
    if (m.kind === 'oneOf') return m.values.slice();
    return ['<?>'];
  }

  function toUrls(u) {
    if (!u) return ['<?>'];
    if (u.kind === 'concrete') return [u.value];
    if (u.kind === 'oneOf') return u.values.slice();
    if (u.kind === 'template') {
      // Try to enumerate if every hole is enumerable
      const holeSets = [];
      for (const p of u.parts) {
        if (p.kind === 'literal') holeSets.push([p.value]);
        else {
          if (p.value && p.value.kind === 'concrete') holeSets.push([p.value.value]);
          else if (p.value && p.value.kind === 'oneOf') holeSets.push(p.value.values.slice());
          else { return [u.template]; }
        }
      }
      // Cartesian product
      let accs = [''];
      for (const s of holeSets) {
        const next = [];
        for (const a of accs) for (const v of s) next.push(a + v);
        accs = next;
      }
      return accs;
    }
    if (u.kind === 'unknown') return ['<?' + u.reason + '>'];
    return ['<?>'];
  }

  // =========================================================================
  // Export
  // =========================================================================

  const api = Object.freeze({
    discover,
    summarize,
    DEFAULT_TARGETS,
  });

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.FetchTrace = api;
  }
})();
