// fetch-trace.js — fetch/XHR call-site discovery consumer
// (Wave 12 / Phase E, D11)
//
// Walks a completed trace and extracts every fetch / XHR /
// Beacon / WebSocket / EventSource call site, resolving:
//
//   * URL (concrete string, OneOf union of strings, or
//     tainted opaque)
//   * HTTP method (default GET)
//   * Headers object (when passable as a concrete literal)
//   * Body shape (when the body is a concrete string or
//     FormData / Blob constructor call)
//   * Query-parameter keys, when the URL contains a `?`
//
// The point of this consumer is "discovers APIs that haven't
// been called yet, including URLs, methods, headers, body
// structure, and query params." — the bundle is analyzed
// interprocedurally, so call sites inside functions that
// haven't been reached from the top-level still surface
// (because trace.calls is populated unconditionally during
// the walk).
//
// Public API:
//
//   const ft = require('jsanalyze/consumers/fetch-trace');
//   const sites = await ft.trace(input, options?);
//     // returns Array<FetchCallSite>
//
//   type FetchCallSite = {
//     api: 'fetch' | 'XMLHttpRequest' | 'Beacon' | 'WebSocket' |
//          'EventSource' | 'Request';
//     url: string | null;           // concrete URL if known
//     urlValue: Value;              // raw Value from the trace
//     method: string;               // 'GET' / 'POST' / …
//     headers: Record<string, string> | null;
//     body: string | null;          // concrete body if known
//     bodyValue: Value | null;      // raw Value
//     queryKeys: string[];          // parsed from URL when known
//     site: Location;
//     // Reachability from the function entry — 'reachable' for
//     // every call the engine walked (which is all of them,
//     // interprocedurally).
//     reachable: boolean;
//     // Taint labels on the URL Value (for consumers that
//     // want to filter out call sites whose URL is built
//     // from attacker input).
//     urlLabels: string[];
//   };
//
// Design notes
// ------------
//
//   * Everything comes from trace.calls — no walker reach-in.
//   * Inter-proc tracing is free because the engine walks
//     user functions via applyCall. A `fetch()` inside an
//     event handler that the top-level never triggers still
//     gets analyzed and shows up in trace.calls.
//   * `options.accept` is passed through to the analyser so
//     consumers can reject performance shortcuts (e.g.
//     reject 'summary-reused' for full context sensitivity
//     on fetch-building helpers that get called from many
//     sites).

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');

// Callees whose URL goes into the fetch-trace output. Key:
// method/callee name; value: { api, urlArgIdx, initArgIdx? }.
// `initArgIdx` is the index of the options object for APIs
// that take one (fetch/Request), which is where the method,
// headers, and body live.
const FETCH_APIS = {
  'fetch':                      { api: 'fetch',          urlArgIdx: 0, initArgIdx: 1 },
  'Request':                    { api: 'Request',        urlArgIdx: 0, initArgIdx: 1 },
  'XMLHttpRequest.open':        { api: 'XMLHttpRequest', urlArgIdx: 1, methodArgIdx: 0 },
  'open':                       { api: 'XMLHttpRequest', urlArgIdx: 1, methodArgIdx: 0 },
  'navigator.sendBeacon':       { api: 'Beacon',         urlArgIdx: 0, bodyArgIdx: 1 },
  'sendBeacon':                 { api: 'Beacon',         urlArgIdx: 0, bodyArgIdx: 1 },
  'WebSocket':                  { api: 'WebSocket',      urlArgIdx: 0 },
  'EventSource':                { api: 'EventSource',    urlArgIdx: 0 },
};

async function trace(input, options) {
  options = options || {};
  const t = await analyze(input, {
    typeDB: options.typeDB || TDB,
    precision: options.precision || 'precise',
    accept: options.accept,
    watchers: options.watchers,
  });

  const out = [];
  for (const c of t.calls) {
    const text = c.callee.text || '';
    const base = text.split('.').pop();
    // Exact-match first, fall back to method-name match.
    const desc = FETCH_APIS[text] || FETCH_APIS[base];
    if (!desc) continue;

    const urlValue = c.args[desc.urlArgIdx] || null;
    const url = concreteString(urlValue);
    const queryKeys = extractQueryKeys(url);
    const urlLabels = valueLabels(urlValue);

    // Method resolution:
    //   * XHR: arg 0 is the method.
    //   * fetch / Request: init.method if the init object is
    //     a concrete literal we can inspect, else default GET.
    //   * WebSocket / EventSource / Beacon: no method.
    let method = 'GET';
    if (desc.methodArgIdx != null) {
      const m = concreteString(c.args[desc.methodArgIdx]);
      if (m) method = m.toUpperCase();
    } else if (desc.initArgIdx != null) {
      const init = c.args[desc.initArgIdx];
      const m = readInitField(init, 'method');
      if (m && typeof m === 'string') method = m.toUpperCase();
    }
    if (desc.api === 'Beacon') method = 'POST';   // sendBeacon is always POST

    // Headers resolution: init.headers for fetch / Request.
    let headers = null;
    if (desc.initArgIdx != null) {
      const init = c.args[desc.initArgIdx];
      const h = readInitField(init, 'headers');
      headers = canonicalizeHeaders(h);
    }

    // Body resolution: init.body for fetch / Request;
    // arg N for sendBeacon.
    let bodyValue = null;
    if (desc.initArgIdx != null) {
      const init = c.args[desc.initArgIdx];
      bodyValue = readInitFieldRaw(init, 'body');
    } else if (desc.bodyArgIdx != null) {
      bodyValue = c.args[desc.bodyArgIdx] || null;
    }
    const body = concreteString(bodyValue);

    out.push({
      api: desc.api,
      url,
      urlValue,
      method,
      headers,
      body,
      bodyValue,
      queryKeys,
      site: c.site,
      reachable: c.reachability !== 'unreachable',
      urlLabels,
    });
  }

  return out;
}

// concreteString — return the concrete string value of a
// Value if known, else null. Handles Concrete, single-element
// OneOf, and StrPattern with both prefix AND suffix (rare).
function concreteString(v) {
  if (!v) return null;
  if (v.kind === 'concrete' && typeof v.value === 'string') return v.value;
  if (v.kind === 'oneOf' && Array.isArray(v.values) && v.values.length === 1 &&
      typeof v.values[0] === 'string') {
    return v.values[0];
  }
  return null;
}

// valueLabels — return the array form of a Value's labels.
function valueLabels(v) {
  if (!v || !v.labels) return [];
  if (v.labels instanceof Set) return Array.from(v.labels).sort();
  if (Array.isArray(v.labels)) return v.labels.slice().sort();
  return [];
}

// extractQueryKeys(url) — parse the query string of a URL
// and return the set of parameter keys, sorted. Null URLs
// and URLs without a query string return [].
function extractQueryKeys(url) {
  if (!url || typeof url !== 'string') return [];
  const qIdx = url.indexOf('?');
  if (qIdx < 0) return [];
  const query = url.slice(qIdx + 1).split('#')[0];
  const keys = new Set();
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=');
    const key = eq >= 0 ? pair.slice(0, eq) : pair;
    if (key) keys.add(decodeURIComponent(key));
  }
  return Array.from(keys).sort();
}

// readInitField — look up a field on an object-shaped Value.
// Returns the concrete value if the field is a concrete
// primitive, else null.
function readInitField(initValue, fieldName) {
  const raw = readInitFieldRaw(initValue, fieldName);
  return concreteString(raw) || (raw && raw.kind === 'concrete' ? raw.value : null);
}

// readInitFieldRaw — raw Value access on an object-shaped
// Value. `initValue` may be a Value with `fields` (rare) or
// an 'object' kind with `props` (the public projection).
// Returns the field's Value or null.
function readInitFieldRaw(initValue, fieldName) {
  if (!initValue) return null;
  if (initValue.kind !== 'object') return null;
  const props = initValue.props || initValue.fields || null;
  if (!props) return null;
  return props[fieldName] || null;
}

// canonicalizeHeaders — convert a headers Value into a plain
// object, if the value is fully enumerable. Returns null for
// non-enumerable values so consumers know to fall back to the
// taint labels on the headers Value.
function canonicalizeHeaders(headersValue) {
  if (!headersValue || headersValue.kind !== 'object') return null;
  const props = headersValue.props || headersValue.fields || null;
  if (!props) return null;
  const out = {};
  for (const k in props) {
    const v = props[k];
    const concrete = concreteString(v);
    if (concrete != null) out[k] = concrete;
  }
  return Object.keys(out).length > 0 ? out : null;
}

module.exports = {
  trace,
};
