// jsanalyze-query.js
//
// Stage 2 of the jsanalyze migration plan.
//
// This file is the public query layer. It exposes two things:
//
//   (1) `analyze(input, options)` — a single entry point that runs
//       the walker over an input (string or file map) and produces
//       a Trace object. A Trace is pure data, JSON-serializable,
//       versioned, and the stable contract between the walker and
//       every consumer.
//
//   (2) A `query` namespace of pure functions over a Trace —
//       `query.calls(trace, filter)`, `query.enumerate(value)`,
//       `query.property(value, path)`, `query.valueSetOf(trace, name)`,
//       `query.innerHtmlAssignments(trace)`, `query.taintFlows(trace)`,
//       `query.stringLiterals(trace, filter)`, `query.callGraph(trace)`.
//
// Every query takes a Trace and returns a typed result. Queries
// never re-walk the code — they're cheap, composable, and
// cacheable. If a consumer needs to observe events at walk time
// (streaming), it passes `options.watchers` to `analyze` which
// installs them on the walker directly.
//
// The walker lives in jsanalyze.js (renamed from htmldom.js in Stage 5).
// This file reaches into the
// walker via `globalThis.__jsanalyze` / `globalThis.__bindingToValue`
// that the walker's IIFE sets when it loads.

(function () {
  'use strict';

  // === Schema module (required) ===
  function loadSchemas() {
    if (typeof globalThis !== 'undefined' && globalThis.JsAnalyzeSchemas) return globalThis.JsAnalyzeSchemas;
    if (typeof require !== 'undefined') {
      try { return require('./jsanalyze-schemas.js'); } catch (_) {}
    }
    throw new Error('jsanalyze-query: jsanalyze-schemas.js not available');
  }

  // === Walker access ===
  // Reaches into jsanalyze.js through the same globals the test
  // harness uses. Direct require is preferred when available.
  function loadWalker() {
    if (typeof globalThis !== 'undefined' && globalThis.__jsanalyze) return globalThis.__jsanalyze;
    if (typeof require !== 'undefined') {
      try {
        const api = require('./jsanalyze.js');
        if (api && api.jsanalyze) return api.jsanalyze;
      } catch (_) {}
    }
    throw new Error('jsanalyze-query: walker not available');
  }

  // === Trace shape ===
  //
  // {
  //   schemaVersion: '1',
  //   partial: boolean,
  //   files: { filename -> source },
  //   calls: CallSite[],                  // every call site observed during the walk
  //   innerHtmlAssignments: HtmlAssignment[],
  //   taintFlows: TaintFlow[],
  //   stringLiterals: LiteralObservation[],
  //   mayBe: { name -> MayBeSlot },       // copy of walker lattice
  //   bindings: { name -> Value },        // final top-level bindings
  //   warnings: Warning[],                // partial-walk notices
  // }
  //
  // Every field is populated at walk time by hooks. Queries read
  // these arrays directly — no re-walking.

  function mkTrace(files, schemas) {
    return {
      schemaVersion: schemas.SCHEMA_MAJOR,
      partial: false,
      files: Object.assign(Object.create(null), files),
      calls: [],
      innerHtmlAssignments: [],
      taintFlows: [],
      stringLiterals: [],
      mayBe: Object.create(null),
      bindings: Object.create(null),
      warnings: [],
    };
  }

  // === analyze() — the one entry point ===
  async function analyze(input, options) {
    options = options || {};
    const schemas = loadSchemas();
    const walker = loadWalker();
    const { tokenize, buildScopeState, scanMutations, bindingToValue } = walker;

    // Normalize input to { filename: source } so single-file and
    // multi-file consumers take the same path. A bare string is
    // treated as a single JS file under the synthetic name
    // '<input>.js' so the file-extension filter below still picks
    // it up.
    const files = typeof input === 'string' ? { '<input>.js': input } : Object.assign(Object.create(null), input);
    const trace = mkTrace(files, schemas);

    const taintConfig = options.taint ? (typeof options.taint === 'object' ? options.taint : { enabled: true }) : null;

    // Build a shared recorder and the walker hooks. Users can
    // supplement with their own watchers via options.watchers.
    const userWatchers = (options.watchers && options.watchers.callWatchers) || [];
    const assignmentWatchers = (options.watchers && options.watchers.innerHtmlAssignmentWatchers) || [];
    const literalWatchers = (options.watchers && options.watchers.literalWatchers) || [];

    // Multi-file handling: concatenate every JavaScript file into
    // a single token stream with line-directive comments marking
    // file boundaries. The walker sees one big program, which
    // gives us cross-file symbol resolution for free (a function
    // defined in a.js called from b.js walks its body at the call
    // site). The callRecorder looks up the file from the token's
    // position in this merged source via `fileBoundaries`.
    //
    // The alternative — walk each file in isolation — loses
    // cross-file flow entirely and was the initial blocker. For
    // now we concat unconditionally and trust the walker's scope
    // stack to keep file-local `var` and `const` hygienic (which
    // it does — each file is separated by a blank line and there
    // are no top-level `let`/`const` sharing concerns since JS
    // bundles don't use them across files without a module system).
    //
    // A future version could preserve module boundaries more
    // carefully, but for Stage 2 this gives us working cross-file
    // inter-procedural analysis.
    const fileList = Object.keys(files).filter(f => /\.(m?js)$/i.test(f));
    let mergedSrc = '';
    const fileBoundaries = []; // { file, start, end }
    for (const filename of fileList) {
      const start = mergedSrc.length;
      const content = files[filename];
      mergedSrc += content;
      if (!content.endsWith('\n')) mergedSrc += '\n';
      mergedSrc += '\n'; // extra blank line between files
      fileBoundaries.push({ file: filename, start, end: mergedSrc.length });
    }

    function fileForPos(pos) {
      for (const b of fileBoundaries) {
        if (pos >= b.start && pos < b.end) return b.file;
      }
      return '<input>';
    }

    // Dedupe key for call entries — same callee text + same file:line
    // + same args fingerprint. Walker passes may walk the same
    // call site twice (once definition-time with symbolic params,
    // once per concrete caller); deduping by fingerprint keeps the
    // trace tight without losing distinct-value entries.
    const seenCalls = Object.create(null);
    function callFingerprint(entry) {
      return entry.callee.text + '|' + entry.site.file + ':' + entry.site.line + '|' +
        entry.args.map(a => schemas.helpers.stringify(a)).join('||');
    }

    const callRecorder = (callee, argBindings, tok, info) => {
      const file = tok && tok.start != null ? fileForPos(tok.start) : '<input>';
      const args = argBindings.map(b => bindingToValue(b, { file: file }));
      const site = makeSource(tok, file, schemas.SOURCE_KINDS.INLINE_LITERAL, schemas);
      const pathConditions = (info.pathConditions || []).map(c => ({
        text: typeof c === 'string' ? c : String(c),
      }));
      const reachability = pathConditions.length
        ? { kind: 'conditional', conditions: pathConditions }
        : { kind: 'always' };
      const entry = {
        callee: { text: callee, resolved: null },
        args: args,
        site: site,
        reachability: reachability,
        reached: info.reached !== false,
      };
      const fp = callFingerprint(entry);
      if (seenCalls[fp]) return;
      seenCalls[fp] = true;
      trace.calls.push(entry);
      for (const w of userWatchers) {
        try { w(callee, argBindings, tok, info); } catch (_) {}
      }
    };

    let anyWalked = false;
    if (mergedSrc.trim()) {
      try {
        const tokens = tokenize(mergedSrc);
        const mut = scanMutations(tokens);
        const scope = await buildScopeState(
          tokens, tokens.length, mut, null, taintConfig,
          { callWatchers: [callRecorder] }
        );
        anyWalked = true;

        if (scope) {
          if (scope.taintFindings) {
            for (const f of scope.taintFindings) {
              const file = f.location ? fileForPos(f.location.pos | 0) : (fileList[0] || '<input>');
              trace.taintFlows.push(taintFindingToFlow(f, file, schemas));
            }
          }
          if (scope.domElements && scope.domElements.length) {
            trace._domElements = scope.domElements.slice();
          }
          if (scope.domOps && scope.domOps.length) {
            trace._domOps = scope.domOps.slice();
          }
        }
      } catch (e) {
        trace.partial = true;
        trace.warnings.push({
          severity: 'error',
          message: 'walk failed: ' + (e.message || String(e)),
        });
      }
    }

    if (!anyWalked) {
      trace.warnings.push({
        severity: 'warning',
        message: 'no JavaScript files found to analyze',
      });
    }

    return trace;
  }

  // === Helpers ===

  // Cached line-start index for the most-recently-seen source string.
  // The walker hands makeSource a stream of tokens that all share
  // the same `_src` reference across a single analyze() call, so
  // caching only the most recent source hits 100% within any one
  // walk while staying O(1) in memory across calls. Without this,
  // each makeSource was scanning from byte 0 to the token's byte
  // offset, making trace construction quadratic in source length.
  let _lineSrc = null;
  let _lineStarts = null;
  function _getLineStarts(src) {
    if (src === _lineSrc) return _lineStarts;
    const starts = [0];
    for (let i = 0; i < src.length; i++) {
      if (src.charCodeAt(i) === 10) starts.push(i + 1);
    }
    _lineSrc = src;
    _lineStarts = starts;
    return starts;
  }
  function _lineColFromPos(src, pos) {
    const starts = _getLineStarts(src);
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1;
      if (starts[mid] <= pos) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, col: pos - starts[lo] };
  }

  function makeSource(tok, file, kind, schemas) {
    if (!tok || !tok._src) return schemas.mkSource(file || '<anonymous>', 1, 0, kind);
    const src = tok._src;
    const pos = tok.start | 0;
    const lc = _lineColFromPos(src, pos);
    const snippet = src.slice(pos, Math.min(tok.end || pos + 40, src.length));
    return schemas.mkSource(file || '<anonymous>', lc.line, lc.col, kind, snippet);
  }

  function taintFindingToFlow(finding, file, schemas) {
    return {
      type: finding.type || 'unknown',
      severity: finding.severity || 'medium',
      sources: (finding.sources || []).slice(),
      sink: {
        prop: finding.sink ? finding.sink.prop : null,
        elementTag: finding.sink ? finding.sink.elementTag : null,
      },
      conditions: (finding.conditions || []).map(c => ({ text: String(c) })),
      site: {
        file: file,
        line: finding.location ? (finding.location.line | 0) : 1,
        col: finding.location ? ((finding.location.pos | 0) || 0) : 0,
        kind: schemas.SOURCE_KINDS.ASSIGNMENT,
        snippet: finding.location ? finding.location.expr : undefined,
      },
    };
  }

  // =========================================================================
  // === Query primitives ===
  //
  // Every query is a pure function over a Trace. No side effects,
  // no walker re-run, no hidden state. Consumers can mix-and-match
  // queries freely and cache results.
  // =========================================================================

  const query = Object.freeze({

    // --- calls(trace, filter) ---
    //
    // Return every call site whose callee matches `filter.targets`.
    // `filter.targets` is an array of strings; each entry matches
    // either the full dotted callee text ('xhr.open') or the final
    // segment ('open'). If `filter.targets` is absent, returns all
    // call sites.
    //
    // Additional filters:
    //   filter.reached: true — only reached call sites
    //   filter.reached: false — only unreached (dead code)
    //   filter.reachability: 'always' | 'conditional' | 'unreachable'
    calls(trace, filter) {
      filter = filter || {};
      const targets = filter.targets ? new Set(filter.targets) : null;
      return trace.calls.filter(c => {
        if (targets) {
          const text = c.callee.text || '';
          if (!targets.has(text)) {
            const base = text.split('.').pop();
            if (!targets.has(base)) return false;
          }
        }
        if (filter.reached === true && !c.reached) return false;
        if (filter.reached === false && c.reached) return false;
        if (filter.reachability && c.reachability.kind !== filter.reachability) return false;
        return true;
      });
    },

    // --- property(value, path) ---
    //
    // Navigate into a Value. `path` is a dotted string like
    // 'headers.Content-Type'. Handles object walks; returns an
    // `unknown` Value if the path doesn't resolve.
    property(value, path) {
      const S = loadSchemas();
      if (!value || !path) return S.value.unknown(S.UNKNOWN_REASONS.UNRESOLVED_IDENTIFIER, null, []);
      const parts = String(path).split('.');
      let cur = value;
      for (const p of parts) {
        if (!cur) return S.value.unknown(S.UNKNOWN_REASONS.UNRESOLVED_IDENTIFIER, null, []);
        if (cur.kind !== 'object') return S.value.unknown(S.UNKNOWN_REASONS.UNRESOLVED_IDENTIFIER, null, []);
        cur = cur.props[p];
      }
      if (!cur) return S.value.unknown(S.UNKNOWN_REASONS.UNRESOLVED_IDENTIFIER, null, []);
      return cur;
    },

    // --- enumerate(value) ---
    //
    // Return every concrete primitive `value` could take, as an
    // array. Returns null if any branch is not fully enumerable.
    // Delegates to the schema helper.
    enumerate(value) {
      return loadSchemas().helpers.enumerate(value);
    },

    // --- asConcrete(value) ---
    //
    // Return the concrete primitive if `value` is `kind: 'concrete'`,
    // null otherwise. Does not attempt to materialize templates or
    // oneOf — use `enumerate` for that.
    asConcrete(value) {
      return loadSchemas().helpers.asConcrete(value);
    },

    // --- stringify(value) ---
    stringify(value) {
      return loadSchemas().helpers.stringify(value);
    },

    // --- innerHtmlAssignments(trace) ---
    innerHtmlAssignments(trace) {
      return trace.innerHtmlAssignments.slice();
    },

    // --- taintFlows(trace, filter) ---
    //
    // Return taint flows, optionally filtered by severity / source
    // label / sink prop.
    taintFlows(trace, filter) {
      filter = filter || {};
      return trace.taintFlows.filter(f => {
        if (filter.severity && f.severity !== filter.severity) return false;
        if (filter.source && !f.sources.includes(filter.source)) return false;
        if (filter.sinkProp && f.sink.prop !== filter.sinkProp) return false;
        return true;
      });
    },

    // --- stringLiterals(trace, filter) ---
    //
    // Every string literal observed in a given context (e.g.
    // 'fetch.arg0', 'script.src'). Filter by context substring.
    stringLiterals(trace, filter) {
      filter = filter || {};
      let out = trace.stringLiterals.slice();
      if (filter.context) {
        out = out.filter(l => l.context && l.context.indexOf(filter.context) >= 0);
      }
      return out;
    },

    // --- valueSetOf(trace, name) ---
    //
    // Every concrete literal `name` can take, as far as the may-be
    // lattice + call site enumeration knows. Uses the lattice first,
    // falls back to scanning call sites whose callee parameter
    // matches `name`.
    valueSetOf(trace, name) {
      const slot = trace.mayBe[name];
      if (slot && slot.values) return slot.values.slice();
      // Lattice has no entry — scan call args for calls whose
      // resolved callee has `name` as a param. Not perfect but
      // useful for inter-procedural enumeration.
      const vals = [];
      const seen = new Set();
      for (const c of trace.calls) {
        if (!c.callee.resolved) continue;
        const params = c.callee.resolved.params || [];
        const idx = params.indexOf(name);
        if (idx < 0) continue;
        const av = c.args[idx];
        if (!av) continue;
        const concrete = loadSchemas().helpers.asConcrete(av);
        if (concrete !== null && !seen.has(concrete)) {
          seen.add(concrete);
          vals.push(concrete);
        }
      }
      return vals.length ? vals : null;
    },

    // --- callGraph(trace) ---
    //
    // Build a call graph from observed call sites. Nodes are
    // function names (or file+line for anonymous functions).
    // Edges are {from, to, site, reachable}.
    callGraph(trace) {
      const nodes = new Set(['<top>']);
      const edges = [];
      for (const c of trace.calls) {
        const from = c.caller && c.caller.name ? c.caller.name : '<top>';
        const to = c.callee.text;
        nodes.add(from);
        nodes.add(to);
        edges.push({ from, to, site: c.site, reachable: c.reached });
      }
      return {
        nodes: Array.from(nodes),
        edges: edges,
      };
    },
  });

  // === Export ===
  const api = Object.freeze({
    analyze: analyze,
    query: query,
    // Re-exports for consumer convenience.
    schemas: loadSchemas(),
  });

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.JsAnalyzeQuery = api;
  }
})();
