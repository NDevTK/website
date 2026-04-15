// z3.js — Wave 11 / Phase D: Z3-backed SMT, per D5.
//
// Contract (DESIGN-DECISIONS.md §D5):
//
//   * Z3 is vendored under `jsanalyze/vendor/z3-solver/` as
//     the single on-disk copy of the 33 MB WASM.
//
//   * The SMT layer imports Z3 through a single `_initZ3()`
//     function that works in BOTH Node (`require('z3-solver')`)
//     and the browser (via `globalThis.__htmldomZ3Init`, the
//     pre-registered loader from `analyzer/jsanalyze-z3-browser.js`).
//
// Z3 is REQUIRED. There is no fallback path; if the solver
// can't load, analysis fails loudly. This mirrors the legacy
// engine's "every formula goes through Z3; no fallback" rule.
//
// Reachability cascade (D6, Layer 5)
// ----------------------------------
//
// The worklist's BRANCH handling calls `checkPathSat(formula)`
// once per unresolved-at-layers-1-4 edge. The function returns
// 'sat' | 'unsat' | 'unknown' and caches results by the
// formula's string expression so repeated branch decisions on
// the same conjunction hit the cache.
//
// The solver uses Z3's push/pop frames to isolate each check
// from subsequent checks: declarations are installed once at
// the persistent solver level, the per-check extras go inside
// a push frame, and pop() restores the solver after the check.
// This matches the legacy engine's `smtSat` pattern.
//
// Post-pass refutation
// --------------------
//
// `refuteTrace(trace)` runs after the worklist completes and
// drops any taint flow whose pathFormula is UNSAT that wasn't
// already killed by the Layer 5 cascade (which kills flows at
// the block level, not at the flow emission point). This is a
// secondary check: Layer 5 handles the common case during the
// walk; refuteTrace catches residuals from flows emitted
// before the path formula reached its final disjunctive form.

'use strict';

const SMT = require('./smt.js');

// --- Loader ---------------------------------------------------------------
//
// Three loading paths, tried in order, matching the legacy
// engine's _initZ3 exactly:
//
//   1. `globalThis.__htmldomZ3Init` — browser, pre-registered
//      by `analyzer/jsanalyze-z3-browser.js`. Returns an init
//      function that boots the vendored WASM lazily.
//
//   2. Node `require('z3-solver')` — the test harness and any
//      CommonJS consumer. The vendored copy at
//      `jsanalyze/vendor/z3-solver/` is required by absolute
//      path (see below).
//
//   3. Error — neither path was set up. Loud failure.
let _z3 = null;
let _z3Promise = null;
function _initZ3() {
  if (_z3Promise) return _z3Promise;
  _z3Promise = (async function () {
    let initFn = null;
    if (typeof globalThis !== 'undefined' && typeof globalThis.__htmldomZ3Init === 'function') {
      initFn = globalThis.__htmldomZ3Init;
    } else if (typeof window === 'undefined' && typeof module === 'object' && module && module.exports && typeof require === 'function') {
      // Node: require the vendored package by its absolute
      // path under jsanalyze/vendor/z3-solver/.
      const path = require('path');
      const vendorEntry = path.join(__dirname, '..', 'vendor', 'z3-solver', 'node.js');
      const mod = require(vendorEntry);
      initFn = mod.init;
    } else {
      throw new Error(
        'jsanalyze: Z3 is not available. In the browser, load ' +
        'analyzer/jsanalyze-z3-browser.js before jsanalyze. ' +
        'In Node, ensure jsanalyze/vendor/z3-solver/ is populated.'
      );
    }
    const api = await initFn();
    const context = api.Context('jsanalyze');
    _z3 = { api: api, Context: context, Solver: context.Solver };
    return _z3;
  })();
  return _z3Promise;
}

// --- Shared solver state --------------------------------------------------
//
// Mirror the legacy `smtSat` caching: one persistent Solver,
// a declaration tracker, and a satisfiability memoisation map
// keyed by the formula's (sorted) script text. push/pop
// isolates individual checks.
//
// Multi-use: the solver state is module-level (intentional — Z3
// init is 33 MB of WASM and costs seconds; we amortise it
// across every `analyze()` call in the process). The SAT cache
// is LRU-bounded so long-running hosts (browser UIs, analysis
// servers) don't leak memory over hours of analysis.
// `_declaredSorts` is small (bounded by the number of distinct
// source syms in the program being analysed; each analyse()
// call resets the solver if a sort conflict appears so
// declarations are refreshed). `resetCache()` is exposed for
// hosts that want a hard reset — e.g. a browser UI loading a
// new file where the previous file's cached SAT results are
// stale.
let _sharedSolver = null;
const _declaredSorts = new Map();   // symName → 'Int' | 'String' | 'Bool'

// SAT-result LRU. We use a plain Map and rely on JavaScript
// Map's insertion-order iteration to implement LRU-on-touch:
// every read deletes + reinserts the entry so its iteration
// position moves to the newest slot; evictions pop the oldest
// entry when the size exceeds SAT_CACHE_LIMIT. The limit is a
// property of the *solver cache implementation*, not an
// analysis knob — it bounds memory growth and nothing else.
// Cache hits preserve the same verdict they'd return
// uncached; evictions just trigger a re-solve.
const SAT_CACHE_LIMIT = 10000;
const _satCache = new Map();        // scriptText → verdict

function _satCacheGet(key) {
  if (!_satCache.has(key)) return undefined;
  const v = _satCache.get(key);
  // Touch: move to most-recent by delete + reinsert.
  _satCache.delete(key);
  _satCache.set(key, v);
  return v;
}

function _satCachePut(key, verdict) {
  _satCache.set(key, verdict);
  if (_satCache.size > SAT_CACHE_LIMIT) {
    // Evict the oldest entry. Map iterator yields in insertion
    // order; the first key is the LRU victim.
    const oldest = _satCache.keys().next().value;
    if (oldest !== undefined) _satCache.delete(oldest);
  }
}

// resetCache() — hard reset of the per-process solver cache.
// Hosts that reuse a single jsanalyze import across many
// analyses (browser UI, analysis server) call this when they
// want to guarantee no stale SAT results from a previous
// analyse() leak into the next. The shared Solver is also
// released so its declaration table is rebuilt from scratch
// on the next `_initZ3()` use. Safe to call at any time.
function resetCache() {
  _satCache.clear();
  _declaredSorts.clear();
  _sharedSolver = null;
}

// Emit declare-const lines for every sort in `formula.sorts`
// that isn't already installed on the shared solver, AND
// record the declarations in `_declaredSorts`. If any sym has
// a conflicting prior sort, return null — the caller must
// skip this formula (we don't reset the solver on sort
// upgrades to keep things simple).
function computePendingDecls(formula) {
  if (!formula || !formula.sorts) return '';
  let pending = '';
  for (const name in formula.sorts) {
    if (name === '__conflict') continue;
    const sort = formula.sorts[name] || 'Int';
    const prev = _declaredSorts.get(name);
    if (prev === sort) continue;
    if (prev && prev !== sort) return null;  // sort upgrade: bail
    pending += '(declare-const ' + _quoteSmtName(name) + ' ' + sort + ')\n';
  }
  return pending;
}

function _quoteSmtName(s) {
  return '|' + String(s).replace(/\|/g, '_') + '|';
}

function _recordDecls(formula) {
  if (!formula || !formula.sorts) return;
  for (const name in formula.sorts) {
    if (name === '__conflict') continue;
    const sort = formula.sorts[name] || 'Int';
    _declaredSorts.set(name, sort);
  }
}

// --- checkPathSat ---------------------------------------------------------
//
// Ask Z3 whether `formula` is satisfiable. Returns:
//
//   'sat'     — a model exists; the path is feasible
//   'unsat'   — no model; the path is statically dead
//   'unknown' — timeout, sort conflict, or unhandled fragment
//
// Callers treat 'unsat' as a refutation and 'sat'/'unknown'
// as "keep the edge/flow". Soundness is one-sided.
//
// `timeoutMs` caps the solver's wall-clock budget. The legacy
// engine uses 5000ms; API.md specifies this as the default
// `options.smtTimeoutMs`.
async function checkPathSat(formula, timeoutMs) {
  if (!formula) return 'sat';                    // null = top, trivially SAT
  if (formula.value && formula.value.kind === 'bool') {
    return formula.value.val ? 'sat' : 'unsat';
  }
  if (formula.incompatible) return 'unknown';
  if (!SMT.hasSym(formula)) {
    // Fully concrete formula — fold at the SMT level.
    return 'sat';
  }

  // Build the script text used for caching.
  const asserted = formula.isBool
    ? formula.expr
    : SMT._internals.toBool(formula);
  const assertText = '(assert ' + asserted + ')\n';
  const cacheKey = assertText;
  const hit = _satCacheGet(cacheKey);
  if (hit !== undefined) return hit;

  const z3 = await _initZ3();
  if (!_sharedSolver) _sharedSolver = new z3.Solver();

  // Compute the declarations this formula needs. If any sym
  // has a conflicting prior sort, reset the solver (and
  // _declaredSorts) and re-declare.
  let pending = computePendingDecls(formula);
  if (pending === null) {
    // Sort conflict — fall back by resetting the solver.
    _sharedSolver = new z3.Solver();
    _declaredSorts.clear();
    _satCache.clear();
    pending = computePendingDecls(formula);
  }
  if (pending) {
    _sharedSolver.fromString(pending);
    _recordDecls(formula);
  }

  // Configure per-check timeout. The Z3 Solver.set API
  // accepts ('timeout', <ms>). Supported in current builds.
  if (typeof timeoutMs === 'number' && timeoutMs > 0) {
    _sharedSolver.set('timeout', timeoutMs);
  }

  _sharedSolver.push();
  _sharedSolver.fromString(assertText);
  const result = await _sharedSolver.check();
  _sharedSolver.pop();

  let verdict;
  if (result === 'unsat') verdict = 'unsat';
  else if (result === 'sat') verdict = 'sat';
  else verdict = 'unknown';
  _satCachePut(cacheKey, verdict);
  return verdict;
}

// --- getModel -------------------------------------------------------------
//
// Ask Z3 to produce a satisfying assignment for `formula`. On
// SAT, returns { [symName]: string | number | boolean } keyed
// by the original sym names (stripped of pipe quoting). On
// UNSAT or UNKNOWN, returns null.
//
// This is the witness-extraction half of the solver interface:
// `checkPathSat` decides feasibility, `getModel` turns a
// feasible formula into a concrete attacker input. The inline
// PoC synthesis pass below (`synthesisePocs`) conjoins a
// taint flow's pathFormula with a sink-specific exploitability
// constraint and calls this function to get a payload.
//
// Like `checkPathSat`, this function uses the shared solver
// with push/pop so concurrent `refuteTrace` calls don't
// corrupt each other. Unlike `checkPathSat` it does NOT cache
// results — models can grow large and the SAT cache entry
// size is the inverse of throughput.
async function getModel(formula, timeoutMs) {
  if (!formula) return Object.create(null);   // top — no constraints, empty witness
  if (formula.value && formula.value.kind === 'bool') {
    return formula.value.val ? Object.create(null) : null;
  }
  if (formula.incompatible) return null;

  const asserted = formula.isBool
    ? formula.expr
    : SMT._internals.toBool(formula);
  const assertText = '(assert ' + asserted + ')\n';

  const z3 = await _initZ3();
  if (!_sharedSolver) _sharedSolver = new z3.Solver();

  let pending = computePendingDecls(formula);
  if (pending === null) {
    _sharedSolver = new z3.Solver();
    _declaredSorts.clear();
    _satCache.clear();
    pending = computePendingDecls(formula);
  }
  if (pending) {
    _sharedSolver.fromString(pending);
    _recordDecls(formula);
  }

  if (typeof timeoutMs === 'number' && timeoutMs > 0) {
    _sharedSolver.set('timeout', timeoutMs);
  }

  _sharedSolver.push();
  _sharedSolver.fromString(assertText);
  const verdict = await _sharedSolver.check();
  if (verdict !== 'sat') {
    _sharedSolver.pop();
    return null;
  }
  const model = _sharedSolver.model();

  // Walk the model's declarations and pull out every sym that
  // appears in `formula.sorts`. The vendored z3-solver exposes
  // the model as an iterable of FuncDecl; each decl has a
  // `.name()` (the symbol name) and a `.call()` that returns
  // the corresponding application AST. `model.eval(app)`
  // yields the value AST, whose `asString()` gives the
  // textual form (unquoted for String sort, decimal for Int /
  // Real, 'true'/'false' for Bool).
  const out = Object.create(null);
  for (const decl of model) {
    const name = String(typeof decl.name === 'function' ? decl.name() : decl.name);
    if (!(name in formula.sorts) || name === '__conflict') continue;
    const ast = model.eval(decl.call());
    out[name] = astToJs(ast, formula.sorts[name]);
  }
  _sharedSolver.pop();
  return out;
}

// astToJs — decode a Z3 model AST into a JS primitive. Uses
// `asString()` when the vendored z3-solver exposes it
// (preferred — it already handles String sort de-quoting and
// Int / Real formatting); falls back to `toString()` for
// older bindings.
function astToJs(ast, sort) {
  if (ast == null) return undefined;
  const raw = typeof ast.asString === 'function'
    ? ast.asString()
    : String(ast);
  if (raw == null) return undefined;
  if (sort === 'String') {
    // `asString()` on the vendored build returns the raw
    // characters (no outer quotes). Older bindings return
    // `"…"`; strip quotes if present.
    if (raw.length >= 2 && raw[0] === '"' && raw[raw.length - 1] === '"') {
      return raw.slice(1, -1).replace(/""/g, '"');
    }
    return raw;
  }
  if (sort === 'Bool') {
    return raw === 'true';
  }
  // Int / Real: `(- 5)` style negatives need parsing.
  const m = raw.match(/^\(- (\d+(?:\.\d+)?)\)$/);
  if (m) return -Number(m[1]);
  const n = Number(raw);
  return Number.isNaN(n) ? raw : n;
}

// --- refuteTrace ----------------------------------------------------------
//
// Post-pass refutation over a completed trace. For each flow
// whose pathFormula is non-trivial, ask checkPathSat; drop
// flows with 'unsat' verdicts into `trace.refutedFlows`.
// Flows already killed during the Layer 5 cascade never reach
// this pass (they weren't emitted in the first place). After
// refutation, surviving flows get a PoC witness attached via
// synthesisePocs — the same SMT system drives both refutation
// and witness extraction so we don't need a separate consumer
// pass.
async function refuteTrace(trace, timeoutMs) {
  if (!trace || !trace.taintFlows || trace.taintFlows.length === 0) {
    return trace;
  }
  const kept = [];
  const refuted = trace.refutedFlows ? trace.refutedFlows.slice() : [];
  for (const flow of trace.taintFlows) {
    const f = flow.pathFormula;
    if (!f || f.incompatible || !SMT.hasSym(f)) {
      kept.push(flow);
      continue;
    }
    const verdict = await checkPathSat(f, timeoutMs);
    if (verdict === 'unsat') {
      refuted.push(flow);
    } else {
      kept.push(flow);
    }
  }
  trace.taintFlows = kept;
  if (refuted.length > 0) trace.refutedFlows = refuted;
  await synthesisePocs(trace, timeoutMs);
  return trace;
}

// --- PoC synthesis ---------------------------------------------------------
//
// Per-sink exploit constraints. Each entry takes the flow's
// valueFormula (the SMT expression for the value reaching the
// sink) and returns a predicate that an attacker-controllable
// witness must satisfy. The conjunction of pathFormula ∧
// exploit(valueFormula) is handed to Z3; a SAT model gives us
// a concrete payload.
//
//   html       — innerHTML / outerHTML / document.write /
//                insertAdjacentHTML. A payload containing a
//                `<script>` open tag is parsed as an element
//                whose content is executed inline.
//   navigation — location.href / location.assign /
//                window.open. `javascript:` URLs execute as
//                code in the current origin.
//   url        — iframe.src / frame.src / img.src. Same
//                `javascript:` vector inside a frame.
//   code       — eval / Function / setTimeout(string). Any
//                non-empty string suffices to demonstrate
//                attacker control.
const EXPLOIT_CONSTRAINTS = {
  html:       (val) => SMT.mkContains(val, SMT.mkConst('<script>')),
  navigation: (val) => SMT.mkPrefixOf(SMT.mkConst('javascript:'), val),
  url:        (val) => SMT.mkPrefixOf(SMT.mkConst('javascript:'), val),
  code:       (val) => SMT.mkCmp('>', SMT.mkLength(val), SMT.mkConst(0)),
};

// extractPayload — pick a single value from the witness map
// most likely to interest a human reviewer. String bindings
// come first (those are the attacker-visible payloads);
// everything else falls back to a JSON dump.
function extractPayload(witness) {
  if (!witness) return null;
  const keys = Object.keys(witness);
  if (keys.length === 0) return '';
  for (const k of keys) {
    if (typeof witness[k] === 'string') return witness[k];
  }
  return JSON.stringify(witness);
}

// synthesisePocs — attach a PoC witness to every surviving
// taint flow. Runs immediately after refuteTrace so the
// witness is built from the same solver state that already
// determined the flow's feasibility. Per-flow results are
// written onto `flow.poc`:
//
//   { verdict: 'synthesised' | 'trivial' | 'infeasible'
//              | 'unsolvable' | 'no-constraint',
//     payload: string | null,
//     witness: {symName: value} | null,
//     note:    string | null }
//
// verdict meanings:
//   trivial       — valueFormula is already a concrete string
//                   literal; no solver round-trip needed.
//   synthesised   — Z3 returned a model that satisfies path ∧
//                   exploit constraint.
//   infeasible    — path ∧ exploit is UNSAT. Flow is real but
//                   the exploit shape is blocked.
//   unsolvable    — no exploit shape registered for the sink
//                   kind, or solver returned unknown.
//   no-constraint — flow has neither a pathFormula nor a
//                   known exploit builder; nothing to solve.
async function synthesisePocs(trace, timeoutMs) {
  if (!trace || !trace.taintFlows || trace.taintFlows.length === 0) {
    return;
  }
  for (const flow of trace.taintFlows) {
    // A bad formula on one flow shouldn't take down witness
    // generation for the other flows on the same trace. Each
    // flow's failure is recorded as an `unsolvable` verdict
    // with the error message in the note so the UI can show it.
    try {
      flow.poc = await synthesisePocForFlow(flow, timeoutMs);
    } catch (err) {
      flow.poc = {
        verdict: 'unsolvable',
        payload: null,
        witness: null,
        note: 'synthesis threw: ' + (err && err.message),
      };
    }
  }
}

async function synthesisePocForFlow(flow, timeoutMs) {
  const val = flow.valueFormula;

  // Trivial case: the value is already a concrete literal in
  // the source. Report the literal as the payload without
  // touching Z3.
  if (val && val.value && typeof val.value.val === 'string') {
    return {
      verdict: 'trivial',
      payload: val.value.val,
      witness: { __const__: val.value.val },
      note: null,
    };
  }

  const sinkKind = flow.sink && flow.sink.kind;
  const builder = EXPLOIT_CONSTRAINTS[sinkKind];

  let formula = flow.pathFormula || null;
  let exploited = false;
  if (builder && val) {
    const exploitC = builder(val);
    if (exploitC) {
      formula = formula ? SMT.mkAnd(formula, exploitC) : exploitC;
      exploited = true;
    }
  }

  if (!formula) {
    return {
      verdict: 'no-constraint',
      payload: null,
      witness: null,
      note: 'no pathFormula and no valueFormula to constrain',
    };
  }

  const witness = await getModel(formula, timeoutMs);
  if (witness === null) {
    return {
      verdict: exploited ? 'infeasible' : 'unsolvable',
      payload: null,
      witness: null,
      note: exploited
        ? 'path condition + exploit constraint is UNSAT'
        : 'Z3 returned unknown (timeout or unhandled theory)',
    };
  }

  return {
    verdict: exploited ? 'synthesised' : 'no-constraint',
    payload: extractPayload(witness),
    witness,
    note: null,
  };
}

module.exports = {
  _initZ3,
  checkPathSat,
  getModel,
  refuteTrace,
  synthesisePocs,
  resetCache,
};
