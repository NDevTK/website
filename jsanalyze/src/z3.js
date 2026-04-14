// z3.js — Wave 11 / Phase D: Z3-backed SMT, per D5.
//
// Contract (DESIGN-DECISIONS.md §D5):
//
//   * Z3 is vendored under `jsanalyze/vendor/z3-solver/`
//     (symlinked to `htmldom/vendor/z3-solver/` so both the
//     legacy engine and the new engine share the 33 MB WASM).
//
//   * The SMT layer imports Z3 through a single `_initZ3()`
//     function that works in BOTH Node (`require('z3-solver')`)
//     and the browser (via `globalThis.__htmldomZ3Init`, the
//     pre-registered loader from `htmldom/jsanalyze-z3-browser.js`).
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
//      by `htmldom/jsanalyze-z3-browser.js`. Returns an init
//      function that boots the vendored WASM lazily.
//
//   2. Node `require('z3-solver')` — the test harness and any
//      CommonJS consumer. Node's Module resolution starts at
//      this file and walks up; the vendored symlink at
//      `jsanalyze/vendor/z3-solver/` is used via a direct
//      require of the package's node entry.
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
      // path under jsanalyze/vendor/z3-solver/. This is a
      // symlink to htmldom/vendor/z3-solver/ so both engines
      // share one WASM copy.
      const path = require('path');
      const vendorEntry = path.join(__dirname, '..', 'vendor', 'z3-solver', 'node.js');
      const mod = require(vendorEntry);
      initFn = mod.init;
    } else {
      throw new Error(
        'jsanalyze: Z3 is not available. In the browser, load ' +
        'htmldom/jsanalyze-z3-browser.js before jsanalyze. ' +
        'In Node, ensure jsanalyze/vendor/z3-solver/ is populated ' +
        '(symlinked from htmldom/vendor/z3-solver/).'
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
let _sharedSolver = null;
const _declaredSorts = new Map();   // symName → 'Int' | 'String' | 'Bool'
const _satCache = new Map();        // scriptText → 'sat'|'unsat'|'unknown'

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
  if (_satCache.has(cacheKey)) return _satCache.get(cacheKey);

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
  _satCache.set(cacheKey, verdict);
  return verdict;
}

// --- refuteTrace ----------------------------------------------------------
//
// Post-pass refutation over a completed trace. For each flow
// whose pathFormula is non-trivial, ask checkPathSat; drop
// flows with 'unsat' verdicts into `trace.refutedFlows`.
// Flows already killed during the Layer 5 cascade never reach
// this pass (they weren't emitted in the first place).
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
  return trace;
}

module.exports = {
  _initZ3,
  checkPathSat,
  refuteTrace,
};
