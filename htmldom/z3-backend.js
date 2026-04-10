// Z3 SMT backend for htmldom taint analysis.
//
// This module provides an *async post-hoc verification* pass over the
// findings produced by the home-grown solver. The walker in htmldom.js
// runs synchronously against a fast, approximate solver; each finding
// it emits carries the snapshot of the SMT path-constraint formulas
// that were active when the sink was reached. This module takes those
// internal AST formulas, translates them to Z3 expressions, and asks
// a real SMT solver whether the conjunction is satisfiable.
//
// If Z3 proves the path infeasible, the finding is filtered out. This
// turns the walker's over-approximation into a refined, Z3-verified
// result — exactly the pattern used by industrial taint/verification
// tools (a cheap pass to enumerate candidates, an expensive pass to
// confirm).
//
// Usage (Node):
//
//     const z3 = require('./z3-backend');
//     const verified = await z3.verifyFindings(findings);
//
// The module is a no-op if z3-solver is not installed.

'use strict';

let _z3Promise = null;
function initZ3() {
  if (_z3Promise) return _z3Promise;
  _z3Promise = (async () => {
    let mod;
    try { mod = require('z3-solver'); }
    catch (e) { return null; }
    const api = await mod.init();
    return api;
  })();
  return _z3Promise;
}

// -----------------------------------------------------------------------
// Symbol sort inference
// -----------------------------------------------------------------------
// Each symbol in the internal SMT AST is untyped; its sort is inferred
// from its usage. Walk the formula tree collecting per-symbol usage
// hints and pick the sort that fits all constraints (String if any
// string-theory constraint touches it, otherwise Int).
function inferSorts(formulas) {
  const hint = Object.create(null); // symName -> 'str' | 'int'
  const symNames = new Set();
  const visit = (f) => {
    if (!f || typeof f !== 'object') return;
    if (f.type === 'sym') { symNames.add(f.name); return; }
    if (f.type === 'const') return;
    if (f.type === 'not') { visit(f.arg); return; }
    if (f.type === 'and' || f.type === 'or') { visit(f.left); visit(f.right); return; }
    if (f.type === 'cmp') {
      // Track whether a literal string compares to a symbol.
      if (f.left && f.left.type === 'sym' && f.right && f.right.type === 'const' && typeof f.right.value === 'string') hint[f.left.name] = 'str';
      if (f.right && f.right.type === 'sym' && f.left && f.left.type === 'const' && typeof f.left.value === 'string') hint[f.right.name] = 'str';
      visit(f.left); visit(f.right);
      return;
    }
    if (f.type === 'arith') {
      // length/indexOf mark the left sym as string-typed.
      if (f.op === 'length' && f.left && f.left.type === 'sym') hint[f.left.name] = 'str';
      if (f.op === 'indexOf' && f.left && f.left.type === 'sym') hint[f.left.name] = 'str';
      visit(f.left); visit(f.right);
      return;
    }
    if (f.type === 'strProp') {
      // strProp uses a symId but not a symName directly. Caller must
      // map symId→name via the smtSym cache.
      return;
    }
  };
  for (const f of formulas) visit(f);
  const sorts = Object.create(null);
  for (const n of symNames) sorts[n] = hint[n] || 'int';
  return sorts;
}

// -----------------------------------------------------------------------
// Translate internal SMT AST to Z3 expressions
// -----------------------------------------------------------------------
// Returns { expr, ok }. When ok is false, the formula contains
// constructs that couldn't be translated and the caller should treat
// the whole finding as "reachable" (conservative).
function makeTranslator(Context) {
  const { Int, String: ZStr, Bool } = Context;
  return function translate(f, symConsts, symSorts) {
    if (!f) return { expr: Bool.val(true), ok: true };
    if (f.type === 'const') {
      if (typeof f.value === 'boolean') return { expr: Bool.val(f.value), ok: true };
      if (typeof f.value === 'number') return { expr: Int.val(f.value), ok: true };
      if (typeof f.value === 'string') return { expr: ZStr.val(f.value), ok: true };
      return { expr: Bool.val(true), ok: false };
    }
    if (f.type === 'sym') {
      if (symConsts[f.name]) return { expr: symConsts[f.name], ok: true };
      const sort = symSorts[f.name] || 'int';
      symConsts[f.name] = sort === 'str' ? ZStr.const(f.name) : Int.const(f.name);
      return { expr: symConsts[f.name], ok: true };
    }
    if (f.type === 'not') {
      const a = translate(f.arg, symConsts, symSorts);
      return { expr: a.expr.not(), ok: a.ok };
    }
    if (f.type === 'and') {
      const l = translate(f.left, symConsts, symSorts);
      const r = translate(f.right, symConsts, symSorts);
      return { expr: l.expr.and(r.expr), ok: l.ok && r.ok };
    }
    if (f.type === 'or') {
      const l = translate(f.left, symConsts, symSorts);
      const r = translate(f.right, symConsts, symSorts);
      return { expr: l.expr.or(r.expr), ok: l.ok && r.ok };
    }
    if (f.type === 'cmp') {
      const L = translate(f.left, symConsts, symSorts);
      const R = translate(f.right, symConsts, symSorts);
      if (!L.ok || !R.ok) return { expr: Bool.val(true), ok: false };
      // Mixed-sort comparisons: drop.
      let lx = L.expr, rx = R.expr;
      // Numeric comparison operators require matching sorts.
      try {
        switch (f.op) {
          case '<':   return { expr: lx.lt(rx),    ok: true };
          case '<=':  return { expr: lx.le(rx),    ok: true };
          case '>':   return { expr: lx.gt(rx),    ok: true };
          case '>=':  return { expr: lx.ge(rx),    ok: true };
          case '==':
          case '===': return { expr: lx.eq(rx),    ok: true };
          case '!=':
          case '!==': return { expr: lx.neq(rx),   ok: true };
          default:    return { expr: Bool.val(true), ok: false };
        }
      } catch (e) {
        return { expr: Bool.val(true), ok: false };
      }
    }
    if (f.type === 'arith') {
      // Numeric arithmetic: +, -, *, /, %
      if (f.op === '+' || f.op === '-' || f.op === '*' || f.op === '/' || f.op === '%') {
        const L = translate(f.left, symConsts, symSorts);
        const R = translate(f.right, symConsts, symSorts);
        if (!L.ok || !R.ok) return { expr: Int.val(0), ok: false };
        try {
          switch (f.op) {
            case '+': return { expr: L.expr.add(R.expr), ok: true };
            case '-': return { expr: L.expr.sub(R.expr), ok: true };
            case '*': return { expr: L.expr.mul(R.expr), ok: true };
            case '/': return { expr: L.expr.div(R.expr), ok: true };
            case '%': return { expr: L.expr.mod(R.expr), ok: true };
          }
        } catch (e) {
          return { expr: Int.val(0), ok: false };
        }
      }
      // String theory arith ops — translate to Z3 string operations.
      if (f.op === 'length' && f.left && f.left.type === 'sym') {
        // Mark the sym as string.
        symSorts[f.left.name] = 'str';
        if (!symConsts[f.left.name]) symConsts[f.left.name] = ZStr.const(f.left.name);
        try { return { expr: symConsts[f.left.name].length(), ok: true }; }
        catch (e) { return { expr: Int.val(0), ok: false }; }
      }
      // indexOf is harder; skip.
      return { expr: Int.val(0), ok: false };
    }
    if (f.type === 'strProp') {
      // strProp: { symId, prop, value }. We don't have the symName from
      // symId alone, so we can't translate. Skip (conservative).
      return { expr: Bool.val(true), ok: false };
    }
    return { expr: Bool.val(true), ok: false };
  };
}

// -----------------------------------------------------------------------
// Main verification entry point
// -----------------------------------------------------------------------
// Takes a list of findings (each with .formulas) and returns a new
// filtered list: findings whose path-constraint conjunction is
// demonstrably unsat via Z3 are removed. Findings that Z3 can't decide
// (unknown, translation failure) are kept (conservative).
async function verifyFindings(findings) {
  if (!findings || findings.length === 0) return findings || [];
  const api = await initZ3();
  if (!api) return findings; // z3-solver unavailable → no-op
  const { Context } = api;
  const ctx = Context('htmldom-verify');
  const { Solver } = ctx;
  const translate = makeTranslator(ctx);
  const kept = [];
  for (const finding of findings) {
    const formulas = finding.formulas || [];
    if (formulas.length === 0) { kept.push(finding); continue; }
    const sorts = inferSorts(formulas);
    const solver = new Solver();
    const symConsts = Object.create(null);
    let translationOk = true;
    try {
      for (const f of formulas) {
        const r = translate(f, symConsts, sorts);
        if (!r.ok) { translationOk = false; break; }
        solver.add(r.expr);
      }
    } catch (e) {
      translationOk = false;
    }
    if (!translationOk) { kept.push(finding); continue; }
    let res;
    try { res = await solver.check(); }
    catch (e) { kept.push(finding); continue; }
    if (res === 'unsat') {
      // Path is infeasible — Z3 proved the finding unreachable.
      continue;
    }
    kept.push(finding);
  }
  return kept;
}

// -----------------------------------------------------------------------
// Wrapper: combine a synchronous traceTaint result with async Z3 verify
// -----------------------------------------------------------------------
async function verifyTraceTaintResult(result) {
  if (!result || !result.findings) return result;
  const verified = await verifyFindings(result.findings);
  return Object.assign({}, result, { findings: verified });
}

module.exports = {
  initZ3,
  verifyFindings,
  verifyTraceTaintResult,
  inferSorts,
};
