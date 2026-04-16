// smt.js — SMT-LIB v2 formula AST primitives.
//
// Pure functions that build SMT-LIB v2 expressions from
// JavaScript-level operations. Every helper returns a Formula
// record:
//
//   {
//     expr:        string  -- SMT-LIB s-expression
//     sorts:       { [symName]: 'Int' | 'String' | 'Bool' }
//                  -- declarations the formula needs
//     isBool:      boolean -- true iff `expr` is already a Bool
//                              s-expression (no toBool coercion
//                              needed when used in conjunctions)
//     value?:      { kind: 'bool'|'int'|'str', val }
//                  -- present iff fully concrete; used for
//                     compile-time const folding without Z3
//     symName?:    string  -- when this formula IS a single sym,
//                              its name (used by sort upgrade)
//     stringResult?: bool   -- true iff the expression denotes a
//                              String-sorted result (needed by
//                              sort upgrade for cross-comparisons)
//     incompatible?: bool   -- true iff the formula can't be
//                              translated to SMT-LIB cleanly
//                              (sort conflict). Such formulas are
//                              conservatively treated as
//                              satisfiable by the solver layer.
//   }
//
// No module-level state: callers manage their own symbol
// table. The engine's ctx carries `nextSymId` and a
// `regToSym` map so each Opaque value with a source label
// gets exactly one SMT symbol per analysis.
//
// All helpers are total: they accept null operands and
// propagate null where appropriate. They never throw.

'use strict';

// --- Helpers -----------------------------------------------------------

// SMT-LIB quoted symbol name. Z3 accepts pipe-quoted symbols
// containing arbitrary characters except `|` itself; we replace
// `|` with `_` to keep the encoding total.
function quoteName(s) {
  return '|' + String(s).replace(/\|/g, '_') + '|';
}

// SMT-LIB string literal. Embedded `"` doubles per the SMT-LIB v2
// spec; everything else passes through.
function quoteString(s) {
  return '"' + String(s).replace(/"/g, '""') + '"';
}

// Merge two sort tables. If both declare the same symbol with
// different sorts, the result is marked __conflict so callers can
// treat the formula as incompatible. Otherwise String wins over
// Int (string theory subsumes integer arithmetic for the
// engine's purposes).
function mergeSorts(a, b) {
  const out = Object.create(null);
  let conflict = false;
  if (a) for (const k in a) out[k] = a[k];
  if (b) for (const k in b) {
    if (out[k] && out[k] !== b[k]) conflict = true;
    out[k] = (out[k] === 'String' || b[k] === 'String') ? 'String' : (out[k] || b[k]);
  }
  if (conflict) Object.defineProperty(out, '__conflict', { value: true });
  return out;
}

// Coerce a Formula to a SMT-LIB Bool s-expression. Already-Bool
// formulas pass through. Concrete primitives fold to literal
// `true` / `false`. Symbols apply JavaScript truthiness rules:
// non-empty / non-zero / non-null is truthy.
function toBool(o) {
  if (!o) return 'true';
  if (o.isBool) return o.expr;
  if (o.value) {
    if (o.value.kind === 'bool') return o.value.val ? 'true' : 'false';
    if (o.value.kind === 'int')  return o.value.val !== 0  ? 'true' : 'false';
    if (o.value.kind === 'str') {
      const s = o.value.val;
      // JavaScript-falsy string forms.
      if (s === '' || s === 'false' || s === 'null' || s === 'undefined' || s === 'NaN' || s === '0') return 'false';
      return 'true';
    }
  }
  if (o.symName) {
    const sort = (o.sorts && o.sorts[o.symName]) || 'Int';
    if (sort === 'String') {
      // A string sym is JS-truthy iff it's not one of the
      // falsy forms above. Z3 string theory handles each
      // (= sym "...") check directly.
      return '(and (not (= ' + o.expr + ' ""))' +
             ' (not (= ' + o.expr + ' "false"))' +
             ' (not (= ' + o.expr + ' "null"))' +
             ' (not (= ' + o.expr + ' "undefined"))' +
             ' (not (= ' + o.expr + ' "NaN"))' +
             ' (not (= ' + o.expr + ' "0")))';
    }
    return '(not (= ' + o.expr + ' 0))';
  }
  return '(not (= ' + o.expr + ' 0))';
}

// True iff `o` denotes a String-sorted value: a string literal,
// a sym already declared as String, or a string-theory composite
// flagged stringResult.
function isStringSide(o) {
  if (!o) return false;
  if (o.value && o.value.kind === 'str') return true;
  if (o.symName && o.sorts && o.sorts[o.symName] === 'String') return true;
  if (o.stringResult) return true;
  return false;
}

// --- Public formula constructors ---------------------------------------

// mkSym(name, sort) — fresh symbolic variable. Sort defaults to
// 'Int'; pass 'String' explicitly when the caller knows the
// underlying value is a string (e.g. a property whose TypeDB
// readType is 'String'). Later operations may still upgrade
// from Int to String via sort propagation if the caller didn't
// hint, but starting at the right sort lets binary-op formula
// construction pick `str.++` over `+` on the very first use,
// without waiting for an external comparison to drive the
// upgrade. Passing 'Bool' is also accepted; it sets isBool so
// the sym can be used directly in conjunctions.
function mkSym(name, sort) {
  const s = sort || 'Int';
  const sorts = Object.create(null);
  sorts[name] = s;
  const out = {
    expr: quoteName(name),
    sorts,
    isBool: s === 'Bool',
    symName: name,
  };
  if (s === 'String') out.stringResult = true;
  return out;
}

// mkConst(value) — constant primitive. Boolean / number / string
// literals are folded to their SMT-LIB literal forms.
function mkConst(value) {
  if (typeof value === 'boolean') {
    return {
      expr: value ? 'true' : 'false',
      sorts: Object.create(null),
      isBool: true,
      value: { kind: 'bool', val: value },
    };
  }
  if (typeof value === 'number') {
    const n = value < 0 ? '(- ' + (-value) + ')' : String(value);
    return {
      expr: n,
      sorts: Object.create(null),
      isBool: false,
      value: { kind: 'int', val: value },
    };
  }
  if (typeof value === 'string') {
    return {
      expr: quoteString(value),
      sorts: Object.create(null),
      isBool: false,
      value: { kind: 'str', val: value },
      stringResult: true,
    };
  }
  // null / undefined / object — encode as the boolean true so the
  // formula stays satisfiable. The caller's lattice-side handling
  // is what ensures soundness; this is a placeholder.
  return {
    expr: 'true',
    sorts: Object.create(null),
    isBool: true,
    value: { kind: 'bool', val: true },
  };
}

// mkNot(o) — boolean negation. Concrete fold short-circuits.
function mkNot(o) {
  if (!o) return null;
  if (o.value && o.value.kind === 'bool') return mkConst(!o.value.val);
  const r = {
    expr: '(not ' + toBool(o) + ')',
    sorts: o.sorts,
    isBool: true,
  };
  if (o.incompatible) r.incompatible = true;
  return r;
}

// mkAnd(a, b) — conjunction. Either operand being null returns
// the other (so callers can chain `mkAnd(a, mkAnd(b, c))` without
// null-checks). Concrete bool operands collapse the conjunction.
function mkAnd(a, b) {
  if (!a) return b;
  if (!b) return a;
  if (a.value && a.value.kind === 'bool') return a.value.val ? b : a;
  if (b.value && b.value.kind === 'bool') return b.value.val ? a : b;
  const sorts = mergeSorts(a.sorts, b.sorts);
  const r = {
    expr: '(and ' + toBool(a) + ' ' + toBool(b) + ')',
    sorts,
    isBool: true,
  };
  if (a.incompatible || b.incompatible || sorts.__conflict) r.incompatible = true;
  return r;
}

// mkOr(a, b) — disjunction. Same null/concrete short-circuits.
function mkOr(a, b) {
  if (!a) return b;
  if (!b) return a;
  if (a.value && a.value.kind === 'bool') return a.value.val ? a : b;
  if (b.value && b.value.kind === 'bool') return b.value.val ? b : a;
  const sorts = mergeSorts(a.sorts, b.sorts);
  const r = {
    expr: '(or ' + toBool(a) + ' ' + toBool(b) + ')',
    sorts,
    isBool: true,
  };
  if (a.incompatible || b.incompatible || sorts.__conflict) r.incompatible = true;
  return r;
}

// mkCmp(op, l, r) — comparison. Folds fully-concrete operands
// using JavaScript semantics, including the `===`/`!==` strict
// type check. Cross-kind concrete compares are handled correctly
// (e.g. `false === "svg"` folds to false without producing a
// sort-mismatched SMT formula).
function mkCmp(op, l, r) {
  if (!l || !r) return null;
  if (l.value && r.value) {
    const lv = l.value.val;
    const rv = r.value.val;
    const sameKind = l.value.kind === r.value.kind;
    let ok;
    switch (op) {
      case '<':   ok = lv < rv; break;
      case '>':   ok = lv > rv; break;
      case '<=':  ok = lv <= rv; break;
      case '>=':  ok = lv >= rv; break;
      case '==':  ok = lv == rv; break;       // eslint-disable-line eqeqeq
      case '===': ok = sameKind && lv === rv; break;
      case '!=':  ok = lv != rv; break;       // eslint-disable-line eqeqeq
      case '!==': ok = !sameKind || lv !== rv; break;
      default:    ok = true;
    }
    return mkConst(ok);
  }
  // Sort upgrade: a sym compared with a String-sorted side
  // becomes String. Without this, equating `|sym|` (Int) against
  // `(str.++ ...)` left the sym Int while the assertion needed
  // String, producing a Z3 sort-mismatch parse error.
  const sorts = mergeSorts(l.sorts, r.sorts);
  const lIsStr = isStringSide(l);
  const rIsStr = isStringSide(r);
  if (l.symName && rIsStr) sorts[l.symName] = 'String';
  if (r.symName && lIsStr) sorts[r.symName] = 'String';
  let smtOp;
  if (op === '<')  smtOp = '<';
  else if (op === '>')  smtOp = '>';
  else if (op === '<=') smtOp = '<=';
  else if (op === '>=') smtOp = '>=';
  else if (op === '==' || op === '===') smtOp = '=';
  else if (op === '!=' || op === '!==') {
    const rne = {
      expr: '(not (= ' + l.expr + ' ' + r.expr + '))',
      sorts,
      isBool: true,
    };
    if (l.incompatible || r.incompatible || sorts.__conflict) rne.incompatible = true;
    return rne;
  } else {
    return null;
  }
  const re = {
    expr: '(' + smtOp + ' ' + l.expr + ' ' + r.expr + ')',
    sorts,
    isBool: true,
  };
  if (l.incompatible || r.incompatible || sorts.__conflict) re.incompatible = true;
  return re;
}

// mkConcat(l, r) — string concatenation via SMT-LIB `str.++`.
// Both folded literal strings collapse to a const; otherwise
// produces a String-sorted composite.
function mkConcat(l, r) {
  if (!l || !r) return null;
  if (l.value && l.value.kind === 'str' && r.value && r.value.kind === 'str') {
    return mkConst(l.value.val + r.value.val);
  }
  const sorts = mergeSorts(l.sorts, r.sorts);
  if (l.symName) sorts[l.symName] = 'String';
  if (r.symName) sorts[r.symName] = 'String';
  const r2 = {
    expr: '(str.++ ' + l.expr + ' ' + r.expr + ')',
    sorts,
    isBool: false,
    stringResult: true,
  };
  if (l.incompatible || r.incompatible || sorts.__conflict) r2.incompatible = true;
  return r2;
}

// mkLength(s) — string length via SMT-LIB `str.len`.
function mkLength(s) {
  if (!s) return null;
  if (s.value && s.value.kind === 'str') return mkConst(s.value.val.length);
  if (!s.symName) return null;
  const sorts = mergeSorts(s.sorts, null);
  sorts[s.symName] = 'String';
  return { expr: '(str.len ' + s.expr + ')', sorts, isBool: false };
}

// mkContains(haystack, needle) — `str.contains` predicate.
function mkContains(haystack, needle) {
  if (!haystack || !needle) return null;
  if (haystack.value && haystack.value.kind === 'str' &&
      needle.value && needle.value.kind === 'str') {
    return mkConst(haystack.value.val.indexOf(needle.value.val) >= 0);
  }
  const sorts = mergeSorts(haystack.sorts, needle.sorts);
  if (haystack.symName) sorts[haystack.symName] = 'String';
  if (needle.symName) sorts[needle.symName] = 'String';
  return {
    expr: '(str.contains ' + haystack.expr + ' ' + needle.expr + ')',
    sorts,
    isBool: true,
  };
}

// mkPrefixOf(prefix, full) — `str.prefixof` predicate.
function mkPrefixOf(prefix, full) {
  if (!prefix || !full) return null;
  if (prefix.value && prefix.value.kind === 'str' &&
      full.value && full.value.kind === 'str') {
    return mkConst(full.value.val.indexOf(prefix.value.val) === 0);
  }
  const sorts = mergeSorts(prefix.sorts, full.sorts);
  if (prefix.symName) sorts[prefix.symName] = 'String';
  if (full.symName) sorts[full.symName] = 'String';
  return {
    expr: '(str.prefixof ' + prefix.expr + ' ' + full.expr + ')',
    sorts,
    isBool: true,
  };
}

// mkSuffixOf(suffix, full) — `str.suffixof` predicate.
function mkSuffixOf(suffix, full) {
  if (!suffix || !full) return null;
  if (suffix.value && suffix.value.kind === 'str' &&
      full.value && full.value.kind === 'str') {
    const sv = suffix.value.val;
    const fv = full.value.val;
    return mkConst(fv.length >= sv.length && fv.slice(fv.length - sv.length) === sv);
  }
  const sorts = mergeSorts(suffix.sorts, full.sorts);
  if (suffix.symName) sorts[suffix.symName] = 'String';
  if (full.symName) sorts[full.symName] = 'String';
  return {
    expr: '(str.suffixof ' + suffix.expr + ' ' + full.expr + ')',
    sorts,
    isBool: true,
  };
}

// mkSubstr(s, start, length) — `str.substr`. JS substring(a,b)
// callers should pre-compute length = b - a.
function mkSubstr(s, start, length) {
  if (!s || !start || !length) return null;
  if (s.value && s.value.kind === 'str' &&
      start.value && start.value.kind === 'int' &&
      length.value && length.value.kind === 'int') {
    const sv = s.value.val;
    const a = start.value.val;
    const len = Math.max(0, length.value.val);
    return mkConst(sv.slice(a, a + len));
  }
  const sorts = mergeSorts(mergeSorts(s.sorts, start.sorts), length.sorts);
  if (s.symName) sorts[s.symName] = 'String';
  return {
    expr: '(str.substr ' + s.expr + ' ' + start.expr + ' ' + length.expr + ')',
    sorts,
    isBool: false,
    stringResult: true,
  };
}

// mkAt(s, i) — `str.at`, single-char substring. JS charAt(i)
// returns '' when i is out of range; Z3 str.at matches.
function mkAt(s, i) {
  if (!s || !i) return null;
  if (s.value && s.value.kind === 'str' &&
      i.value && i.value.kind === 'int') {
    return mkConst(s.value.val.charAt(i.value.val));
  }
  const sorts = mergeSorts(s.sorts, i.sorts);
  if (s.symName) sorts[s.symName] = 'String';
  return {
    expr: '(str.at ' + s.expr + ' ' + i.expr + ')',
    sorts,
    isBool: false,
    stringResult: true,
  };
}

// mkIndexOf(haystack, needle, offset) — `str.indexof`. JS
// indexOf returns -1 when not found; Z3 str.indexof matches.
function mkIndexOf(haystack, needle, offset) {
  if (!haystack || !needle) return null;
  const off = offset || mkConst(0);
  if (haystack.value && haystack.value.kind === 'str' &&
      needle.value && needle.value.kind === 'str' &&
      off.value && off.value.kind === 'int') {
    return mkConst(haystack.value.val.indexOf(needle.value.val, off.value.val));
  }
  const sorts = mergeSorts(mergeSorts(haystack.sorts, needle.sorts), off.sorts);
  if (haystack.symName) sorts[haystack.symName] = 'String';
  if (needle.symName) sorts[needle.symName] = 'String';
  return {
    expr: '(str.indexof ' + haystack.expr + ' ' + needle.expr + ' ' + off.expr + ')',
    sorts,
    isBool: false,
  };
}

// mkReplace(s, from, to) — `str.replace`. Replaces FIRST match
// only, matching JS's String.prototype.replace(string, string).
function mkReplace(s, from, to) {
  if (!s || !from || !to) return null;
  if (s.value && s.value.kind === 'str' &&
      from.value && from.value.kind === 'str' &&
      to.value && to.value.kind === 'str') {
    const sv = s.value.val, fv = from.value.val, tv = to.value.val;
    const i = sv.indexOf(fv);
    return mkConst(i < 0 ? sv : sv.slice(0, i) + tv + sv.slice(i + fv.length));
  }
  const sorts = mergeSorts(mergeSorts(s.sorts, from.sorts), to.sorts);
  if (s.symName) sorts[s.symName] = 'String';
  if (from.symName) sorts[from.symName] = 'String';
  if (to.symName) sorts[to.symName] = 'String';
  return {
    expr: '(str.replace ' + s.expr + ' ' + from.expr + ' ' + to.expr + ')',
    sorts,
    isBool: false,
    stringResult: true,
  };
}

// mkReplaceAll(s, from, to) — `str.replace_all` (Z3 extension).
// Matches JS String.prototype.replaceAll(string, string).
function mkReplaceAll(s, from, to) {
  if (!s || !from || !to) return null;
  if (s.value && s.value.kind === 'str' &&
      from.value && from.value.kind === 'str' &&
      to.value && to.value.kind === 'str') {
    const fv = from.value.val;
    if (fv === '') return mkConst(s.value.val);  // empty pattern: JS throws; treat as identity
    return mkConst(s.value.val.split(fv).join(to.value.val));
  }
  const sorts = mergeSorts(mergeSorts(s.sorts, from.sorts), to.sorts);
  if (s.symName) sorts[s.symName] = 'String';
  if (from.symName) sorts[from.symName] = 'String';
  if (to.symName) sorts[to.symName] = 'String';
  return {
    expr: '(str.replace_all ' + s.expr + ' ' + from.expr + ' ' + to.expr + ')',
    sorts,
    isBool: false,
    stringResult: true,
  };
}

// mkToLower(s) / mkToUpper(s) — Z3 string-theory extensions.
function mkToLower(s) {
  if (!s) return null;
  if (s.value && s.value.kind === 'str') return mkConst(s.value.val.toLowerCase());
  const sorts = mergeSorts(s.sorts, null);
  if (s.symName) sorts[s.symName] = 'String';
  return {
    expr: '(str.to_lower ' + s.expr + ')',
    sorts,
    isBool: false,
    stringResult: true,
  };
}
function mkToUpper(s) {
  if (!s) return null;
  if (s.value && s.value.kind === 'str') return mkConst(s.value.val.toUpperCase());
  const sorts = mergeSorts(s.sorts, null);
  if (s.symName) sorts[s.symName] = 'String';
  return {
    expr: '(str.to_upper ' + s.expr + ')',
    sorts,
    isBool: false,
    stringResult: true,
  };
}

// mkArith(op, l, r) — integer arithmetic. Supports +, -, *, div, mod.
// Operands must both be Int-sorted; sym×String → incompatible.
function mkArith(op, l, r) {
  if (!l || !r) return null;
  if (l.value && l.value.kind === 'int' && r.value && r.value.kind === 'int') {
    switch (op) {
      case '+': return mkConst(l.value.val + r.value.val);
      case '-': return mkConst(l.value.val - r.value.val);
      case '*': return mkConst(l.value.val * r.value.val);
      case '/': if (r.value.val !== 0) return mkConst(Math.trunc(l.value.val / r.value.val)); break;
      case '%': if (r.value.val !== 0) return mkConst(l.value.val % r.value.val); break;
    }
  }
  let incompat = false;
  if (l.symName && l.sorts && l.sorts[l.symName] === 'String') incompat = true;
  if (r.symName && r.sorts && r.sorts[r.symName] === 'String') incompat = true;
  if (l.incompatible || r.incompatible) incompat = true;
  const smtOp = op === '/' ? 'div' : op === '%' ? 'mod' : op;
  const sorts = mergeSorts(l.sorts, r.sorts);
  if (sorts.__conflict) incompat = true;
  const r2 = {
    expr: '(' + smtOp + ' ' + l.expr + ' ' + r.expr + ')',
    sorts,
    isBool: false,
  };
  if (incompat) r2.incompatible = true;
  return r2;
}

// hasSym(o) — true iff the formula references at least one sym.
// Used by the engine to decide whether SMT can possibly help.
function hasSym(o) {
  if (!o || !o.sorts) return false;
  for (const k in o.sorts) {
    if (k === '__conflict') continue;
    return true;
  }
  return false;
}

// emitDeclarations(formula) — return the SMT-LIB declare-const
// lines a solver needs before asserting `formula`. Used by the
// Z3 driver in Phase D.
function emitDeclarations(formula) {
  if (!formula || !formula.sorts) return '';
  const lines = [];
  for (const k in formula.sorts) {
    if (k === '__conflict') continue;
    lines.push('(declare-const ' + quoteName(k) + ' ' + formula.sorts[k] + ')');
  }
  return lines.join('\n');
}

module.exports = {
  mkSym, mkConst, mkNot, mkAnd, mkOr, mkCmp,
  mkConcat, mkLength, mkContains, mkPrefixOf, mkSuffixOf, mkSubstr,
  mkAt, mkIndexOf, mkReplace, mkReplaceAll, mkToLower, mkToUpper,
  mkArith,
  hasSym, emitDeclarations,
  // Internals exposed for tests
  _internals: { quoteName, quoteString, mergeSorts, toBool, isStringSide },
};
