// html-templates.js — structured HTML-template extraction
// from JS accumulator patterns (Wave 12d / D11.1).
//
// Observation: a lot of real-world code builds HTML by
// concatenating strings at runtime — `var H = '<nav>'; for
// (...) { H += '<a>'+item+'</a>'; } ...; el.innerHTML = H;`
// is the canonical shape. The value that reaches the
// innerHTML sink is not a compile-time constant, but the
// STRUCTURE of the HTML being built IS static: the engine
// can recognise the accumulator pattern and record what the
// final DOM tree will look like.
//
// This module is the engine's template-extraction pass. For
// each concrete assignment site on the trace, it walks the
// enclosing JS AST looking for one of a set of known
// accumulator patterns and returns an `HtmlTemplate` record
// describing what the assignment builds. Consumers read the
// template off the trace's innerHtmlAssignment records and
// emit code without re-parsing the source themselves.
//
// This is the knowledge half of D11.1. Emitting code from
// the template is consumer work (consumers/dom-convert.js).
//
// HtmlTemplate shape:
//
//   type HtmlTemplate =
//     | { kind: 'concrete'; html: string; nodes: HtmlNode[] }
//         -- fully static; nodes is the parsed tree.
//     | { kind: 'loop';
//         receiver: { start, end };    -- the `elem.innerHTML` LHS
//         outer: null | {               -- optional wrapper element
//           tag: string;
//           attrList: HtmlAttr[];       -- static attributes from the open literal
//         };
//         loopShape: {
//           initSrc: string;            -- verbatim init clause
//           testSrc: string;            -- verbatim test clause
//           updateSrc: string;          -- verbatim update clause
//           bodyStart: number;          -- body block start
//           bodyEnd: number;            -- body block end
//         };
//         child: {                      -- per-iteration child element
//           tag: string;
//           attrs: HtmlAttrTemplate[];
//           textExpr: { start, end } | null;  -- source range of the text expression
//         };
//         rangeStart: number;           -- source range to replace
//         rangeEnd: number;
//       }
//     | { kind: 'branch';
//         // Conditional HTML assignment:
//         //
//         //   var H; if (cond) H = '<a>'; else H = '<b>'; elem.innerHTML = H;
//         //   var H = cond ? '<a>' : '<b>'; elem.innerHTML = H;
//         //
//         // emitFromTemplate emits `receiver.replaceChildren()`
//         // followed by `if (cond) { consequent } else
//         // { alternate }` where each branch recursively
//         // emits its own HtmlTemplate.
//         receiver: { start, end };
//         testExpr: { start, end };     -- source range of the if test
//         consequent: HtmlTemplate;      -- recursive template for the if branch
//         alternate: HtmlTemplate;       -- recursive template for the else branch
//         rangeStart: number;            -- full source range to replace
//         rangeEnd: number;
//       }
//     | { kind: 'switch';
//         // Switch-built HTML assignment:
//         //
//         //   var H;
//         //   switch (x) {
//         //     case 'a': H = '<a>'; break;
//         //     case 'b': H = '<b>'; break;
//         //     default:  H = '<c>';
//         //   }
//         //   elem.innerHTML = H;
//         //
//         // Each case branch must contain a single
//         // `H = <string literal>;` assignment (optionally
//         // followed by a `break`). Fall-through between
//         // cases isn't supported yet.
//         receiver: { start, end };
//         discriminant: { start, end }; -- the switch value
//         cases: Array<{
//           testExpr: { start, end } | null;  -- null for `default`
//           template: HtmlTemplate;
//         }>;
//         rangeStart: number;
//         rangeEnd: number;
//       }
//     | { kind: 'opaque'; reason: string };
//
//   type HtmlAttrTemplate = {
//     name: string;
//     parts: Array<
//       | { kind: 'literal'; value: string }
//       | { kind: 'expr'; start: number; end: number }
//     >;
//   };
//
// `start` / `end` are absolute source positions into the JS
// source. Consumers slice the source at those positions to
// get the exact expression text to re-emit.
//
// Each file's AST is cached on ctx so the detector doesn't
// re-parse the source for every innerHtmlAssignment.

'use strict';

const html = require('./html.js');

// --- AST source resolution ---
//
// The template extractor uses acorn directly (not the
// engine's parse.js) because it needs exact byte-offset
// positions on every AST node for source-range rewrites.
// The engine's parse.js tokenizes via acorn but builds its
// own AST shape with slightly different position semantics;
// the template extractor needs a raw acorn Program so
// `node.start` / `node.end` correspond exactly to the
// source bytes.
let _acorn = null;
function getAcorn() {
  if (_acorn) return _acorn;
  if (typeof globalThis !== 'undefined' && globalThis.acorn &&
      typeof globalThis.acorn.parse === 'function') {
    _acorn = globalThis.acorn;
    return _acorn;
  }
  const path = require('path');
  const vendoredPath = path.join(__dirname, '..', 'vendor', 'acorn.js');
  _acorn = require(vendoredPath);
  return _acorn;
}
function parseAst(source) {
  const acorn = getAcorn();
  return acorn.parse(source, {
    ecmaVersion: 'latest',
    locations: true,
    sourceType: 'script',
  });
}

// extractTemplate(jsSource, assignStmtPos, astCache?) → HtmlTemplate | null
//
// The main entry point. `assignStmtPos` is the absolute
// source position of the innerHTML assignment statement
// (matching the `location.pos` the engine records on the
// innerHtmlAssignment record). `astCache` is an optional
// object that caches the parsed AST for the source so
// multiple calls on the same file don't reparse.
//
// Returns an HtmlTemplate describing the shape, or null
// when the assignment isn't found in the source (e.g. the
// consumer passed in a position that doesn't correspond to
// a known site). An `{ kind: 'opaque', reason }` template
// is returned for recognised-but-unmatchable shapes so the
// consumer knows the site exists but the engine can't tell
// what it builds.
function extractTemplate(jsSource, assignStmtPos, filename, astCache) {
  const ast = getAst(jsSource, filename, astCache);
  if (!ast) return null;
  const stmts = ast.body;
  let assignIdx = -1;
  for (let i = 0; i < stmts.length; i++) {
    if (stmts[i].start <= assignStmtPos && stmts[i].end > assignStmtPos) {
      assignIdx = i;
      break;
    }
  }
  if (assignIdx < 0) return null;
  const assignStmt = stmts[assignIdx];
  if (assignStmt.type !== 'ExpressionStatement') return null;
  const expr = assignStmt.expression;
  if (!expr || expr.type !== 'AssignmentExpression') return null;
  if (expr.operator !== '=' && expr.operator !== '+=') return null;
  const lhs = expr.left;
  const rhs = expr.right;
  if (!lhs || lhs.type !== 'MemberExpression') return null;
  if (lhs.computed || !lhs.property || lhs.property.type !== 'Identifier') return null;
  if (lhs.property.name !== 'innerHTML' && lhs.property.name !== 'outerHTML') return null;

  // `el.innerHTML += <rhs>` — append-shaped assignment. The
  // semantic difference from `=` is that there is no
  // replaceChildren(); the new nodes are appended to the
  // receiver. The template extractor produces an `append`
  // template describing the new nodes, and the consumer
  // emits appendChild calls directly on the receiver.
  if (expr.operator === '+=') {
    return extractAppend(jsSource, stmts, assignStmt, assignIdx,
      lhs.object, rhs, '+=');
  }

  // The RHS must be a plain Identifier referencing an
  // accumulator variable or a string concatenation / literal.
  if (rhs && rhs.type === 'Identifier') {
    return extractFromAccumulator(jsSource, stmts, assignIdx, rhs.name, lhs.object);
  }

  // Right-hand side is a literal string. Parse it as HTML.
  // Template literals with no expressions fold to their
  // cooked string and take the same path.
  if (rhs && rhs.type === 'Literal' && typeof rhs.value === 'string') {
    return {
      kind: 'concrete',
      html: rhs.value,
      nodes: html.parse(rhs.value),
    };
  }
  if (rhs && rhs.type === 'TemplateLiteral' &&
      rhs.expressions.length === 0) {
    const cooked = rhs.quasis.map(q => q.value.cooked).join('');
    return {
      kind: 'concrete',
      html: cooked,
      nodes: html.parse(cooked),
    };
  }

  // Non-literal RHS: a concat chain (BinaryExpression of `+`)
  // or a template literal with ${…} interpolations. Both
  // flatten to the same fragment list via flattenConcat and
  // are recognised by parseLoopBodyFragments. The resulting
  // template is an `append`-shape with operator '=' so the
  // consumer prepends a replaceChildren() call before the
  // new nodes.
  if (rhs && (
      (rhs.type === 'BinaryExpression' && rhs.operator === '+') ||
      rhs.type === 'TemplateLiteral')) {
    const t = extractAppend(jsSource, stmts, assignStmt, assignIdx,
      lhs.object, rhs, '=');
    if (t && t.kind !== 'opaque') return t;
  }

  return { kind: 'opaque', reason: 'unrecognised rhs shape' };
}

// extractAppend — build an `append` template for an
// innerHTML assignment whose RHS is a string-shaped
// expression. The `operator` argument distinguishes `=`
// (prepend replaceChildren) from `+=` (pure append); the
// consumer reads `tmpl.operator` and emits accordingly.
//
// Accepted RHS shapes (after flattenConcat normalises them):
//
//   1. Literal string / single-quasi TemplateLiteral —
//      parse via html.parse; the template carries the
//      parsed node list.
//
//   2. Concat chain (BinaryExpression of `+`) OR
//      TemplateLiteral with ${…} expressions — flatten via
//      flattenConcat and match the single-child shape from
//      parseLoopBodyFragments. The template carries the
//      parsed child descriptor so the consumer emits one
//      appendChild + one textNode slot per iteration.
//
// Anything else falls to opaque so the consumer leaves the
// site alone.
//
// HtmlTemplate shape for append:
//   { kind: 'append';
//     operator: '=' | '+=';
//     receiver: { start, end };
//     nodes: HtmlNode[] | null;         -- literal rhs
//     child: ChildShape | null;          -- concat/tmpl rhs
//     rangeStart, rangeEnd }
function extractAppend(jsSource, stmts, assignStmt, assignIdx,
                       receiverNode, rhs, operator) {
  if (rhs && rhs.type === 'Literal' && typeof rhs.value === 'string') {
    return {
      kind: 'append',
      operator,
      receiver: { start: receiverNode.start, end: receiverNode.end },
      nodes: html.parse(rhs.value),
      child: null,
      rangeStart: assignStmt.start,
      rangeEnd: assignStmt.end,
    };
  }
  if (rhs && rhs.type === 'TemplateLiteral' &&
      rhs.expressions.length === 0) {
    const cooked = rhs.quasis.map(q => q.value.cooked).join('');
    return {
      kind: 'append',
      operator,
      receiver: { start: receiverNode.start, end: receiverNode.end },
      nodes: html.parse(cooked),
      child: null,
      rangeStart: assignStmt.start,
      rangeEnd: assignStmt.end,
    };
  }
  const frags = flattenConcat(rhs);
  if (frags) {
    const parsed = parseLoopBodyFragments(frags);
    if (parsed) {
      return {
        kind: 'append',
        operator,
        receiver: { start: receiverNode.start, end: receiverNode.end },
        nodes: null,
        child: {
          tag: parsed.childTag,
          attrs: parsed.childAttrs,
          textExpr: parsed.textExpr
            ? { start: parsed.textExpr.start, end: parsed.textExpr.end }
            : null,
        },
        rangeStart: assignStmt.start,
        rangeEnd: assignStmt.end,
      };
    }
  }
  return { kind: 'opaque', reason: 'append rhs not recognised' };
}

function getAst(jsSource, filename, astCache) {
  if (astCache && astCache.ast) return astCache.ast;
  const ast = parseAst(jsSource);
  if (astCache) astCache.ast = ast;
  return ast;
}

// detectBranchAccumulator — recognise the if/else or
// conditional-expression shapes that write `varName`. Returns
// a `branch` template or null.
//
// Supported:
//
//   1. `if (cond) { X = <lit>; } else { X = <lit>; }` where
//      both branches have exactly one assignment to X and
//      each literal is parseable HTML.
//
//   2. `if (cond) X = <lit>; else X = <lit>;` (no braces).
//
//   3. `var X = cond ? <lit> : <lit>;` (ternary in a var
//      declaration).
//
//   4. Nested: each consequent / alternate template may
//      itself be a `branch` or `concrete` template, built
//      recursively.
function detectBranchAccumulator(jsSource, stmts, assignIdx, varName, receiverNode) {
  // Case 3: ternary in a var decl. Walk backward for the
  // innermost `var X = cond ? a : b` declaration.
  for (let i = assignIdx - 1; i >= 0; i--) {
    const s = stmts[i];
    if (s.type !== 'VariableDeclaration') continue;
    for (const d of s.declarations) {
      if (!d.id || d.id.type !== 'Identifier' || d.id.name !== varName) continue;
      if (!d.init || d.init.type !== 'ConditionalExpression') break;
      const c = d.init;
      if (c.consequent.type !== 'Literal' || typeof c.consequent.value !== 'string') break;
      if (c.alternate.type !== 'Literal' || typeof c.alternate.value !== 'string') break;
      return {
        kind: 'branch',
        receiver: { start: receiverNode.start, end: receiverNode.end },
        testExpr: { start: c.test.start, end: c.test.end },
        consequent: concreteTemplate(c.consequent.value),
        alternate:  concreteTemplate(c.alternate.value),
        rangeStart: s.start,
        rangeEnd: stmts[assignIdx].end,
      };
    }
    // Stop at the first var decl of X we find (the engine
    // treats the closest one as the controlling init).
    break;
  }

  // Cases 1+2: an IfStatement immediately before the
  // assignment whose both branches write to X.
  if (assignIdx - 1 < 0) return null;
  const ifStmt = stmts[assignIdx - 1];
  if (!ifStmt || ifStmt.type !== 'IfStatement') return null;
  if (!ifStmt.test || !ifStmt.consequent || !ifStmt.alternate) return null;
  const conseqWrite = getSingleStringWrite(ifStmt.consequent, varName);
  const altWrite    = getSingleStringWrite(ifStmt.alternate, varName);
  if (!conseqWrite || !altWrite) return null;

  // Look one statement further back for an optional
  // `var X` or `var X = ...` declaration. If present, the
  // replacement range starts at that declaration; otherwise
  // at the IfStatement.
  let rangeStart = ifStmt.start;
  for (let i = assignIdx - 2; i >= 0; i--) {
    const s = stmts[i];
    if (s.type !== 'VariableDeclaration') break;
    let matches = false;
    for (const d of s.declarations) {
      if (d.id && d.id.type === 'Identifier' && d.id.name === varName) {
        matches = true;
        break;
      }
    }
    if (!matches) break;
    rangeStart = s.start;
    break;
  }

  return {
    kind: 'branch',
    receiver: { start: receiverNode.start, end: receiverNode.end },
    testExpr: { start: ifStmt.test.start, end: ifStmt.test.end },
    consequent: concreteTemplate(conseqWrite),
    alternate:  concreteTemplate(altWrite),
    rangeStart,
    rangeEnd: stmts[assignIdx].end,
  };
}

// detectSwitchAccumulator — recognise the shape
//
//   var H;
//   switch (disc) {
//     case lit1: H = '<a>'; break;
//     case lit2: H = '<b>'; break;
//     default:   H = '<c>';
//   }
//   elem.innerHTML = H;
//
// Each case's consequent statements must be exactly
// `H = <string literal>;` optionally followed by `break;`.
// Multi-statement cases, fall-through, and non-literal
// writes fall through to null.
function detectSwitchAccumulator(jsSource, stmts, assignIdx, varName, receiverNode) {
  if (assignIdx - 1 < 0) return null;
  const swStmt = stmts[assignIdx - 1];
  if (!swStmt || swStmt.type !== 'SwitchStatement') return null;
  if (!Array.isArray(swStmt.cases) || swStmt.cases.length === 0) return null;

  const cases = [];
  for (const c of swStmt.cases) {
    // Each case has `test` (null for default) and `consequent`
    // (an array of statements). We accept:
    //   [ExpressionStatement(H = '<lit>')]
    //   [ExpressionStatement(H = '<lit>'), BreakStatement]
    const stmtsInCase = c.consequent || [];
    if (stmtsInCase.length < 1 || stmtsInCase.length > 2) return null;
    const write = getSingleStringWrite(
      { type: 'BlockStatement', body: [stmtsInCase[0]] },
      varName);
    if (write == null) return null;
    if (stmtsInCase.length === 2 && stmtsInCase[1].type !== 'BreakStatement') return null;
    cases.push({
      testExpr: c.test
        ? { start: c.test.start, end: c.test.end }
        : null,
      template: concreteTemplate(write),
    });
  }

  // Extend the replacement range backward through the
  // optional `var H;` declaration that precedes the switch.
  let rangeStart = swStmt.start;
  for (let i = assignIdx - 2; i >= 0; i--) {
    const s = stmts[i];
    if (s.type !== 'VariableDeclaration') break;
    let matches = false;
    for (const d of s.declarations) {
      if (d.id && d.id.type === 'Identifier' && d.id.name === varName) {
        matches = true;
        break;
      }
    }
    if (!matches) break;
    rangeStart = s.start;
    break;
  }

  return {
    kind: 'switch',
    receiver: { start: receiverNode.start, end: receiverNode.end },
    discriminant: { start: swStmt.discriminant.start, end: swStmt.discriminant.end },
    cases,
    rangeStart,
    rangeEnd: stmts[assignIdx].end,
  };
}

// getSingleStringWrite — look inside an IfStatement branch
// body and return the string literal assigned to `varName`,
// or null when the shape isn't `{ varName = <lit> }` or
// `varName = <lit>`.
function getSingleStringWrite(branchNode, varName) {
  if (!branchNode) return null;
  let stmt = branchNode;
  if (branchNode.type === 'BlockStatement') {
    if (branchNode.body.length !== 1) return null;
    stmt = branchNode.body[0];
  }
  if (!stmt || stmt.type !== 'ExpressionStatement') return null;
  const e = stmt.expression;
  if (!e || e.type !== 'AssignmentExpression' || e.operator !== '=') return null;
  if (!e.left || e.left.type !== 'Identifier' || e.left.name !== varName) return null;
  if (!e.right || e.right.type !== 'Literal' || typeof e.right.value !== 'string') return null;
  return e.right.value;
}

// concreteTemplate — build a `{kind: 'concrete'}` template
// for a literal HTML string. The consumer's emitFromTemplate
// walks the parsed tree to emit DOM calls.
function concreteTemplate(htmlString) {
  return {
    kind: 'concrete',
    html: htmlString,
    nodes: html.parse(htmlString),
  };
}

// extractFromAccumulator — match one of several
// accumulator shapes preceding an innerHTML assignment.
// Ordered by specificity:
//
//   Branch A: if/else accumulator
//
//     var X;          // or `var X = <something>` — overwritten
//     if (cond) X = '<a>'; else X = '<b>';
//     elem.innerHTML = X;
//
//     or the single-statement form:
//
//     var X = cond ? '<a>' : '<b>';
//     elem.innerHTML = X;
//
//     Produces a `{kind: 'branch'}` template.
//
//   Shape A (loop wrapping):
//
//     var X = '<tag>';
//     for (...) { X += <concat>; }
//     X += '</tag>';
//     elem.innerHTML = X;
//
//   Shape B (loop no wrap):
//
//     var X = '';
//     for (...) { X += <concat>; }
//     elem.innerHTML = X;
//
// Returns the first matching template, or `opaque` when
// nothing matches.
function extractFromAccumulator(jsSource, stmts, assignIdx, varName, receiverNode) {
  // Try the branch shape first: immediately before the
  // assignment, we have either an IfStatement whose both
  // branches write to `varName`, or a VariableDeclaration
  // with a ConditionalExpression init.
  const branch = detectBranchAccumulator(jsSource, stmts, assignIdx, varName, receiverNode);
  if (branch) return branch;

  // Switch shape: `switch (x) { case ...: H = '...'; break; ... }`.
  const sw = detectSwitchAccumulator(jsSource, stmts, assignIdx, varName, receiverNode);
  if (sw) return sw;

  let closeStmtIdx = -1;
  let loopStmtIdx = -1;
  let openStmtIdx = -1;

  // Optional close-accum statement immediately before the
  // assignment (shape A wrapping).
  if (assignIdx - 1 >= 0) {
    const prev = stmts[assignIdx - 1];
    if (isAccumAssign(prev, varName)) {
      const lit = literalOfAccumAssign(prev);
      if (typeof lit === 'string' && /<\/[a-z][^>]*>/i.test(lit)) {
        closeStmtIdx = assignIdx - 1;
      }
    }
  }

  // Find the nearest loop statement walking backward from
  // `afterLoopIdx`, skipping over non-loop / non-accum
  // statements. `var i = 0;` style bookkeeping counts as
  // "skippable" — its presence between the var H declaration
  // and the loop is normal for while loops.
  const afterLoopIdx = closeStmtIdx >= 0 ? closeStmtIdx : assignIdx;
  for (let i = afterLoopIdx - 1; i >= 0; i--) {
    const s = stmts[i];
    if (isLoopStatement(s) && s.body && s.body.type === 'BlockStatement') {
      loopStmtIdx = i;
      break;
    }
    // Skippable: plain var decl that doesn't touch the accumulator.
    if (s.type === 'VariableDeclaration') {
      let touchesAccum = false;
      for (const d of s.declarations) {
        if (d.id && d.id.type === 'Identifier' && d.id.name === varName) {
          touchesAccum = true;
          break;
        }
      }
      if (!touchesAccum) continue;   // bookkeeping var, keep looking
    }
    break;
  }
  if (loopStmtIdx < 0) {
    return { kind: 'opaque', reason: 'no loop before innerHTML assignment' };
  }

  // Open-accum statement (the var X = '<…>' declaration).
  for (let i = loopStmtIdx - 1; i >= 0; i--) {
    const s = stmts[i];
    if (s.type === 'VariableDeclaration') {
      let matched = false;
      for (const d of s.declarations) {
        if (d.id && d.id.type === 'Identifier' && d.id.name === varName &&
            d.init && d.init.type === 'Literal' && typeof d.init.value === 'string') {
          openStmtIdx = i;
          matched = true;
          break;
        }
      }
      if (matched) break;
      // Non-matching var decl (e.g. `var i = 0;`) — skip.
      continue;
    }
    break;
  }
  if (openStmtIdx < 0) {
    return { kind: 'opaque', reason: 'no var declaration of accumulator' };
  }

  const openStmt = stmts[openStmtIdx];
  const loopStmt = stmts[loopStmtIdx];
  const closeStmt = closeStmtIdx >= 0 ? stmts[closeStmtIdx] : null;
  const openInit = openStmt.declarations.find(d => d.id.name === varName).init;
  const openLit = openInit.value;
  const closeLit = closeStmt ? literalOfAccumAssign(closeStmt) : null;

  // Resolve outer wrapper: shape A has `<tag>` + `</tag>`,
  // shape B has empty open literal and no close.
  let outer = null;
  if (openLit.length > 0) {
    const openTree = html.parse(openLit);
    let outerElem = null;
    for (const c of openTree.children) {
      if (c.type === 'element') { outerElem = c; break; }
    }
    if (outerElem == null) {
      return { kind: 'opaque', reason: 'open literal has no element' };
    }
    if (closeLit == null) {
      return { kind: 'opaque', reason: 'wrapper open without close' };
    }
    const closeMatch = closeLit.match(/<\/([a-z][a-z0-9]*)/i);
    if (!closeMatch || closeMatch[1].toLowerCase() !== outerElem.tag) {
      return { kind: 'opaque', reason: 'wrapper tag mismatch' };
    }
    outer = {
      tag: outerElem.tag,
      attrList: outerElem.attrList || [],
    };
  } else {
    if (closeLit != null && closeLit.length > 0) {
      return { kind: 'opaque', reason: 'empty open with non-empty close' };
    }
  }

  // Walk the loop body (including any nested blocks /
  // if / else) and collect every accumulator-append
  // statement. Each append's parsed child shape becomes a
  // splice site the consumer replaces with DOM calls. This
  // handles branches-inside-loops uniformly: every
  // `html += '<li>' + ...` statement anywhere inside the
  // loop body contributes one site, regardless of whether
  // it sits in the top of the body or nested inside an
  // IfStatement.
  const accumSites = [];
  collectAccumAppends(loopStmt.body, varName, accumSites);
  if (accumSites.length === 0) {
    return { kind: 'opaque', reason: 'no accum assign in loop body' };
  }
  // Every site must parse into a recognisable child shape.
  // Sites that don't parse fall the whole template over to
  // opaque (partial rewrites would silently drop some
  // iterations).
  for (const site of accumSites) {
    if (!site.child) {
      return { kind: 'opaque', reason: 'loop body append shape unrecognised' };
    }
  }

  return {
    kind: 'loop',
    receiver: { start: receiverNode.start, end: receiverNode.end },
    outer,
    loopShape: {
      loopType: loopStmt.type,
      headerEnd: loopStmt.body.start + 1,   // position past the `{`
      bodyEnd:   loopStmt.body.end - 1,     // position of the closing `}`
      loopStart: loopStmt.start,
      loopEnd: loopStmt.end,
    },
    accumSites,
    rangeStart: openStmt.start,
    rangeEnd: stmts[assignIdx].end,
  };
}

// collectAccumAppends(bodyNode, varName, out)
//
// Recursive walk that finds every `varName += <concat>`
// statement inside a body node, descending into
// BlockStatement and IfStatement alternatives. Each append
// is pushed onto `out` with its source range and its
// parsed child shape (null if the concat didn't match a
// recognisable pattern). The caller checks the null case
// and falls the whole template over to opaque if any site
// didn't parse.
function collectAccumAppends(node, varName, out) {
  if (!node) return;
  if (node.type === 'BlockStatement') {
    for (const s of node.body) collectAccumAppends(s, varName, out);
    return;
  }
  if (node.type === 'IfStatement') {
    collectAccumAppends(node.consequent, varName, out);
    if (node.alternate) collectAccumAppends(node.alternate, varName, out);
    return;
  }
  if (node.type === 'ExpressionStatement' && isAccumAssign(node, varName)) {
    const frags = flattenConcat(node.expression.right);
    const parsed = frags ? parseLoopBodyFragments(frags) : null;
    out.push({
      start: node.start,
      end: node.end,
      child: parsed ? {
        tag: parsed.childTag,
        attrs: parsed.childAttrs,
        textExpr: parsed.textExpr
          ? { start: parsed.textExpr.start, end: parsed.textExpr.end }
          : null,
      } : null,
    });
    return;
  }
  // Other control-flow nodes (loops, switch, try) aren't
  // recursed into — the MVP supports one level of if/else
  // nesting inside a loop body. A deeper pattern falls
  // through to opaque via the empty-site check below.
}

// --- Helpers -----------------------------------------------------------

// isLoopStatement — true for any JS loop node type that
// carries a body block. Used by the accumulator detector to
// handle for / while / do-while / for-in / for-of
// uniformly; each type's loop header is sliced verbatim
// from the source so the emitter doesn't need per-type
// handling.
function isLoopStatement(s) {
  return s && (
    s.type === 'ForStatement' ||
    s.type === 'WhileStatement' ||
    s.type === 'DoWhileStatement' ||
    s.type === 'ForInStatement' ||
    s.type === 'ForOfStatement'
  );
}

function isAccumAssign(stmt, varName) {
  if (!stmt || stmt.type !== 'ExpressionStatement') return false;
  const e = stmt.expression;
  if (!e || e.type !== 'AssignmentExpression') return false;
  if (e.operator !== '+=') return false;
  if (!e.left || e.left.type !== 'Identifier' || e.left.name !== varName) return false;
  return true;
}

function literalOfAccumAssign(stmt) {
  if (!isAccumAssign(stmt, stmt.expression.left.name)) return null;
  const r = stmt.expression.right;
  if (r && r.type === 'Literal' && typeof r.value === 'string') return r.value;
  return null;
}

// Flatten a left-associative chain of `+` expressions OR a
// TemplateLiteral into a uniform list of
// `{ kind: 'lit' | 'expr', value?, start?, end? }` fragments.
//
// Template literals are handled structurally: quasis become
// `lit` fragments (value = the cooked string) and expressions
// become `expr` fragments with the expression's source
// range. This means a RHS like
//   `<li class="${cls}">${text}</li>`
// flattens to the same shape as
//   '<li class="' + cls + '">' + text + '</li>'
// and parseLoopBodyFragments matches both without knowing
// which source form produced them.
//
// Nested template literals inside `${...}` expressions are
// treated as opaque expr fragments (their inner structure
// isn't flattened into the parent chain), which keeps the
// depth-1 shape the rest of the extractor assumes.
function flattenConcat(node) {
  const out = [];
  function walk(n) {
    if (n.type === 'BinaryExpression' && n.operator === '+') {
      walk(n.left);
      walk(n.right);
      return;
    }
    if (n.type === 'Literal' && typeof n.value === 'string') {
      out.push({ kind: 'lit', value: n.value });
      return;
    }
    if (n.type === 'TemplateLiteral') {
      // `quasis` and `expressions` interleave: quasi[0],
      // expr[0], quasi[1], expr[1], ..., quasi[N].
      const quasis = n.quasis || [];
      const exprs = n.expressions || [];
      for (let i = 0; i < quasis.length; i++) {
        const q = quasis[i];
        const cooked = q && q.value ? q.value.cooked : '';
        if (cooked !== '') out.push({ kind: 'lit', value: cooked });
        if (i < exprs.length) {
          const e = exprs[i];
          out.push({ kind: 'expr', start: e.start, end: e.end });
        }
      }
      return;
    }
    out.push({ kind: 'expr', start: n.start, end: n.end });
  }
  walk(node);
  return out;
}

// parseLoopBodyFragments — recognise the
// `<child attr="prefix` + E + `">` + T + `</child>` shape
// from a flattened concat chain. Returns
// `{ childTag, childAttrs, textExpr }` or null.
function parseLoopBodyFragments(rawFrags) {
  // Coalesce adjacent literal fragments so splits like
  // `"\""` + `">"` become a single `">"` literal.
  const frags = [];
  for (const f of rawFrags) {
    if (f.kind === 'lit' && frags.length > 0 && frags[frags.length - 1].kind === 'lit') {
      frags[frags.length - 1] = {
        kind: 'lit',
        value: frags[frags.length - 1].value + f.value,
      };
    } else {
      frags.push(f);
    }
  }
  if (frags.length < 2) return null;
  if (frags[0].kind !== 'lit') return null;
  const openingLit = frags[0].value;
  const childMatch = openingLit.match(/^<([a-z][a-z0-9]*)([^>]*?)(>)?$/i);
  if (!childMatch) return null;
  const childTag = childMatch[1].toLowerCase();
  const attrsStr = childMatch[2];
  const childAttrs = [];
  let textExpr = null;
  let state = 'attrs';
  let i = 1;

  if (childMatch[3] === '>') {
    // Opening literal is complete — `attrsStr` holds all
    // static attributes (possibly empty). Parse them in
    // full, then drop straight into the children state.
    const staticAttrs = parseStaticAttrsFragment(attrsStr);
    for (const a of staticAttrs) childAttrs.push(a);
    state = 'children';
  } else {
    // Parse static attrs from the opening literal's attr portion.
    const staticAttrs = parseStaticAttrsFragment(attrsStr);
    for (const a of staticAttrs) childAttrs.push(a);
    const dangling = attrsStr.match(/\s([a-z][a-z0-9-]*)\s*=\s*"([^"]*)$/i);
    if (dangling) {
      childAttrs.push({
        name: dangling[1].toLowerCase(),
        parts: [{ kind: 'literal', value: dangling[2] }],
        _pending: true,
      });
    }
  }
  while (i < frags.length) {
    const f = frags[i];
    if (state === 'attrs') {
      const pendingAttr = childAttrs[childAttrs.length - 1];
      if (f.kind === 'expr' && pendingAttr && pendingAttr._pending) {
        pendingAttr.parts.push({ kind: 'expr', start: f.start, end: f.end });
        i++;
        continue;
      }
      if (f.kind === 'lit' && pendingAttr && pendingAttr._pending) {
        const closeIdx = f.value.indexOf('"');
        if (closeIdx < 0) return null;
        if (closeIdx > 0) {
          pendingAttr.parts.push({ kind: 'literal', value: f.value.slice(0, closeIdx) });
        }
        delete pendingAttr._pending;
        const after = f.value.slice(closeIdx + 1);
        const gtIdx = after.indexOf('>');
        if (gtIdx < 0) return null;
        const moreAttrs = after.slice(0, gtIdx);
        const rest = after.slice(gtIdx + 1);
        const staticAttrs = parseStaticAttrsFragment(moreAttrs);
        for (const a of staticAttrs) childAttrs.push(a);
        state = 'children';
        if (rest.length > 0) {
          frags[i] = { kind: 'lit', value: rest };
          continue;
        }
        i++;
        continue;
      }
      return null;
    }
    if (state === 'children') {
      if (f.kind === 'expr' && textExpr == null) {
        textExpr = f;
        i++;
        continue;
      }
      if (f.kind === 'lit') {
        const closingRe = new RegExp('</' + childTag + '\\s*>', 'i');
        if (closingRe.test(f.value)) {
          i++;
          if (i < frags.length) return null;
          // Strip the _pending flag before returning.
          for (const a of childAttrs) delete a._pending;
          return { childTag, childAttrs, textExpr };
        }
        return null;
      }
      return null;
    }
    i++;
  }
  return null;
}

function parseStaticAttrsFragment(s) {
  const out = [];
  const re = /\s*([a-z][a-z0-9-]*)\s*=\s*"([^"]*)"/gi;
  let m;
  while ((m = re.exec(s)) !== null) {
    out.push({
      name: m[1].toLowerCase(),
      parts: [{ kind: 'literal', value: m[2] }],
    });
  }
  return out;
}

module.exports = {
  extractTemplate,
};
