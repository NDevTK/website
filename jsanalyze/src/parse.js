// parse.js — iterative ECMAScript parser
//
// Uses acorn's standalone tokenizer (which is iterative) for lexing,
// and a hand-written iterative parser on top. The parser never
// recurses: expressions go through a Pratt-style algorithm with
// explicit operand and operator stacks, and statements are driven
// by an explicit work stack of parse-state tasks.
//
// The output is an ESTree-compatible AST so the IR builder doesn't
// need to know the parser changed.

'use strict';

let _acorn = null;

// Resolve acorn. Three environments are supported:
//
//   1. Browser (jsanalyze/browser-bundle.js): acorn is
//      expected to be pre-loaded via a `<script>` tag so
//      `globalThis.acorn` is populated. The vendored
//      `jsanalyze/vendor/acorn.js` is a UMD build whose
//      browser branch assigns `global.acorn = {}`, so a
//      bare `<script src="jsanalyze/vendor/acorn.js">`
//      satisfies this contract.
//
//   2. Node with the vendored copy. The vendored path is
//      resolved via fs.existsSync — the boundary between
//      "vendored" and "installed" is an environment property,
//      not a data-dependent recovery, so we check for the
//      file's existence explicitly rather than catching a
//      require error.
//
//   3. Node with `acorn` installed under node_modules. Fall
//      back to a bare `require('acorn')`.
function getAcorn() {
  if (_acorn) return _acorn;
  // Browser path: pre-loaded as a global.
  if (typeof globalThis !== 'undefined' && globalThis.acorn &&
      typeof globalThis.acorn.tokenizer === 'function') {
    _acorn = globalThis.acorn;
    return _acorn;
  }
  const path = require('path');
  const fs = require('fs');
  const vendoredPath = path.join(__dirname, '..', 'vendor', 'acorn.js');
  if (fs.existsSync(vendoredPath)) {
    _acorn = require(vendoredPath);
    return _acorn;
  }
  _acorn = require('acorn');
  return _acorn;
}

// --- Lexer adapter -----------------------------------------------------
//
// Wraps acorn.tokenizer with a peek/advance stream interface so the
// parser can look ahead by one token. The tokenizer is iterative at
// the character level — it does not recurse into expression trees.

function createLexer(source, filename) {
  const acorn = getAcorn();
  const iter = acorn.tokenizer(source, {
    ecmaVersion: 'latest',
    locations: true,
    allowHashBang: true,
  });
  const state = {
    source,
    filename,
    current: null,    // peeked token
    lookahead: null,  // one-token lookahead buffer (null if not yet fetched)
    prev: null,       // most recently consumed token
  };
  function advance() {
    state.prev = state.current;
    // If we had a lookahead token buffered, promote it; otherwise
    // pull a fresh one from the tokenizer. Tokenizer exceptions
    // propagate: a failure means the source contains invalid
    // lexical structure (unterminated string, bad escape, etc.);
    // parse.js converts this into a visible error at the
    // parseModule boundary where the caller sees it in
    // `trace.warnings`. No silent recovery.
    if (state.lookahead) {
      state.current = state.lookahead;
      state.lookahead = null;
    } else {
      state.current = iter.getToken();
    }
    return state.prev;
  }
  // Return the token AFTER `current` without consuming either.
  // Used by contextual-keyword disambiguation (e.g. deciding
  // whether `let` at statement position is a declaration keyword
  // or a plain identifier reference).
  function peek2() {
    if (!state.lookahead) {
      state.lookahead = iter.getToken();
    }
    return state.lookahead;
  }
  // Prime with the first token.
  advance();
  return {
    state,
    peek()  { return state.current; },
    peek2,
    advance,
    eof()   { return state.current && state.current.type.label === 'eof'; },
    filename,
    source,
  };
}

// --- ESTree node factories --------------------------------------------
//
// Produce plain objects matching the subset of ESTree the IR builder
// consumes. `loc` and `range`-style `start`/`end` are populated so
// downstream location reporting works.

function mkProgram(body, sourceType) {
  const loc = body.length > 0
    ? { start: body[0].loc ? body[0].loc.start : { line: 1, column: 0 },
        end:   body[body.length - 1].loc ? body[body.length - 1].loc.end : { line: 1, column: 0 } }
    : { start: { line: 1, column: 0 }, end: { line: 1, column: 0 } };
  return {
    type: 'Program',
    body,
    sourceType: sourceType || 'script',
    loc,
    start: body.length > 0 ? body[0].start : 0,
    end:   body.length > 0 ? body[body.length - 1].end : 0,
  };
}

function mkLiteral(value, raw, tok) {
  return {
    type: 'Literal',
    value,
    raw,
    loc: tok && tok.loc ? { start: tok.loc.start, end: tok.loc.end } : null,
    start: tok ? tok.start : 0,
    end:   tok ? tok.end   : 0,
  };
}

function mkUnary(operator, argument, prefix, tok) {
  return {
    type: 'UnaryExpression',
    operator,
    prefix: prefix !== false,
    argument,
    loc: tok && tok.loc && argument.loc
      ? { start: tok.loc.start, end: argument.loc.end }
      : null,
    start: tok ? tok.start : 0,
    end:   argument ? argument.end : 0,
  };
}

function mkUpdate(operator, argument, prefix, tok) {
  return {
    type: 'UpdateExpression',
    operator,
    prefix: !!prefix,
    argument,
    loc: tok && tok.loc && argument && argument.loc
      ? { start: prefix ? tok.loc.start : argument.loc.start,
          end:   prefix ? argument.loc.end : tok.loc.end }
      : null,
    start: (prefix ? tok : argument) ? (prefix ? tok.start : argument.start) : 0,
    end:   (prefix ? argument : tok) ? (prefix ? argument.end : tok.end) : 0,
  };
}

function mkMember(object, property, computed) {
  return {
    type: 'MemberExpression',
    object,
    property,
    computed: !!computed,
    optional: false,
    loc: object.loc && property.loc
      ? { start: object.loc.start, end: property.loc.end }
      : null,
    start: object.start || 0,
    end:   property.end || 0,
  };
}

function mkCall(callee, args, endPos) {
  return {
    type: 'CallExpression',
    callee,
    arguments: args,
    optional: false,
    loc: callee.loc
      ? { start: callee.loc.start, end: callee.loc.end }
      : null,
    start: callee.start || 0,
    end:   endPos || callee.end || 0,
  };
}

function mkAssign(operator, left, right) {
  return {
    type: 'AssignmentExpression',
    operator,
    left,
    right,
    loc: left.loc && right.loc
      ? { start: left.loc.start, end: right.loc.end }
      : null,
    start: left.start || 0,
    end:   right.end   || 0,
  };
}

function mkConditional(test, consequent, alternate) {
  return {
    type: 'ConditionalExpression',
    test,
    consequent,
    alternate,
    loc: test.loc && alternate.loc
      ? { start: test.loc.start, end: alternate.loc.end }
      : null,
    start: test.start || 0,
    end:   alternate.end || 0,
  };
}

function mkVariableDeclaration(kind, declarations, startTok) {
  const last = declarations[declarations.length - 1];
  return {
    type: 'VariableDeclaration',
    kind,
    declarations,
    loc: startTok && startTok.loc && last && last.loc
      ? { start: startTok.loc.start, end: last.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   last ? last.end : 0,
  };
}

function mkVariableDeclarator(id, init) {
  return {
    type: 'VariableDeclarator',
    id,
    init,
    loc: id.loc && (init ? init.loc : id.loc)
      ? { start: id.loc.start, end: (init || id).loc.end }
      : null,
    start: id.start || 0,
    end:   (init || id).end || 0,
  };
}

function mkExpressionStatement(expression) {
  return {
    type: 'ExpressionStatement',
    expression,
    loc: expression.loc,
    start: expression.start || 0,
    end:   expression.end   || 0,
  };
}

function mkWhileStatement(test, body, startTok) {
  return {
    type: 'WhileStatement',
    test,
    body,
    loc: startTok && startTok.loc && body && body.loc
      ? { start: startTok.loc.start, end: body.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   body ? body.end : 0,
  };
}

function mkDoWhileStatement(body, test, startTok) {
  return {
    type: 'DoWhileStatement',
    body,
    test,
    loc: startTok && startTok.loc && test && test.loc
      ? { start: startTok.loc.start, end: test.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   test ? test.end : (body ? body.end : 0),
  };
}

function mkForStatement(init, test, update, body, startTok) {
  return {
    type: 'ForStatement',
    init,
    test,
    update,
    body,
    loc: startTok && startTok.loc && body && body.loc
      ? { start: startTok.loc.start, end: body.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   body ? body.end : 0,
  };
}

// `for (LEFT of RIGHT) BODY` / `for (LEFT in RIGHT) BODY`.
// `left` is a VariableDeclaration (the declaring form) or an
// arbitrary assignment target (the bare form).
function mkForInOfStatement(isOf, left, right, body, startTok) {
  return {
    type: isOf ? 'ForOfStatement' : 'ForInStatement',
    left,
    right,
    body,
    await: false,
    loc: startTok && startTok.loc && body && body.loc
      ? { start: startTok.loc.start, end: body.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   body ? body.end : 0,
  };
}

function mkTryStatement(block, handler, finalizer, startTok) {
  return {
    type: 'TryStatement',
    block,
    handler,
    finalizer,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start,
          end: (finalizer || handler || block || {loc:null}).loc
            ? (finalizer || handler || block).loc.end
            : startTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   (finalizer || handler || block)
      ? (finalizer || handler || block).end
      : 0,
  };
}

function mkCatchClause(param, body, startTok) {
  return {
    type: 'CatchClause',
    param,
    body,
    loc: startTok && startTok.loc && body && body.loc
      ? { start: startTok.loc.start, end: body.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   body ? body.end : 0,
  };
}

function mkThrowStatement(argument, startTok) {
  return {
    type: 'ThrowStatement',
    argument,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start, end: argument && argument.loc ? argument.loc.end : startTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   argument ? argument.end : (startTok ? startTok.end : 0),
  };
}

function mkBreakStatement(label, startTok) {
  return {
    type: 'BreakStatement',
    label: label ? mkIdentifier(label, startTok) : null,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start, end: startTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   startTok ? startTok.end : 0,
  };
}

function mkContinueStatement(label, startTok) {
  return {
    type: 'ContinueStatement',
    label: label ? mkIdentifier(label, startTok) : null,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start, end: startTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   startTok ? startTok.end : 0,
  };
}

function mkBlockStatement(body, startTok, endTok) {
  return {
    type: 'BlockStatement',
    body,
    loc: startTok && endTok && startTok.loc && endTok.loc
      ? { start: startTok.loc.start, end: endTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   endTok ? endTok.end : 0,
  };
}

function mkIfStatement(test, consequent, alternate, startTok) {
  const endNode = alternate || consequent;
  return {
    type: 'IfStatement',
    test,
    consequent,
    alternate,
    loc: startTok && startTok.loc && endNode && endNode.loc
      ? { start: startTok.loc.start, end: endNode.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   endNode ? endNode.end : 0,
  };
}

function mkReturnStatement(argument, startTok, endTok) {
  return {
    type: 'ReturnStatement',
    argument,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start, end: (argument || endTok || startTok).loc ? (argument || endTok || startTok).loc.end : startTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   (argument ? argument.end : (endTok ? endTok.end : (startTok ? startTok.end : 0))),
  };
}

function mkEmptyStatement(tok) {
  return {
    type: 'EmptyStatement',
    loc: tok && tok.loc ? { start: tok.loc.start, end: tok.loc.end } : null,
    start: tok ? tok.start : 0,
    end:   tok ? tok.end   : 0,
  };
}

// Unimplemented markers — produced when the parser encounters a
// construct it doesn't yet model. They carry the original token
// label and a source range so the IR builder can emit an Opaque
// instruction with an `unimplemented` assumption at the right
// location. The parser skips forward past the construct so
// analysis of the surrounding code continues.
function mkUnimplementedStatement(kind, startTok, endTok) {
  return {
    type: 'UnimplementedStatement',
    kind,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start, end: endTok && endTok.loc ? endTok.loc.end : startTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   endTok ? endTok.end : (startTok ? startTok.end : 0),
  };
}

function mkUnimplementedExpression(kind, startTok, endTok) {
  return {
    type: 'UnimplementedExpression',
    kind,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start, end: endTok && endTok.loc ? endTok.loc.end : startTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   endTok ? endTok.end : (startTok ? startTok.end : 0),
  };
}

function mkFunctionDeclaration(id, params, body, isAsync, isGenerator, startTok) {
  return {
    type: 'FunctionDeclaration',
    id,
    params,
    body,
    async: !!isAsync,
    generator: !!isGenerator,
    loc: startTok && startTok.loc && body && body.loc
      ? { start: startTok.loc.start, end: body.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   body ? body.end : 0,
  };
}

function mkFunctionExpr(params, body, isArrow, isAsync, startTok) {
  return {
    type: isArrow ? 'ArrowFunctionExpression' : 'FunctionExpression',
    id: null,
    params,
    body,
    async: !!isAsync,
    generator: false,
    expression: isArrow && body.type !== 'BlockStatement',
    loc: startTok && startTok.loc && body.loc
      ? { start: startTok.loc.start, end: body.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   body ? body.end : 0,
  };
}

function mkNew(callee, args, startPos, endPos) {
  return {
    type: 'NewExpression',
    callee,
    arguments: args,
    loc: null,
    start: startPos || 0,
    end:   endPos   || 0,
  };
}

function mkBinary(type, operator, left, right) {
  return {
    type,
    operator,
    left,
    right,
    loc: left.loc && right.loc
      ? { start: left.loc.start, end: right.loc.end }
      : null,
    start: left.start || 0,
    end:   right.end   || 0,
  };
}

function mkIdentifier(name, tok) {
  return {
    type: 'Identifier',
    name,
    loc: tok && tok.loc ? { start: tok.loc.start, end: tok.loc.end } : null,
    start: tok ? tok.start : 0,
    end:   tok ? tok.end   : 0,
  };
}

function mkThisExpression(tok) {
  return {
    type: 'ThisExpression',
    loc: tok && tok.loc ? { start: tok.loc.start, end: tok.loc.end } : null,
    start: tok ? tok.start : 0,
    end:   tok ? tok.end   : 0,
  };
}

// Prefix unary operators consumed before a primary expression.
// These form a loop so `!!x`, `-+x`, `typeof !x` all parse
// iteratively. `new` is handled here too since it's a prefix that
// eventually wraps a call-like suffix.
const UNARY_PREFIX = new Set(['!', '~', '+', '-', 'typeof', 'void', 'delete']);

// Parse a single operand — an optional chain of prefix unary
// operators, a primary, then zero or more postfix suffixes
// (member access, calls, indexing).
//
// Loops are the structure: the outer while peels prefix operators,
// the middle parsePrimary reads the base, the inner while applies
// postfix suffixes. No recursion.
function parseOperand(lexer) {
  // Phase-4 expansion: the "primary" that the Pratt loop consumes
  // is actually: prefixUnary* primary postfix*
  const prefixes = [];
  // Pending `new` operators, outermost first. Each claims the
  // next argument list the postfix loop encounters; any left
  // over at the end are argument-less `new X`.
  const pendingNew = [];
  // Set when the prefix scan consumed `new.target`, which is a
  // primary in its own right rather than an operator.
  let metaPrimary = null;
  while (true) {
    const t = lexer.peek();
    if (!t) break;
    // `new` — NOT a plain prefix operator. Per the grammar,
    // `new MemberExpression Arguments` binds to the member
    // expression up to and INCLUDING the first argument list,
    // and the postfix chain then continues on the result:
    // `new C().v` is `(new C()).v`, not `new (C().v)`.
    //
    // Deferring it to the prefix-unwind loop below got that
    // backwards, so `new C().v` built a NewExpression over the
    // member read — which called C() as a plain function, left
    // `this` unbound, and silently dropped every flow through a
    // freshly constructed object. We instead count pending
    // `new`s here and let the postfix loop claim the first
    // argument list for each.
    if (t.type.label === 'new') {
      lexer.advance();
      // `new.target` — a meta-property, not a construction. It
      // IS the primary, so record it and stop peeling prefixes;
      // the postfix loop then runs on it as usual.
      const afterNew = lexer.peek();
      if (afterNew && afterNew.type.label === '.') {
        lexer.advance();
        const metaTok = lexer.peek();
        if (metaTok && metaTok.type.label === 'name') lexer.advance();
        // Inside a constructor it is the constructor, elsewhere
        // undefined. Neither is a taint source, so an ordinary
        // identifier read is the whole story.
        metaPrimary = mkIdentifier('new.target', t);
        break;
      }
      pendingNew.push({ tok: t });
      continue;
    }
    // `await expr`. The awaited value IS the promise's
    // resolution value, and this engine models an async
    // function's return as that value directly, so `await` is
    // the identity here. Left as a bare identifier it detached
    // its operand from the expression entirely.
    if (t.type.label === 'name' && t.value === 'await' &&
        isYieldOperandStart(lexer)) {
      lexer.advance();
      continue;
    }
    // `yield expr` / `yield* expr` inside a generator. The
    // tokenizer hands `yield` back as a plain name, so without
    // this it read as an identifier and the operand became a
    // separate, disconnected expression — the yielded value's
    // side effects and sinks went unanalysed.
    //
    // We evaluate the operand (that is where the sinks are) and
    // give the yield expression itself an opaque value, because
    // what `yield` evaluates to is whatever the CONSUMER passes
    // back into `next()` — not the operand.
    if (t.type.label === 'name' && t.value === 'yield' && isYieldOperandStart(lexer)) {
      lexer.advance();
      if (lexer.peek() && lexer.peek().type.label === '*') lexer.advance();
      prefixes.push({ kind: 'yield', tok: t });
      continue;
    }
    // The value check below is what recognises operators the
    // tokenizer reports under a generic label (`!` and `~` come
    // through as `prefix`, `-` and `+` as `+/-`, `typeof` as a
    // keyword). It must NOT apply to literals: a string whose
    // CONTENTS happen to spell an operator is not an operator.
    // Without that exclusion `op === '+'`, `case '+':`,
    // `x === 'typeof'` and `f('!')` were all parse errors — and
    // a parse error costs the whole file, which is why most of
    // this repo's own sources were unreadable to the analyzer.
    const isLiteralToken =
      t.type.label === 'string' || t.type.label === 'num' ||
      t.type.label === 'regexp' || t.type.label === 'template';
    if (!isLiteralToken &&
        (UNARY_PREFIX.has(t.type.label) || UNARY_PREFIX.has(t.value))) {
      const op = t.type.label === 'name' ? t.value : (t.value || t.type.label);
      // acorn reports +/- with label "+/-" and value "+" or "-".
      const realOp = (op === '+/-') ? t.value : op;
      prefixes.push({ kind: 'unary', op: realOp, tok: t });
      lexer.advance();
      continue;
    }
    // Prefix ++ / --. acorn tokenizes these with label "++/--"
    // and value "++" or "--".
    if (t.type.label === '++/--') {
      prefixes.push({ kind: 'update_prefix', op: t.value, tok: t });
      lexer.advance();
      continue;
    }
    break;
  }

  let base = metaPrimary || parsePrimary(lexer);

  // Postfix suffix loop: `.prop`, `[expr]`, `(args)`.
  while (true) {
    const t = lexer.peek();
    if (!t) break;
    const label = t.type.label;
    if (label === '.') {
      lexer.advance();
      const nameTok = lexer.peek();
      if (!nameTok || (nameTok.type.label !== 'name' &&
                       nameTok.type.label !== 'privateId' &&
                       !nameTok.type.keyword)) {
        throw parseError(lexer, 'expected property name after `.`');
      }
      lexer.advance();
      // Private access `obj.#field` is lowered as a regular
      // property read on the mangled name `#field`.
      const baseName = nameTok.value || nameTok.type.label;
      const propName = nameTok.type.label === 'privateId' ? '#' + baseName : baseName;
      const propNode = mkIdentifier(propName, nameTok);
      base = mkMember(base, propNode, false);
      continue;
    }
    if (label === '[') {
      lexer.advance();
      const keyExpr = withInAllowed(() => parseExpression(lexer));
      expect(lexer, ']');
      base = mkMember(base, keyExpr, true);
      continue;
    }
    if (label === '(') {
      // Function call — parse comma-separated arguments.
      // Supports spread `f(a, ...b, c)`.
      lexer.advance();
      const args = [];
      if (lexer.peek().type.label !== ')') {
        while (true) {
          if (lexer.peek().type.label === '...') {
            const spreadTok = lexer.advance();
            const inner = parseExpression(lexer);
            args.push(mkSpreadElement(inner, spreadTok));
          } else {
            args.push(withInAllowed(() => parseExpression(lexer)));
          }
          const n = lexer.peek();
          // Trailing comma: `f(a, b,)` is legal and is what
          // every formatter emits on multi-line calls. Looping
          // straight back tried to parse `)` as an argument and
          // failed the whole file.
          if (n.type.label === ',') {
            lexer.advance();
            if (lexer.peek() && lexer.peek().type.label === ')') break;
            continue;
          }
          break;
        }
      }
      const closeTok = lexer.peek();
      expect(lexer, ')');
      // An argument list directly after a pending `new` is that
      // `new`'s arguments — the innermost pending one, so
      // `new new C()()` nests correctly. Everything after the
      // resulting NewExpression is an ordinary postfix chain.
      const claimed = pendingNew.length > 0 ? pendingNew.pop() : null;
      base = claimed
        ? mkNew(base, args, claimed.tok.start, closeTok ? closeTok.end : base.end)
        : mkCall(base, args, closeTok ? closeTok.end : base.end);
      continue;
    }
    // Tagged template: `tag`a${x}b``. Per the spec this CALLS
    // `tag` with the strings array first and one argument per
    // interpolation. Treating it as an unparsed primary lost the
    // call entirely, so a tag that forwards its arguments to a
    // sink — the shape every html`` / sanitize`` helper uses —
    // was invisible.
    if (label === '`') {
      const tpl = parseTemplateLiteral(lexer);
      const strings = mkArrayExpression(
        (tpl.quasis || []).map(q => mkLiteral(
          q.value ? q.value.cooked : '',
          JSON.stringify(q.value ? q.value.cooked : ''), t)),
        t, t);
      base = mkCall(base, [strings].concat(tpl.expressions || []), tpl.end);
      continue;
    }
    // Postfix ++ / --. Binds tighter than any binary operator, so
    // apply immediately to the current `base`.
    if (label === '++/--') {
      base = mkUpdate(t.value, base, false, t);
      lexer.advance();
      continue;
    }
    // Optional chaining: `a?.b`, `a?.[k]`, `a?.(args)`.
    //
    // We desugar by stripping the `?.` and treating the access
    // as a regular member / index / call. This loses the
    // "short-circuit to undefined if base is nullish" precision
    // bit, which is fine for our analyzer: the result is
    // already joined with undefined via the phi at the merge
    // point, and taint flows propagate through both branches
    // of the desugared form. The MemberExpression / CallExpression
    // nodes gain an `optional` flag for consumers that want to
    // distinguish.
    if (label === '?.') {
      lexer.advance();
      const after = lexer.peek();
      if (!after) throw parseError(lexer, 'unexpected end after `?.`');
      if (after.type.label === '[') {
        lexer.advance();
        const keyExpr = withInAllowed(() => parseExpression(lexer));
        expect(lexer, ']');
        base = mkMember(base, keyExpr, true);
        base.optional = true;
        continue;
      }
      if (after.type.label === '(') {
        lexer.advance();
        const args = [];
        if (lexer.peek().type.label !== ')') {
          while (true) {
            if (lexer.peek().type.label === '...') {
              const spreadTok = lexer.advance();
              const inner = parseExpression(lexer);
              args.push(mkSpreadElement(inner, spreadTok));
            } else {
              args.push(withInAllowed(() => parseExpression(lexer)));
            }
            if (lexer.peek().type.label === ',') {
              lexer.advance();
              if (lexer.peek() && lexer.peek().type.label === ')') break;
              continue;
            }
            break;
          }
        }
        const closeTok = lexer.peek();
        expect(lexer, ')');
        base = mkCall(base, args, closeTok ? closeTok.end : base.end);
        base.optional = true;
        continue;
      }
      // `a?.name` — the name is after the `?.`.
      if (after.type.label !== 'name' && !after.type.keyword) {
        throw parseError(lexer, 'expected property name after `?.`');
      }
      lexer.advance();
      const propNode = mkIdentifier(after.value || after.type.label, after);
      base = mkMember(base, propNode, false);
      base.optional = true;
      continue;
    }
    break;
  }

  // Any `new` the postfix loop didn't hand an argument list to
  // is the argument-less form, `new Date`.
  while (pendingNew.length > 0) {
    const p = pendingNew.pop();
    base = mkNew(base, [], p.tok.start, base.end);
  }

  // Apply prefix operators in reverse (innermost first).
  while (prefixes.length > 0) {
    const p = prefixes.pop();
    if (p.kind === 'unary') {
      base = mkUnary(p.op, base, true, p.tok);
    } else if (p.kind === 'update_prefix') {
      base = mkUpdate(p.op, base, true, p.tok);
    } else if (p.kind === 'yield') {
      base = mkYieldExpression(base, p.tok);
    }
  }

  return base;
}

// A primary expression: literal, identifier, `this`, or a
// parenthesised expression.
// toBindingPattern — reinterpret an expression parsed under the
// parenthesised cover grammar as a binding pattern, so
// `({a: x = 1, ...rest}) => …` yields real ObjectPattern /
// AssignmentPattern / RestElement nodes.
//
// Rewrites node types in place, driven by an explicit work stack
// rather than recursion: a pattern can nest arbitrarily deep
// (`([[[[x]]]]) => 0`), and nothing in this parser is allowed to
// grow the JavaScript call stack with the input.
function toBindingPattern(node) {
  const stack = [node];
  while (stack.length > 0) {
    const n = stack.pop();
    if (!n || typeof n !== 'object') continue;
    if (n.type === 'ArrayExpression') {
      n.type = 'ArrayPattern';
      for (const el of n.elements || []) if (el) stack.push(el);
      continue;
    }
    if (n.type === 'ObjectExpression') {
      n.type = 'ObjectPattern';
      for (const pr of n.properties || []) {
        if (!pr) continue;
        if (pr.type === 'SpreadElement') { stack.push(pr); continue; }
        if (pr.value) stack.push(pr.value);
      }
      continue;
    }
    if (n.type === 'SpreadElement') {
      n.type = 'RestElement';
      if (n.argument) stack.push(n.argument);
      continue;
    }
    if (n.type === 'RestElement') {
      if (n.argument) stack.push(n.argument);
      continue;
    }
    // `(a = 1) => …`: an assignment in parameter position is a
    // default value. Only the target side is a pattern.
    if (n.type === 'AssignmentExpression' && n.operator === '=') {
      n.type = 'AssignmentPattern';
      if (n.left) stack.push(n.left);
      continue;
    }
    if (n.type === 'AssignmentPattern') {
      if (n.left) stack.push(n.left);
      continue;
    }
    // Identifier / MemberExpression need no rewriting.
  }
  return node;
}

// parseArrowBody — `=>` has already been consumed. Parses the
// arrow body (block or expression) and returns an
// ArrowFunctionExpression node with the provided params.
// parseObjectExpression — `{ key: value, shorthand, [computed]: v,
// ...spread, method() { }, get foo() { }, set foo(v) { } }`.
//
// Runs on the `{` token. Minimal implementation:
//   * `name` alone → shorthand property (key=value=Identifier)
//   * `name : expr` → plain property
//   * `"str" : expr` / `num : expr` → plain property with literal key
//   * `[expr] : value` → computed key property
//   * `...spread`
//   * `name (params) { body }` → method shorthand (lowered as
//     function expression assigned to the key)
//   * `get name () { }` / `set name (v) { }` → accessor (unimplemented;
//     emits an opaque property value)
function parseObjectExpression(lexer) {
  const startTok = lexer.advance();  // `{`
  const properties = [];
  while (lexer.peek() && lexer.peek().type.label !== '}') {
    const t = lexer.peek();
    // Spread: `...expr`
    if (t.type.label === '...') {
      const spreadTok = lexer.advance();
      const inner = parseExpression(lexer);
      properties.push(mkSpreadElement(inner, spreadTok));
      if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
      continue;
    }
    // Computed key: `[expr] : value`
    if (t.type.label === '[') {
      lexer.advance();
      const keyExpr = withInAllowed(() => parseExpression(lexer));
      expect(lexer, ']');
      // Method shorthand with a computed key: `{ [k]() { … } }`.
      if (lexer.peek() && lexer.peek().type.label === '(') {
        lexer.advance();
        const params = parseParamList(lexer);
        expect(lexer, ')');
        const body = parseStatement(lexer);
        const fnExpr = mkFunctionExpression(null, params, body, false, false, t);
        properties.push(mkProperty(keyExpr, fnExpr, 'init', false, true, true, t));
        if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
        continue;
      }
      expect(lexer, ':');
      const value = withInAllowed(() => parseExpression(lexer));
      properties.push(mkProperty(keyExpr, value, 'init', false, true, false, t));
      if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
      continue;
    }
    // String / number literal key.
    if (t.type.label === 'string' || t.type.label === 'num') {
      lexer.advance();
      const key = mkLiteral(t.value, JSON.stringify(t.value), t);
      // Method shorthand with a literal key: `{ "a/b.ts"() { … } }`.
      // Bundlers emit module maps in exactly this shape, so
      // requiring a `:` here failed the whole bundle.
      if (lexer.peek() && lexer.peek().type.label === '(') {
        lexer.advance();
        const params = parseParamList(lexer);
        expect(lexer, ')');
        const body = parseStatement(lexer);
        const fnExpr = mkFunctionExpression(null, params, body, false, false, t);
        properties.push(mkProperty(key, fnExpr, 'init', false, false, true, t));
        if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
        continue;
      }
      expect(lexer, ':');
      const value = parseExpression(lexer);
      properties.push(mkProperty(key, value, 'init', false, false, false, t));
      if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
      continue;
    }
    // Generator method shorthand: `{ *gen() { … } }`. The `*`
    // was an unrecognised token, which failed the object
    // literal and with it the file.
    if (t.type.label === '*') {
      lexer.advance();
      const nameTok = lexer.peek();
      // `{ *[Symbol.iterator]() { … } }` — computed generator key.
      if (nameTok && nameTok.type.label === '[') {
        lexer.advance();
        const keyExpr = withInAllowed(() => parseExpression(lexer));
        expect(lexer, ']');
        expect(lexer, '(');
        const params = parseParamList(lexer);
        expect(lexer, ')');
        const body = parseStatement(lexer);
        const fnExpr = mkFunctionExpression(null, params, body, false, true, nameTok);
        properties.push(mkProperty(keyExpr, fnExpr, 'init', false, true, true, nameTok));
        if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
        continue;
      }
      if (nameTok && (nameTok.type.label === 'name' || nameTok.type.keyword ||
                      nameTok.type.label === 'string' || nameTok.type.label === 'num')) {
        lexer.advance();
        expect(lexer, '(');
        const params = parseParamList(lexer);
        expect(lexer, ')');
        const body = parseStatement(lexer);
        const fnExpr = mkFunctionExpression(null, params, body, false, true, nameTok);
        properties.push(mkProperty(mkIdentifier(String(nameTok.value), nameTok),
          fnExpr, 'init', false, false, true, nameTok));
        if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
        continue;
      }
      throw parseError(lexer, 'expected a method name after `*` in object literal');
    }
    // `async` method shorthand: `{ async m() { … } }`. Only when
    // a method actually follows — `{ async: 1 }` is a plain key.
    if (t.type.label === 'name' && t.value === 'async') {
      const n2 = lexer.peek2();
      if (n2 && (n2.type.label === 'name' || n2.type.keyword || n2.type.label === '*')) {
        lexer.advance();
        continue;   // re-enter: the method (or `*method`) is next
      }
    }
    // Name key. `get` / `set` act as getter/setter modifiers
    // when followed by another name (the property they cover)
    // and an open paren — `{ get foo() { ... } }` means a
    // getter whose key is `foo`. In other positions (`{ get: 1 }`,
    // `{ get }` shorthand) they're plain property names.
    if (t.type.label === 'name' &&
        (t.value === 'get' || t.value === 'set')) {
      const next = lexer.peek2();
      if (next && next.type.label === 'name') {
        // Peek-past: is there a `(` after the next name? If
        // yes, this is a getter/setter definition.
        // We can't lookahead 3 tokens cheaply; use advance-and-
        // save instead: consume `get`, then look at the next
        // token. If it's a name followed by `(`, commit.
        const kindName = t.value;  // 'get' | 'set'
        lexer.advance();   // consume `get`/`set`
        const nameTok2 = lexer.advance();  // property name
        if (lexer.peek() && lexer.peek().type.label === '(') {
          lexer.advance();
          const params = parseParamList(lexer);
          expect(lexer, ')');
          const body = parseStatement(lexer);
          const mangledName = '__' + kindName + '_' + nameTok2.value + '__';
          const fnExpr = mkFunctionExpression(null, params, body, false, false, nameTok2);
          properties.push(mkProperty(
            mkIdentifier(mangledName, nameTok2), fnExpr, 'init', false, false, true, t));
          if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
          continue;
        }
        // Not a getter/setter — rewind by treating `get` as
        // the property name and nameTok2 as a syntax error.
        // We can't rewind, so fall through: treat nameTok2 as
        // an error.
        throw parseError(lexer, 'unexpected token after `' + kindName + '` in object literal');
      }
    }
    // Property keys may be reserved words: `{ extends: 'X' }`,
    // `{ default: 1 }`, `{ class: 2 }`, `{ in: 3 }` are all
    // legal and common (the engine's own TypeDB uses
    // `extends:`). Accepting only `name` tokens rejected the
    // whole object literal — and with it the whole file.
    if (t.type.label === 'name' || t.type.keyword) {
      lexer.advance();
      // `name: value`
      if (lexer.peek() && lexer.peek().type.label === ':') {
        lexer.advance();
        const value = parseExpression(lexer);
        properties.push(mkProperty(
          mkIdentifier(t.value, t), value, 'init', false, false, false, t));
      } else if (lexer.peek() && lexer.peek().type.label === '(') {
        // Method shorthand: `name(params) { body }`. Desugar to a
        // property holding an anonymous FunctionExpression.
        lexer.advance();
        const params = parseParamList(lexer);
        expect(lexer, ')');
        const body = parseStatement(lexer);
        const fnExpr = mkFunctionExpression(null, params, body, false, false, t);
        properties.push(mkProperty(
          mkIdentifier(t.value, t), fnExpr, 'init', false, false, true, t));
      } else {
        // Shorthand: `{ name }` → key and value are both the name.
        const ident = mkIdentifier(t.value, t);
        properties.push(mkProperty(ident, ident, 'init', true, false, false, t));
      }
      if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
      continue;
    }
    throw parseError(lexer, 'unexpected token in object literal: `' + t.type.label + '`');
  }
  const endTok = lexer.peek();
  expect(lexer, '}');
  return mkObjectExpression(properties, startTok, endTok);
}

// parseTemplateLiteral — `` ` template ${ expr } template ` ``.
//
// Lexer state: the `` ` `` token is the CURRENT token. We
// alternate consuming `template` tokens (the literal pieces)
// and `${ ... }` placeholder expressions until we see the
// closing backtick.
//
// We build a TemplateLiteral ESTree node whose `quasis`
// (TemplateElement) and `expressions` are aligned: N+1 quasis
// for N expressions (JS template semantics).
function parseTemplateLiteral(lexer) {
  const openTok = lexer.advance();  // consume leading `
  const quasis = [];
  const expressions = [];
  while (true) {
    const t = lexer.peek();
    if (!t) throw parseError(lexer, 'unterminated template literal');
    if (t.type.label === '`') {
      // Closing backtick. If we never consumed any template
      // piece, push an empty quasi so invariants hold.
      if (quasis.length === 0) {
        quasis.push(mkTemplateElement('', true, t));
      }
      lexer.advance();
      return mkTemplateLiteral(quasis, expressions, openTok);
    }
    if (t.type.label === 'template') {
      lexer.advance();
      quasis.push(mkTemplateElement(t.value || '', false, t));
      continue;
    }
    if (t.type.label === '${') {
      lexer.advance();
      const expr = parseExpression(lexer);
      expressions.push(expr);
      expect(lexer, '}');
      continue;
    }
    throw parseError(lexer, 'unexpected token in template literal: `' + t.type.label + '`');
  }
}

function mkTemplateLiteral(quasis, expressions, startTok) {
  const last = quasis[quasis.length - 1];
  return {
    type: 'TemplateLiteral',
    quasis,
    expressions,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start,
          end: last && last.loc ? last.loc.end : startTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   last ? last.end : 0,
  };
}

function mkTemplateElement(cooked, tail, tok) {
  return {
    type: 'TemplateElement',
    value: { cooked, raw: cooked },
    tail: !!tail,
    loc: tok && tok.loc ? { start: tok.loc.start, end: tok.loc.end } : null,
    start: tok ? tok.start : 0,
    end:   tok ? tok.end : 0,
  };
}

// parseClassBody — parses `{ member* }` where each member is:
//   constructor ( params ) { body }
//   method_name ( params ) { body }
//   static method_name ( params ) { body }
//   get name ( ) { body }            (unimplemented — opaque)
//   set name ( v ) { body }          (unimplemented — opaque)
//   fieldName = expr ;               (field init — unimplemented)
//   #privateName                     (private — unimplemented)
function parseClassBody(lexer) {
  const openTok = lexer.peek();
  expect(lexer, '{');
  const members = [];
  while (lexer.peek() && lexer.peek().type.label !== '}') {
    // Skip stray semicolons (empty members are legal).
    if (lexer.peek().type.label === ';') {
      lexer.advance();
      continue;
    }
    const m = parseClassMember(lexer);
    if (m) members.push(m);
  }
  expect(lexer, '}');
  return mkClassBody(members, openTok);
}

function parseClassMember(lexer) {
  const startTok = lexer.peek();
  let isStatic = false;
  // `static` prefix. Peek past to see if this is actually a
  // member modifier — it must be followed by another valid
  // member starter (a name, privateId, `(`, `[`, or a string
  // literal).
  if (startTok.type.label === 'name' && startTok.value === 'static') {
    const next = lexer.peek2();
    if (next && (next.type.label === 'name' || next.type.label === 'privateId' ||
                 next.type.label === '(' || next.type.label === '[' ||
                 next.type.label === 'string')) {
      lexer.advance();
      isStatic = true;
    }
  }
  // Private member: acorn tokenises `#name` as a single
  // `privateId` token with value = the bare name. We prefix
  // it with `#` and treat it as a normal identifier for all
  // subsequent stages — GetProp / SetProp on `#foo` are
  // indistinguishable from other property accesses at the IR
  // level, which is what we need for taint tracking.
  const t = lexer.peek();
  let privatePrefix = '';
  if (t.type.label === 'privateId') {
    // Leave the token for parseClassMember's name-consumption
    // branch below; the memberName will use the '#' prefix.
    privatePrefix = '#';
  }
  // Getter / setter: `get name(...) { body }`, `set name(v) { body }`.
  // Stored on the instance under a mangled key `__get_<name>__`
  // or `__set_<name>__` so the method body is still walked for
  // taint. (Precise accessor semantics — invoking the getter
  // on every property read — are out of scope.)
  if (!privatePrefix && t.type.label === 'name' &&
      (t.value === 'get' || t.value === 'set')) {
    const next = lexer.peek2();
    if (next && next.type.label === 'name') {
      const accessorKind = t.value;
      lexer.advance();
      const nameTok = lexer.advance();
      expect(lexer, '(');
      const params = parseParamList(lexer);
      expect(lexer, ')');
      const body = parseStatement(lexer);
      const mangledName = '__' + accessorKind + '_' + nameTok.value + '__';
      return mkMethodDefinition(
        mkIdentifier(mangledName, nameTok),
        mkFunctionExpression(null, params, body, false, false, nameTok),
        'method',
        isStatic, nameTok);
    }
  }
  // Method or field (possibly private).
  // Computed member name: `[Symbol.iterator]() { … }`. The key
  // is an expression, so it has no stable name to store the
  // method under; we key it on the source text of the
  // expression, which is enough to keep the body walked.
  if (lexer.peek() && lexer.peek().type.label === '[') {
    const openTok = lexer.advance();
    const keyExpr = parseExpression(lexer);
    expect(lexer, ']');
    expect(lexer, '(');
    const params = parseParamList(lexer);
    expect(lexer, ')');
    const body = parseStatement(lexer);
    const label = '[' + (keyExpr && keyExpr.type === 'Identifier'
      ? keyExpr.name : 'computed') + ']';
    return mkMethodDefinition(
      mkIdentifier(label, openTok),
      mkFunctionExpression(null, params, body, false, false, openTok),
      'method', isStatic, openTok);
  }
  const memberTok = lexer.peek();
  // Reserved words are legal member names — `delete(t) {}`,
  // `new()`, `class` — and d3 ships exactly that. Skipping the
  // token desynchronised the class body and lost every member
  // after it.
  if (memberTok.type.label !== 'name' &&
      memberTok.type.label !== 'privateId' &&
      memberTok.type.label !== 'string' &&
      memberTok.type.label !== 'num' &&
      !memberTok.type.keyword) {
    lexer.advance();
    return null;
  }
  const nameTok = lexer.advance();
  const memberName = privatePrefix + nameTok.value;
  const afterName = lexer.peek();
  // Method: `name ( params ) { body }` (or `#name (...)` for
  // private methods).
  if (afterName && afterName.type.label === '(') {
    lexer.advance();
    const params = parseParamList(lexer);
    expect(lexer, ')');
    const body = parseStatement(lexer);
    return mkMethodDefinition(
      mkIdentifier(memberName, nameTok),
      mkFunctionExpression(null, params, body, false, false, nameTok),
      memberName === 'constructor' ? 'constructor' : 'method',
      isStatic, nameTok);
  }
  // Field: `name = expr ;` or `name ;` (or `#name = expr ;`).
  let init = null;
  if (afterName && afterName.type.label === '=') {
    lexer.advance();
    init = parseExpression(lexer);
  }
  if (lexer.peek() && lexer.peek().type.label === ';') lexer.advance();
  return mkFieldDefinition(
    mkIdentifier(memberName, nameTok),
    init, isStatic, nameTok);
}

function skipBalanced(lexer, open, close) {
  expect(lexer, open);
  let depth = 1;
  while (!lexer.eof() && depth > 0) {
    const t = lexer.advance();
    if (t.type.label === open) depth++;
    else if (t.type.label === close) depth--;
  }
}

function mkClassDeclaration(id, superClass, body, tok) {
  return {
    type: 'ClassDeclaration',
    id,
    superClass,
    body,
    loc: tok && tok.loc && body && body.loc
      ? { start: tok.loc.start, end: body.loc.end }
      : null,
    start: tok ? tok.start : 0,
    end:   body ? body.end : 0,
  };
}

function mkClassBody(members, tok) {
  return {
    type: 'ClassBody',
    body: members,
    loc: tok && tok.loc ? { start: tok.loc.start, end: tok.loc.end } : null,
    start: tok ? tok.start : 0,
    end:   tok ? tok.end : 0,
  };
}

function mkMethodDefinition(key, value, kind, isStatic, tok) {
  return {
    type: 'MethodDefinition',
    key,
    value,                         // FunctionExpression
    kind,                          // 'method' | 'constructor' | 'get' | 'set'
    static: !!isStatic,
    computed: false,
    loc: tok && tok.loc && value && value.loc
      ? { start: tok.loc.start, end: value.loc.end }
      : null,
    start: tok ? tok.start : 0,
    end:   value ? value.end : 0,
  };
}

function mkFieldDefinition(key, value, isStatic, tok) {
  return {
    type: 'PropertyDefinition',
    key,
    value,                         // Expression or null
    static: !!isStatic,
    computed: false,
    loc: tok && tok.loc ? { start: tok.loc.start, end: (value && value.loc ? value.loc.end : tok.loc.end) } : null,
    start: tok ? tok.start : 0,
    end:   value ? value.end : (tok ? tok.end : 0),
  };
}

function mkFunctionExpression(id, params, body, isAsync, isGenerator, tok) {
  return {
    type: 'FunctionExpression',
    id,
    params,
    body,
    async: !!isAsync,
    generator: !!isGenerator,
    loc: tok && tok.loc && body && body.loc
      ? { start: tok.loc.start, end: body.loc.end }
      : null,
    start: tok ? tok.start : 0,
    end:   body ? body.end : 0,
  };
}

function parseArrowBody(lexer, params, startTok) {
  const t = lexer.peek();
  if (t && t.type.label === '{') {
    // Block-body arrow: parse a BlockStatement. We reuse the
    // statement parser's block-body machinery by invoking
    // parseStatement on the `{` token.
    //
    // parseStatement drives its own task loop; it returns a
    // BlockStatement node.
    const block = parseStatement(lexer);
    return mkArrowFunctionExpression(params, block, false, startTok);
  }
  // Expression-body arrow: parse an AssignmentExpression
  // (matches the ES grammar for concise arrow bodies).
  const body = parseExpression(lexer);
  return mkArrowFunctionExpression(params, body, true, startTok);
}

// exprToArrowParams — convert an expression parsed inside
// `(...)` into an arrow-function parameter list. The grammar
// requires each element to be either an Identifier,
// AssignmentPattern (for defaults), RestElement, or a
// destructuring pattern. We support the identifier case
// precisely; other shapes raise an error. Destructuring and
// default-params land in later Wave 5 sub-waves.
//
// The input is a SequenceExpression (for `(a, b)`), a single
// Identifier (for `(a)`), or something else (error).
function exprToArrowParams(expr) {
  if (!expr) return [];
  if (expr.type === 'Identifier') return [expr];
  if (expr.type === 'SequenceExpression') {
    const out = [];
    for (const e of expr.expressions) {
      if (e.type !== 'Identifier') {
        throw new Error('arrow parameter must be an identifier (got ' + e.type + ')');
      }
      out.push(e);
    }
    return out;
  }
  throw new Error('arrow parameter list must be identifiers (got ' + expr.type + ')');
}

function mkSpreadElement(argument, tok) {
  return {
    type: 'SpreadElement',
    argument,
    loc: tok && tok.loc && argument && argument.loc
      ? { start: tok.loc.start, end: argument.loc.end }
      : null,
    start: tok ? tok.start : 0,
    end:   argument ? argument.end : 0,
  };
}

function mkArrayExpression(elements, startTok, endTok) {
  return {
    type: 'ArrayExpression',
    elements,
    loc: startTok && startTok.loc && endTok && endTok.loc
      ? { start: startTok.loc.start, end: endTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   endTok ? endTok.end : 0,
  };
}

function mkObjectExpression(properties, startTok, endTok) {
  return {
    type: 'ObjectExpression',
    properties,
    loc: startTok && startTok.loc && endTok && endTok.loc
      ? { start: startTok.loc.start, end: endTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   endTok ? endTok.end : 0,
  };
}

function mkProperty(key, value, kind, shorthand, computed, method, tok) {
  return {
    type: 'Property',
    key,
    value,
    kind: kind || 'init',
    shorthand: !!shorthand,
    computed: !!computed,
    method: !!method,
    loc: tok && tok.loc && value && value.loc
      ? { start: tok.loc.start, end: value.loc.end }
      : null,
    start: tok ? tok.start : 0,
    end:   value ? value.end : 0,
  };
}

function mkObjectPattern(properties, startTok) {
  const last = properties[properties.length - 1];
  return {
    type: 'ObjectPattern',
    properties,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start,
          end: (last && last.loc ? last.loc.end : startTok.loc.end) }
      : null,
    start: startTok ? startTok.start : 0,
    end:   last ? last.end : (startTok ? startTok.end : 0),
  };
}

function mkObjectPatternProperty(key, value, shorthand, tok) {
  return {
    type: 'Property',
    key,
    value,
    kind: 'init',
    shorthand,
    computed: false,
    method: false,
    loc: tok && tok.loc ? { start: tok.loc.start, end: (value.loc || tok.loc).end } : null,
    start: tok ? tok.start : 0,
    end:   value ? value.end : 0,
  };
}

function mkArrayPattern(elements, startTok) {
  const last = elements[elements.length - 1];
  return {
    type: 'ArrayPattern',
    elements,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start,
          end: (last && last.loc ? last.loc.end : startTok.loc.end) }
      : null,
    start: startTok ? startTok.start : 0,
    end:   last ? last.end : (startTok ? startTok.end : 0),
  };
}

function mkRestElement(argument, tok) {
  return {
    type: 'RestElement',
    argument,
    loc: tok && tok.loc && argument && argument.loc
      ? { start: tok.loc.start, end: argument.loc.end }
      : null,
    start: tok ? tok.start : 0,
    end:   argument ? argument.end : 0,
  };
}

function mkAssignmentPattern(left, right) {
  return {
    type: 'AssignmentPattern',
    left,
    right,
    loc: left && left.loc && right && right.loc
      ? { start: left.loc.start, end: right.loc.end }
      : null,
    start: left ? left.start : 0,
    end:   right ? right.end : 0,
  };
}

// `yield x`. Modelled as an expression that EVALUATES its
// operand (so the operand's reads and sinks are analysed) but
// whose own value is supplied by the generator's consumer.
function mkYieldExpression(argument, tok) {
  return {
    type: 'YieldExpression',
    argument,
    delegate: false,
    loc: tok && tok.loc && argument && argument.loc
      ? { start: tok.loc.start, end: argument.loc.end }
      : null,
    start: tok ? tok.start : 0,
    end:   argument ? argument.end : (tok ? tok.end : 0),
  };
}

// True when `async` here introduces a function rather than
// being an ordinary identifier named `async`.
//
// `async function` is unambiguous. The arrow forms are not:
// `async (1)` is a CALL to a function named `async`, while
// `async (a) => …` is an async arrow, and the two only diverge
// at the `=>` after the closing paren. One token of lookahead
// cannot see that far, so we run a throwaway tokenizer over the
// remaining source and skip balanced parens. Tokenizing (rather
// than scanning characters) is what keeps a `)` inside a string,
// comment or regex from being miscounted.
function isAsyncFunctionStart(lexer) {
  const n = lexer.peek2();
  if (!n) return false;
  if (n.type.label === 'function') return true;
  if (n.type.label !== '(' && n.type.label !== 'name') return false;
  return arrowFollows(lexer.source, n.start);
}

// Scan from `offset` — positioned at either `(` or a parameter
// name — and report whether the parameter list is followed by
// `=>`.
//
// No error handling here on purpose: a lexical error in the
// remaining source is a real error the main tokenizer will hit
// moments later, and swallowing it would turn a broken file
// into a silently mis-parsed one. It propagates to the
// parseModule boundary like any other lexical failure.
function arrowFollows(source, offset) {
  if (typeof source !== 'string') return false;
  const iter = getAcorn().tokenizer(source.slice(offset), {
    ecmaVersion: 'latest', allowHashBang: true,
  });
  let depth = 0;
  let seen = 0;
  // Parameter lists are small. The bound stops a pathological
  // file from turning one lookahead into a whole-file scan.
  const LIMIT = 4096;
  while (seen++ < LIMIT) {
    const tok = iter.getToken();
    const l = tok.type.label;
    if (l === 'eof') return false;
    if (l === '(') { depth++; continue; }
    if (l === ')') {
      depth--;
      if (depth === 0) return iter.getToken().type.label === '=>';
      if (depth < 0) return false;
      continue;
    }
    // Bare single-parameter form: `async x => …`. Exactly one
    // identifier may precede the arrow.
    if (depth === 0) {
      if (l === '=>') return true;
      if (seen === 1 && l === 'name') continue;
      return false;
    }
  }
  return false;
}

// True when the token after `yield` can begin an operand. A
// bare `yield` (`yield;`, `yield)`, `yield}`) has none, and a
// variable actually NAMED `yield` in sloppy-mode code must keep
// working as an identifier.
function isYieldOperandStart(lexer) {
  const n = lexer.peek2();
  if (!n) return false;
  const l = n.type.label;
  if (l === ';' || l === ')' || l === '}' || l === ']' || l === ',' ||
      l === 'eof' || l === ':') return false;
  // An operator following `yield` means `yield` was the operand:
  // `yield + 1` is ambiguous in theory but `yield` as a variable
  // is what sloppy-mode code means by it.
  // `yield.x`, `yield = 1`, `yield++` — `yield` is the operand
  // itself. `yield [a, b]` and `yield (x)` are yields of an
  // array / parenthesised expression, which is what generator
  // code actually writes.
  if (l === '=' || l === '.' || l === '++/--') return false;
  return true;
}

function mkSequenceExpression(expressions) {
  const first = expressions[0];
  const last = expressions[expressions.length - 1];
  return {
    type: 'SequenceExpression',
    expressions,
    loc: first && first.loc && last && last.loc
      ? { start: first.loc.start, end: last.loc.end }
      : null,
    start: first ? first.start : 0,
    end:   last ? last.end : 0,
  };
}

function mkArrowFunctionExpression(params, body, expression, startTok) {
  return {
    type: 'ArrowFunctionExpression',
    params,
    body,
    expression,                    // true iff body is a plain expression (not a block)
    async: false,
    generator: false,
    id: null,                      // arrows are anonymous
    loc: startTok && startTok.loc && body && body.loc
      ? { start: startTok.loc.start, end: body.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   body ? body.end : 0,
  };
}

function parsePrimary(lexer) {
  const t = lexer.peek();
  if (!t) throw parseError(lexer, 'unexpected end of input');
  const label = t.type.label;
  // Numeric / string / regex / template literal (simple parts) /
  // boolean / null / undefined-like.
  if (label === 'num') {
    lexer.advance();
    return mkLiteral(t.value, String(t.value), t);
  }
  if (label === 'string') {
    lexer.advance();
    return mkLiteral(t.value, JSON.stringify(t.value), t);
  }
  if (label === 'regexp') {
    lexer.advance();
    const v = t.value;
    const raw = '/' + (v && v.pattern) + '/' + (v && v.flags || '');
    return mkLiteral(v, raw, t);
  }
  if (label === 'true') {
    lexer.advance();
    return mkLiteral(true, 'true', t);
  }
  if (label === 'false') {
    lexer.advance();
    return mkLiteral(false, 'false', t);
  }
  if (label === 'null') {
    lexer.advance();
    return mkLiteral(null, 'null', t);
  }
  if (label === 'name' && t.value === 'async' && isAsyncFunctionStart(lexer)) {
    // `async function …`, `async (…) => …`, `async x => …`.
    //
    // `async` was consumed as a plain identifier, so
    // `var f = async () => …` parsed as THREE statements
    // (`async;`, `() => …;`, …) and `(async () => {…})()` — the
    // async IIFE, one of the most common shapes in modern web
    // code — was a hard parse error that failed the whole file.
    //
    // The asynchrony itself needs no special handling: `await`
    // is modelled as the identity below, and an async
    // function's return value IS its resolution value.
    lexer.advance();
    const node = parsePrimary(lexer);
    if (node && (node.type === 'FunctionExpression' ||
                 node.type === 'ArrowFunctionExpression')) {
      node.async = true;
    }
    return node;
  }
  if (label === 'name') {
    // Single-identifier arrow-function shortcut: `x => body`.
    // Peek two tokens ahead; if the next non-name token is
    // `=>`, parse as arrow function with one identifier param.
    const next = lexer.peek2();
    if (next && next.type.label === '=>') {
      lexer.advance();                 // consume the name
      lexer.advance();                 // consume `=>`
      const paramIdent = mkIdentifier(t.value, t);
      return parseArrowBody(lexer, [paramIdent], t);
    }
    // Identifier, or contextual keyword handled as identifier.
    lexer.advance();
    if (t.value === 'undefined') {
      // `undefined` is an identifier in JS, but most programs use
      // it as the undefined literal. Keep it as an identifier; the
      // IR builder resolves it against scope first, then falls to
      // GetGlobal.
      return mkIdentifier('undefined', t);
    }
    return mkIdentifier(t.value, t);
  }
  if (label === 'this') {
    lexer.advance();
    return mkThisExpression(t);
  }
  if (label === 'function') {
    // Function expression: `function [name](params) { body }`.
    // Can be anonymous. Used in expression position; behaves
    // like a FunctionDeclaration for IR-lowering purposes but
    // doesn't bind its name in the enclosing scope.
    lexer.advance();
    // `function*` — generator expression. Parsed as an ordinary
    // function so the body is walked; see the statement form.
    if (lexer.peek() && lexer.peek().type.label === '*') lexer.advance();
    let id = null;
    if (lexer.peek() && lexer.peek().type.label === 'name') {
      const idTok = lexer.advance();
      id = mkIdentifier(idTok.value, idTok);
    }
    expect(lexer, '(');
    const params = parseParamList(lexer);
    expect(lexer, ')');
    const body = parseStatement(lexer);
    return mkFunctionExpression(id, params, body, false, false, t);
  }
  if (label === 'super') {
    lexer.advance();
    return { type: 'Super', loc: t.loc ? { start: t.loc.start, end: t.loc.end } : null, start: t.start, end: t.end };
  }
  if (label === '(') {
    // Parenthesised expression OR arrow-function parameter list.
    // Ambiguous until we see the token after the closing `)`:
    //   `(a + b)` → paren expression
    //   `(a, b) => ...` → arrow with two params
    //   `() => ...` → zero-param arrow
    //
    // Strategy: parse a comma-separated list of expressions
    // inside the parens. If the list has exactly one element
    // and the next token is NOT `=>`, return that element as the
    // paren expression. Otherwise (multiple elements or `=>`
    // follows) convert the list into arrow parameters.
    lexer.advance();
    if (lexer.peek() && lexer.peek().type.label === ')') {
      lexer.advance();
      if (lexer.peek() && lexer.peek().type.label === '=>') {
        lexer.advance();
        return parseArrowBody(lexer, [], t);
      }
      throw parseError(lexer, '`()` is not a valid expression');
    }
    // `( … )` is a cover grammar: until we see whether `=>`
    // follows, the contents could be a parenthesised expression
    // OR an arrow parameter list. We parse permissively — rest
    // elements included — and reinterpret afterwards.
    //
    // Requiring every item to be a plain Identifier rejected
    // `({a, b}) => …`, `([x]) => …` and `(a, ...rest) => …`.
    // Destructured and rest parameters are the normal way modern
    // and bundled code writes callbacks.
    const items = [];
    while (true) {
      if (lexer.peek() && lexer.peek().type.label === '...') {
        const restTok = lexer.advance();
        items.push(mkRestElement(parseBindingTarget(lexer), restTok));
      } else {
        items.push(withInAllowed(() => parseExpression(lexer)));
      }
      if (lexer.peek() && lexer.peek().type.label === ',') {
        lexer.advance();
        // Trailing comma before `)`, legal in a parameter list.
        if (lexer.peek() && lexer.peek().type.label === ')') break;
        continue;
      }
      break;
    }
    expect(lexer, ')');
    if (lexer.peek() && lexer.peek().type.label === '=>') {
      lexer.advance();
      return parseArrowBody(lexer, items.map(toBindingPattern), t);
    }
    for (const it of items) {
      if (it.type === 'RestElement') {
        throw parseError(lexer, 'rest element outside a parameter list');
      }
    }
    // Paren-expression. If multiple items, wrap as
    // SequenceExpression (the comma operator).
    if (items.length === 1) return items[0];
    return mkSequenceExpression(items);
  }
  // Array literal: `[a, b, ...rest]`. Elements may include
  // spread elements and holes (produced by two adjacent commas).
  if (label === '[') {
    lexer.advance();
    const elements = [];
    while (lexer.peek() && lexer.peek().type.label !== ']') {
      if (lexer.peek().type.label === ',') {
        elements.push(null);  // hole
        lexer.advance();
        continue;
      }
      if (lexer.peek().type.label === '...') {
        const spreadTok = lexer.advance();
        const inner = parseExpression(lexer);
        elements.push(mkSpreadElement(inner, spreadTok));
      } else {
        elements.push(parseExpression(lexer));
      }
      if (lexer.peek() && lexer.peek().type.label === ',') {
        lexer.advance();
      }
    }
    const endTok = lexer.peek();
    expect(lexer, ']');
    return mkArrayExpression(elements, t, endTok);
  }
  // Object literal: `{ a: 1, b, ...rest, [k]: v }`.
  if (label === '{') {
    return parseObjectExpression(lexer);
  }
  // Template literal: `` `hello ${x} world` ``.
  //
  // Acorn tokenizes as:
  //   `  template("hello ")  ${  <expr tokens>  }  template(" world")  `
  //
  // We desugar to a left-folded chain of string concatenations
  // so the IR builder's existing BinOp('+') transfer handles
  // taint propagation (a string op with any tainted operand
  // keeps the labels). Tagged templates `tag`...`` fall back
  // to opaque because their semantics are tag-specific.
  if (label === '`') {
    return parseTemplateLiteral(lexer);
  }
  // Class expression: `var C = class [Name] [extends P] { … }`.
  // Without this the `class` keyword fell through to the
  // unknown-primary handler, which skipped the balanced `{ … }`
  // — so the member bodies were never parsed, and the
  // assignment silently produced an opaque.
  if (label === 'class') {
    lexer.advance();
    let id = null;
    const nameTok = lexer.peek();
    if (nameTok && nameTok.type.label === 'name') {
      lexer.advance();
      id = mkIdentifier(nameTok.value, nameTok);
    }
    let superClass = null;
    if (lexer.peek() && lexer.peek().type.label === 'extends') {
      lexer.advance();
      superClass = parseExpression(lexer);
    }
    const body = parseClassBody(lexer);
    const node = mkClassDeclaration(id, superClass, body, t);
    node.type = 'ClassExpression';
    return node;
  }
  // Unknown primary. Emit an UnimplementedExpression marker so
  // the IR builder can raise an explicit `unimplemented`
  // assumption at this location. Consume the token so the
  // surrounding parser doesn't loop forever on the same
  // unrecognised input; if it's a balanced delimiter, skip the
  // matched region.
  const startTok = lexer.advance();
  let endTok = startTok;
  if (startTok.type.label === '[' || startTok.type.label === '{') {
    // Skip to matching close.
    const opener = startTok.type.label;
    const closer = opener === '[' ? ']' : '}';
    let depth = 1;
    while (!lexer.eof() && depth > 0) {
      const t2 = lexer.advance();
      endTok = t2;
      if (t2.type.label === opener) depth++;
      else if (t2.type.label === closer) depth--;
    }
  }
  return mkUnimplementedExpression(label, startTok, endTok);
}

function expect(lexer, label) {
  const t = lexer.peek();
  if (!t || t.type.label !== label) {
    throw parseError(lexer, 'expected `' + label + '` but got `' + (t ? t.type.label : 'eof') + '`');
  }
  lexer.advance();
  return t;
}

function parseError(lexer, msg) {
  const t = lexer.peek();
  const prefix = lexer.filename ? lexer.filename + ': ' : '';
  const locStr = t && t.loc
    ? ('(' + t.loc.start.line + ':' + t.loc.start.column + ')')
    : '';
  return new Error(prefix + 'parse error: ' + msg + ' ' + locStr);
}

// --- Parse entry points -----------------------------------------------
//
// parseModule: full source → Program node. The current implementation
// handles the subset covered by docs/IR.md; any construct the parser
// doesn't yet recognise raises a syntax error that the caller
// handles (wrapping in a partial trace).

function parseModule(source, filename, options) {
  const opts = options || {};
  // createLexer() advances once to prime the token stream, so
  // a tokenizer error on the first character surfaces here. Both
  // createLexer and parseTopLevel propagate exceptions upward;
  // the boundary handler in index.js wraps them into a partial
  // trace warning so the consumer always sees what went wrong.
  const lexer = createLexer(source, filename);
  const body = parseTopLevel(lexer);
  const program = mkProgram(body, opts.sourceType || 'script');
  program._jsanalyzeFilename = filename;
  return program;
}

// Top-level: parse statements until EOF. Each statement is parsed
// by a dedicated function; none of them recurse into themselves.
// Block statements and function bodies are handled by explicit
// work stacks in parseStatement.
function parseTopLevel(lexer) {
  const stmts = [];
  while (!lexer.eof()) {
    const stmt = parseStatement(lexer);
    if (stmt) stmts.push(stmt);
    // Skip stray semicolons between statements.
    while (!lexer.eof() && lexer.peek().type.label === ';') lexer.advance();
  }
  return stmts;
}

// --- Operator precedence table ---------------------------------------
//
// Matches ECMAScript's binary operator precedence levels. Higher
// number = binds tighter. Logical operators produce LogicalExpression
// nodes; arithmetic / comparison produce BinaryExpression. The
// parser dispatches on the `nodeType` field to choose between them.
//
// `||` and `??` are not allowed to mix without parens per ES spec,
// but we accept any ordering and let downstream analyses sort it out.

const BINOP_PRECEDENCE = Object.freeze({
  '||':   { prec: 3, nodeType: 'LogicalExpression' },
  '??':   { prec: 3, nodeType: 'LogicalExpression' },
  '&&':   { prec: 4, nodeType: 'LogicalExpression' },
  '|':    { prec: 5, nodeType: 'BinaryExpression' },
  '^':    { prec: 6, nodeType: 'BinaryExpression' },
  '&':    { prec: 7, nodeType: 'BinaryExpression' },
  '==':   { prec: 8, nodeType: 'BinaryExpression' },
  '!=':   { prec: 8, nodeType: 'BinaryExpression' },
  '===':  { prec: 8, nodeType: 'BinaryExpression' },
  '!==':  { prec: 8, nodeType: 'BinaryExpression' },
  '<':    { prec: 9, nodeType: 'BinaryExpression' },
  '<=':   { prec: 9, nodeType: 'BinaryExpression' },
  '>':    { prec: 9, nodeType: 'BinaryExpression' },
  '>=':   { prec: 9, nodeType: 'BinaryExpression' },
  'in':   { prec: 9, nodeType: 'BinaryExpression' },
  'instanceof': { prec: 9, nodeType: 'BinaryExpression' },
  '<<':   { prec: 10, nodeType: 'BinaryExpression' },
  '>>':   { prec: 10, nodeType: 'BinaryExpression' },
  '>>>':  { prec: 10, nodeType: 'BinaryExpression' },
  '+':    { prec: 11, nodeType: 'BinaryExpression' },
  '-':    { prec: 11, nodeType: 'BinaryExpression' },
  '*':    { prec: 12, nodeType: 'BinaryExpression' },
  '/':    { prec: 12, nodeType: 'BinaryExpression' },
  '%':    { prec: 12, nodeType: 'BinaryExpression' },
  '**':   { prec: 13, nodeType: 'BinaryExpression' },  // right-associative
});

// `**` is the only right-associative binary operator.
const RIGHT_ASSOC = new Set(['**']);

// Map acorn token labels to operator strings. acorn exposes most
// operators via the `value` field, but keywords like `in` /
// `instanceof` have distinct labels.
function tokenAsBinOp(t) {
  if (!t) return null;
  const label = t.type.label;
  // `for (c in a)`: inside the init slot `in` is not an operator,
  // it is the loop keyword. Swallowing it here parsed the header
  // as `for (<c in a>` and then demanded a `;`.
  if (label === 'in') return noIn ? null : 'in';
  if (label === 'instanceof') return 'instanceof';
  // Binary operators acorn tags with the symbol itself as the label,
  // but for `+`, `-`, `<`, etc. the label is a precedence tag like
  // `+/-` or `</>`. Fall back to `value` in those cases.
  if (BINOP_PRECEDENCE[label]) return label;
  if (t.value && BINOP_PRECEDENCE[t.value]) return t.value;
  return null;
}

// Assignment operators recognised at the outermost layer of an
// expression. These are right-associative with respect to each
// other, so `a = b = c` parses as `a = (b = c)`.
const ASSIGN_OPS = new Set([
  '=', '+=', '-=', '*=', '/=', '%=', '**=',
  '<<=', '>>=', '>>>=', '&=', '|=', '^=',
  '&&=', '||=', '??=',
]);

// parseExpression — public entry point for expressions. Dispatches
// through parseAssignment → parseConditional → parseBinary →
// parseOperand, each layer iterative. The `assignment stack`
// handles right-associativity of chained assignments without
// recursion.
// parseExpression — AssignmentExpression. Commas are NOT
// consumed here, because in most positions a comma is a
// separator (call arguments, array elements, declarator lists)
// rather than the comma operator.
function parseExpression(lexer) {
  return parseAssignment(lexer);
}

// parseCommaExpression — the grammar's `Expression`: one or more
// assignment expressions joined by the comma OPERATOR. This is
// what belongs inside `if (…)`, `while (…)`, a `for` header's
// slots, and after `return` / `throw`.
//
// Using the assignment-level parser in those positions rejected
// `if (a = f(), a !== X)` and `while (n = next(), n)` — shapes a
// minifier produces from any multi-statement branch, and the
// reason lodash, Vue and Angular could not be read at all.
function parseCommaExpression(lexer) {
  const first = parseAssignment(lexer);
  if (!lexer.peek() || lexer.peek().type.label !== ',') return first;
  const items = [first];
  while (lexer.peek() && lexer.peek().type.label === ',') {
    lexer.advance();
    items.push(parseAssignment(lexer));
  }
  return mkSequenceExpression(items);
}

// The `for` header's init slot forbids the `in` operator, so
// that `for (c in a)` reads as a for-in loop rather than as a
// C-style loop whose init is the relational expression `c in a`.
// The flag is scoped to the init slot and cleared inside any
// bracketing, matching the grammar's [In] parameter.
let noIn = false;

function withNoIn(fn) {
  const saved = noIn;
  noIn = true;
  try { return fn(); } finally { noIn = saved; }
}

function withInAllowed(fn) {
  const saved = noIn;
  noIn = false;
  try { return fn(); } finally { noIn = saved; }
}

// parseAssignment: handles assignments and ternary conditionals
// together in a single iterative loop.
//
// Both constructs are right-associative and bind looser than the
// binary operators parseBinary handles. The loop structure is:
//
//   loop:
//     read a binary expression (possible lhs or test)
//     if next token is `=`/`+=`/etc., push (expr, 'assign') frame, consume op, continue
//     if next token is `?`, push (expr, 'ternary-test') frame, consume op, continue
//     otherwise expr is the final rightmost value. Unwind frames
//     from the stack, folding each with the accumulated value:
//       - 'assign' frame: value = mkAssign(op, lhs, value)
//       - 'ternary-test': we still need the `: alternate`. After
//         parsing the consequent we continue the outer loop for
//         the alternate. We handle this by pushing a separate
//         'ternary-alt' frame with the saved test+consequent, and
//         NOT unwinding at `:` — the outer loop re-enters and
//         reads the alternate as the next binary expression.
//
// This gives us a single iterative state machine that can handle
// arbitrarily deep chains of `a ? b : c = d ? e : f = g` without
// growing the JS call stack.
function parseAssignment(lexer) {
  const frames = [];  // stack of pending contexts
  // How many `ternary-test` frames are on the stack. Counted
  // rather than searched so a long chain of nested ternaries
  // stays linear.
  let pendingTests = 0;

  // Read the first expression.
  let value = parseBinary(lexer);

  outer: while (true) {
    const t = lexer.peek();
    if (t) {
      const label = t.type.label;
      // Assignment operator.
      if (ASSIGN_OPS.has(label) || ASSIGN_OPS.has(t.value)) {
        const op = label === 'name' ? t.value : (t.value || label);
        frames.push({ kind: 'assign', op, lhs: value });
        lexer.advance();
        value = parseBinary(lexer);
        continue;
      }
      // Start of ternary.
      if (label === '?') {
        frames.push({ kind: 'ternary-test', test: value });
        pendingTests++;
        lexer.advance();
        value = parseBinary(lexer);
        continue;
      }
      // `:` terminating a ternary-test frame's consequent.
      //
      // The pending test is not necessarily on TOP of the stack:
      // in `a ? b ? 1 : 2 : 3` the inner ternary completes first
      // and leaves a `ternary-alt` frame sitting above the outer
      // `ternary-test`. Requiring the test to be on top made that
      // shape — which minifiers emit constantly, since a nested
      // ternary is how they encode if/else-if — a parse error, and
      // a parse error costs the whole file. So we REDUCE completed
      // frames into `value` until the pending test surfaces, then
      // shift, which is the ordinary shift-reduce step done with
      // an explicit stack rather than recursion.
      if (label === ':' && pendingTests > 0) {
        while (frames.length > 0 &&
               frames[frames.length - 1].kind !== 'ternary-test') {
          const top = frames.pop();
          if (top.kind === 'assign') {
            value = mkAssign(top.op, top.lhs, value);
          } else if (top.kind === 'ternary-alt') {
            value = mkConditional(top.test, top.consequent, value);
          }
        }
        const testFrame = frames.pop();
        pendingTests--;
        frames.push({ kind: 'ternary-alt', test: testFrame.test, consequent: value });
        lexer.advance();
        value = parseBinary(lexer);
        continue;
      }
    }

    // No pending assignment/ternary continuation. Unwind frames
    // right-to-left, folding each into `value`.
    while (frames.length > 0) {
      const top = frames[frames.length - 1];
      if (top.kind === 'assign') {
        frames.pop();
        value = mkAssign(top.op, top.lhs, value);
        continue;
      }
      if (top.kind === 'ternary-alt') {
        frames.pop();
        value = mkConditional(top.test, top.consequent, value);
        continue;
      }
      if (top.kind === 'ternary-test') {
        // Dangling `?` with no `:` — error.
        throw parseError(lexer, 'ternary conditional missing `:`');
      }
      break;
    }
    return value;
  }
}

// parseConditional is no longer a separate function — it's folded
// into parseAssignment above. Kept as a thin alias for any callers
// that want a ternary-only parse.
function parseConditional(lexer) {
  return parseAssignment(lexer);
}

// parseBinary — the Pratt-style binary operator layer. Formerly
// called parseExpression; renamed because the public entry point
// is now parseAssignment.
//
// Uses an iterative Pratt algorithm:
//
//   1. Push a primary onto the output stack.
//   2. Peek at the next token. If it's a binary operator:
//      a. While the top of the operator stack has precedence >=
//         the new operator (or >, for right-assoc), pop it and
//         combine the top two output entries into a binary node,
//         pushing the result back onto the output stack.
//      b. Push the new operator onto the operator stack.
//      c. Parse another primary, push to output.
//   3. If not a binary operator, drain the operator stack and
//      return the single remaining output entry.
//
// No recursion. The output and operator stacks grow linearly with
// the number of operators in the expression; deep nesting is free.
function parseBinary(lexer) {
  const output = [];   // operand / subexpression stack
  const ops = [];      // operator stack: { op, prec, nodeType, rightAssoc, loc }

  // First operand.
  output.push(parseOperand(lexer));

  while (true) {
    const t = lexer.peek();
    const opStr = tokenAsBinOp(t);
    if (!opStr) break;
    const info = BINOP_PRECEDENCE[opStr];
    const prec = info.prec;
    const rightAssoc = RIGHT_ASSOC.has(opStr);

    // Reduce while the operator stack's top binds at least as
    // tightly. For right-associative ops, only reduce strictly
    // higher-precedence tops.
    while (ops.length > 0) {
      const top = ops[ops.length - 1];
      const shouldReduce = rightAssoc
        ? top.prec > prec
        : top.prec >= prec;
      if (!shouldReduce) break;
      ops.pop();
      const right = output.pop();
      const left  = output.pop();
      output.push(mkBinary(top.nodeType, top.op, left, right));
    }

    ops.push({ op: opStr, prec, nodeType: info.nodeType, rightAssoc });
    lexer.advance();  // consume the operator token
    // Parse the next operand (including any prefix unary and postfix).
    output.push(parseOperand(lexer));
  }

  // Drain remaining operators.
  while (ops.length > 0) {
    const top = ops.pop();
    const right = output.pop();
    const left  = output.pop();
    output.push(mkBinary(top.nodeType, top.op, left, right));
  }

  if (output.length !== 1) {
    throw parseError(lexer, 'internal: expression parser left ' + output.length + ' operands');
  }
  return output[0];
}

// parseStatement — iterative statement parser.
//
// Two stacks:
//   tasks[]   — pending work items driving the parse
//   outputs[] — completed AST nodes waiting to be assembled
//
// Each task is a small record like `{ kind, ...context }`. The
// loop pops a task, runs the corresponding stepper, and may push
// follow-up tasks. Nested blocks, if-bodies, and function bodies
// produce more tasks rather than more call-stack frames.
//
// The entry point pushes a single `parse_stmt` task and drains
// the loop. When the loop terminates the outputs stack holds
// exactly one node — the parsed statement.
// `let` is a contextual keyword: at statement-start position it
// introduces a VariableDeclaration when followed by an Identifier,
// `[`, or `{`. Any other follow-up (`let + 1`, `let.foo`, `let[0]`
// in an expression context, `let()`, etc.) means `let` is a
// plain identifier reference. We peek two tokens to decide.
//
// This conservative rule matches ES6 grammar exactly: the only
// ambiguity is at the first token of a statement, and only when
// the second token is an Identifier or a destructuring opener.
// The `[` case for destructuring is what makes `let [a,b] = x`
// a declaration rather than a computed member access. We handle
// it the same way the spec does — treat `let [`as a declaration.
// (The engine's destructuring lowering is not yet implemented;
// it raises an unimplemented assumption at IR-build time.)
function isLetDeclarationStart(lexer) {
  const next = lexer.peek2();
  if (!next) return false;
  const lbl = next.type.label;
  if (lbl === 'name') return true;     // `let foo = ...`
  if (lbl === '[')    return true;     // `let [a, b] = ...`
  if (lbl === '{')    return true;     // `let {a, b} = ...`
  return false;
}

function parseStatement(lexer) {
  const tasks = [{ kind: 'parse_stmt' }];
  const outputs = [];
  // The `for` header's no-in restriction covers the header
  // EXPRESSION only. A function body written inside that header
  // — `for (var f = function () { if ("x" in o) …; }; …)`, and
  // minified code does this — is ordinary statement context
  // where `in` is an operator again. Without this reset the
  // restriction leaked into the body and rejected the operator.
  const savedNoIn = noIn;
  noIn = false;
  try {

  while (tasks.length > 0) {
    const task = tasks.pop();
    switch (task.kind) {
      case 'parse_stmt':
        beginStatement(lexer, tasks, outputs);
        break;
      case 'finish_if':
        finishIf(lexer, task, tasks, outputs);
        break;
      case 'finish_if_else':
        finishIfElse(task, outputs);
        break;
      case 'finish_while':
        finishWhile(task, outputs);
        break;
      case 'finish_do_while':
        finishDoWhile(lexer, task, tasks, outputs);
        break;
      case 'finish_do_while_test':
        finishDoWhileTest(task, outputs);
        break;
      case 'finish_for':
        finishFor(task, outputs);
        break;
      case 'finish_for_in_of':
        finishForInOf(task, outputs);
        break;
      case 'finish_try_body':
        finishTryBody(lexer, task, tasks, outputs);
        break;
      case 'finish_try_catch':
        finishTryCatch(lexer, task, tasks, outputs);
        break;
      case 'finish_try_finally':
        finishTryFinally(task, outputs);
        break;
      case 'finish_with':
        finishWith(task, outputs);
        break;
      case 'block_body':
        blockBodyStep(lexer, task, tasks, outputs);
        break;
      case 'collect_block_stmt':
        collectBlockStmt(task, tasks, outputs);
        break;
      case 'finish_block':
        finishBlock(task, outputs);
        break;
      case 'finish_func_decl':
        finishFuncDecl(task, outputs);
        break;
      default:
        throw new Error('parse: unknown task kind ' + task.kind);
    }
  }

  if (outputs.length !== 1) {
    throw parseError(lexer, 'internal: statement parser left ' + outputs.length + ' outputs');
  }
  return outputs[0];
  } finally {
    noIn = savedNoIn;
  }
}

// --- Statement dispatch ----------------------------------------------

function beginStatement(lexer, tasks, outputs) {
  if (lexer.eof()) {
    throw parseError(lexer, 'unexpected end of input in statement');
  }
  const t = lexer.peek();
  const label = t.type.label;

  if (label === ';') {
    lexer.advance();
    outputs.push(mkEmptyStatement(t));
    return;
  }
  if (label === '{') {
    lexer.advance();
    // Finish task reads the accumulated body and builds the node.
    // block_body loops over statements until `}`.
    tasks.push({ kind: 'finish_block', startTok: t, body: [] });
    tasks.push({ kind: 'block_body' });
    return;
  }
  if (label === 'var' || label === 'const' ||
      (label === 'name' && t.value === 'let' && isLetDeclarationStart(lexer))) {
    // `let` is a contextual keyword — acorn tokenizes it as
    // 'name'. We only treat it as a declaration when the next
    // token can legally follow `let` in a VariableDeclaration
    // context (an Identifier, `[`, or `{` for destructuring).
    // In expression position (`let + 1`, `let.foo`) it remains a
    // plain identifier reference.
    const kind = label === 'var' ? 'var'
      : label === 'const' ? 'const'
      : 'let';
    lexer.advance();
    parseVarDeclarations(lexer, kind, t, outputs);
    return;
  }
  if (label === 'if') {
    lexer.advance();
    expect(lexer, '(');
    const test = parseCommaExpression(lexer);
    expect(lexer, ')');
    tasks.push({ kind: 'finish_if', startTok: t, test });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }
  if (label === 'return') {
    lexer.advance();
    const n = lexer.peek();
    if (!n || n.type.label === ';' || n.type.label === '}' || n.type.label === 'eof') {
      if (n && n.type.label === ';') lexer.advance();
      outputs.push(mkReturnStatement(null, t, n));
      return;
    }
    const arg = parseCommaExpression(lexer);
    if (lexer.peek() && lexer.peek().type.label === ';') lexer.advance();
    outputs.push(mkReturnStatement(arg, t, null));
    return;
  }
  if (label === 'name' && t.value === 'async' &&
      lexer.peek2() && lexer.peek2().type.label === 'function') {
    // `async function f() { … }` in statement position. The
    // async marker is kept on the node: an async function's
    // return value is its promise's RESOLUTION value, which is
    // what `.then(cb)` hands the callback.
    lexer.advance();
    beginStatement(lexer, tasks, outputs);
    for (let i = tasks.length - 1; i >= 0; i--) {
      if (tasks[i].kind === 'finish_func_decl') { tasks[i].isAsync = true; break; }
    }
    return;
  }
  if (label === 'function') {
    lexer.advance();
    // `function*` — a generator. The `*` was an unconditional
    // parse error, which failed the ENTIRE file: one generator
    // anywhere and every sink in that file disappeared. We parse
    // it as an ordinary function so the body is walked; `yield`
    // is handled below.
    let isGenerator = false;
    if (lexer.peek() && lexer.peek().type.label === '*') {
      lexer.advance();
      isGenerator = true;
    }
    const nameTok = lexer.peek();
    let id = null;
    if (nameTok && nameTok.type.label === 'name') {
      lexer.advance();
      id = mkIdentifier(nameTok.value, nameTok);
    }
    expect(lexer, '(');
    const params = parseParamList(lexer);
    expect(lexer, ')');
    tasks.push({ kind: 'finish_func_decl', startTok: t, id, params, isGenerator });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }

  // --- while loop ---
  if (label === 'while') {
    lexer.advance();
    expect(lexer, '(');
    const test = parseCommaExpression(lexer);
    expect(lexer, ')');
    tasks.push({ kind: 'finish_while', startTok: t, test });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }
  // --- do-while loop ---
  if (label === 'do') {
    lexer.advance();
    tasks.push({ kind: 'finish_do_while', startTok: t });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }
  // --- for / for-in / for-of loop ---
  if (label === 'for') {
    lexer.advance();
    // `for await (… of …)` — async iteration. The `await` only
    // affects WHEN each value arrives, not which values the loop
    // sees, so it is dropped and the loop lowers like any other
    // for-of. Rejecting it failed the whole file, which is how
    // `for await (const entry of dirHandle.values())` erased
    // every finding in the analyzer's own UI source.
    if (lexer.peek() && lexer.peek().type.label === 'name' &&
        lexer.peek().value === 'await') {
      lexer.advance();
    }
    expect(lexer, '(');
    // Parse the init slot. It may be:
    //   * empty (just `;`)
    //   * a VariableDeclaration (`var/let/const i = 0`)
    //   * an Expression
    let init = null;
    const initTok = lexer.peek();
    if (initTok && initTok.type.label === ';') {
      // empty init
    } else if (initTok && (initTok.type.label === 'var' ||
               initTok.type.label === 'const' ||
               (initTok.type.label === 'name' && initTok.value === 'let' &&
                isLetDeclarationStart(lexer)))) {
      const kind = initTok.type.label === 'var' ? 'var'
        : initTok.type.label === 'const' ? 'const'
        : 'let';
      lexer.advance();
      // Parse a single declarator list (no trailing ';' — we'll
      // consume it below ourselves).
      const declBuf = [];
      parseVarDeclarationsInFor(lexer, kind, initTok, declBuf);
      init = declBuf[0] || null;
    } else {
      // No-in restriction: `for (c in a)` must leave `in` for
      // the header to consume. Without it the expression parser
      // ate `c in a` as a relational expression and the header
      // then demanded a `;`, so every bare-identifier for-in —
      // `for (c in obj)`, the shape minifiers emit — failed.
      init = withNoIn(() => parseCommaExpression(lexer));
    }
    // for-in / for-of. Either keyword follows the loop's binding
    // target rather than a `;`, so we branch here on what the
    // lexer actually produced.
    //
    // `init` is currently either a VariableDeclaration (whose
    // single declarator IS the binding target) or an expression
    // (an assignment target, `for (x of xs)`). Both shapes go
    // straight into the ESTree node; the IR builder handles them.
    const afterInit = lexer.peek();
    if (afterInit && (afterInit.type.label === 'in' ||
        (afterInit.type.label === 'name' && afterInit.value === 'of'))) {
      const isOf = afterInit.type.label !== 'in';
      lexer.advance();
      // The iterated expression is comma-level: minifiers write
      // `for (d in b = b || {}, a)` to fold a preceding statement
      // into the header.
      const right = parseCommaExpression(lexer);
      expect(lexer, ')');
      tasks.push({ kind: 'finish_for_in_of', startTok: t, left: init, right, isOf });
      tasks.push({ kind: 'parse_stmt' });
      return;
    }
    expect(lexer, ';');
    let test = null;
    if (lexer.peek() && lexer.peek().type.label !== ';') {
      test = parseCommaExpression(lexer);
    }
    expect(lexer, ';');
    let update = null;
    if (lexer.peek() && lexer.peek().type.label !== ')') {
      update = parseCommaExpression(lexer);
    }
    expect(lexer, ')');
    tasks.push({ kind: 'finish_for', startTok: t, init, test, update });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }
  // --- class declaration ---
  //
  // `class Name [extends Parent] { body }` lowers at parse time
  // to a FunctionDeclaration + a series of prototype-assignment
  // expression statements. The key insight: classes are
  // syntactic sugar over functions in JS, and our existing
  // function-decl + object-literal + `new` handling already
  // does what we need if we emit the right desugaring.
  //
  // We don't yet model `extends` precisely — the parent chain
  // requires __proto__ manipulation which our heap model
  // doesn't expose. We flag it via an unimplemented marker
  // in the parser output; the IR builder raises a soundness
  // assumption but otherwise treats the class as a standalone
  // constructor.
  //
  // Likewise, private fields `#x`, static fields, getters, and
  // setters are skipped over with an unimplemented marker.
  if (label === 'class') {
    lexer.advance();
    const nameTok = lexer.peek();
    let id = null;
    if (nameTok && nameTok.type.label === 'name') {
      lexer.advance();
      id = mkIdentifier(nameTok.value, nameTok);
    }
    // `extends Parent` — capture the parent identifier but treat
    // the chain conservatively.
    let superClass = null;
    if (lexer.peek() && lexer.peek().type.label === 'extends') {
      lexer.advance();
      superClass = parseExpression(lexer);
    }
    const body = parseClassBody(lexer);
    outputs.push(mkClassDeclaration(id, superClass, body, t));
    return;
  }
  // --- switch statement ---
  //
  // `switch (disc) { case v: stmts; case v2: stmts; default:
  // stmts; }` parses into a SwitchStatement node with a list
  // of SwitchCase entries. Each case's consequent is a
  // flat array of statements (fall-through is explicit in the
  // IR: a case without a terminating `break` falls into the
  // next case body).
  if (label === 'switch') {
    lexer.advance();
    expect(lexer, '(');
    const disc = parseCommaExpression(lexer);
    expect(lexer, ')');
    expect(lexer, '{');
    const cases = [];
    while (lexer.peek() && lexer.peek().type.label !== '}') {
      const c = parseSwitchCase(lexer);
      if (c) cases.push(c);
    }
    expect(lexer, '}');
    outputs.push(mkSwitchStatement(disc, cases, t));
    return;
  }
  // --- with statement ---
  //
  // `with (obj) body;` dynamically adds obj's properties to
  // the scope chain for resolutions inside body. It's legacy
  // JS (forbidden in strict mode) but still parseable. We
  // lower it by evaluating obj for its side effects, raising
  // an UNIMPLEMENTED assumption to flag the precision gap
  // (identifier → property lookups via the dynamic scope are
  // not modeled), and then processing the body as if the
  // `with` wasn't there. This is sound for taint flowing
  // through the body's explicit statements, only imprecise
  // for implicit property reads through the with object.
  if (label === 'with') {
    lexer.advance();
    expect(lexer, '(');
    const obj = parseExpression(lexer);
    expect(lexer, ')');
    tasks.push({ kind: 'finish_with', startTok: t, obj });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }
  // --- try / catch / finally ---
  if (label === 'try') {
    lexer.advance();
    // Body: expect a BlockStatement.
    tasks.push({ kind: 'finish_try_body', startTok: t });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }
  // --- throw ---
  if (label === 'throw') {
    lexer.advance();
    const arg = parseCommaExpression(lexer);
    if (lexer.peek() && lexer.peek().type.label === ';') lexer.advance();
    outputs.push(mkThrowStatement(arg, t));
    return;
  }
  // --- break / continue ---
  if (label === 'break' || label === 'continue') {
    lexer.advance();
    // Optional label — not yet supported.
    const next = lexer.peek();
    let labelName = null;
    if (next && next.type.label === 'name') {
      labelName = next.value;
      lexer.advance();
    }
    if (lexer.peek() && lexer.peek().type.label === ';') lexer.advance();
    outputs.push(label === 'break'
      ? mkBreakStatement(labelName, t)
      : mkContinueStatement(labelName, t));
    return;
  }

  // Keywords not yet implemented: skip to the next `;` or to the
  // end of a balanced brace region, then emit a marker node. This
  // keeps the rest of the program analysable.
  if (isUnhandledStatementKeyword(label)) {
    const startTok = t;
    const endTok = skipToNextStatementBoundary(lexer);
    outputs.push(mkUnimplementedStatement(label, startTok, endTok));
    return;
  }

  // Expression statement — fall-through. The expression parser
  // propagates errors; unknown primaries become
  // UnimplementedExpression markers inside parsePrimary rather
  // than via exception-and-recover here.
  // Comma-level: a minifier folds a run of statements into one
  // `a(), b(), c();`. Stopping at the first comma left the rest
  // of the line unconsumed and the parse derailed — this is what
  // `do t%2&&(r+=n), t=f(t/2); while (t)` tripped over.
  const expr = parseCommaExpression(lexer);
  if (lexer.peek() && lexer.peek().type.label === ';') lexer.advance();
  outputs.push(mkExpressionStatement(expr));
}

// Keywords that introduce statement constructs we haven't
// implemented yet. Each becomes an UnimplementedStatement marker
// until the corresponding transfer function is written.
const UNHANDLED_STATEMENT_KEYWORDS = new Set([
  'import', 'export',
]);

function isUnhandledStatementKeyword(label) {
  return UNHANDLED_STATEMENT_KEYWORDS.has(label);
}

// Advance past tokens until we reach a semicolon, a newline
// statement boundary, or a balanced `}` that closes the enclosing
// scope. This keeps the parser's cursor at a resumable position
// after an unimplemented construct.
function skipToNextStatementBoundary(lexer) {
  let depth = 0;
  let last = lexer.peek();
  while (!lexer.eof()) {
    const t = lexer.peek();
    const label = t.type.label;
    if (label === '(' || label === '[' || label === '{') {
      depth++;
      last = lexer.advance();
      continue;
    }
    if (label === ')' || label === ']' || label === '}') {
      if (depth === 0) return last;
      depth--;
      last = lexer.advance();
      continue;
    }
    if (depth === 0 && label === ';') {
      last = lexer.advance();
      return last;
    }
    last = lexer.advance();
  }
  return last;
}

function parseVarDeclarations(lexer, kind, startTok, outputs) {
  const decls = [];
  while (true) {
    const target = parseBindingTarget(lexer);
    let init = null;
    const next = lexer.peek();
    if (next && (next.type.label === '=' || next.value === '=')) {
      lexer.advance();
      init = parseExpression(lexer);
    }
    decls.push(mkVariableDeclarator(target, init));
    if (lexer.peek() && lexer.peek().type.label === ',') {
      lexer.advance();
      continue;
    }
    break;
  }
  if (lexer.peek() && lexer.peek().type.label === ';') lexer.advance();
  outputs.push(mkVariableDeclaration(kind, decls, startTok));
}

function parseParamList(lexer) {
  const params = [];
  if (lexer.peek() && lexer.peek().type.label === ')') return params;
  while (true) {
    // `...rest`
    if (lexer.peek() && lexer.peek().type.label === '...') {
      const restTok = lexer.advance();
      const target = parseBindingTarget(lexer);
      params.push(mkRestElement(target, restTok));
      // Rest must be the last param.
      break;
    }
    const target = parseBindingTarget(lexer);
    // Default value: `x = 1`
    if (lexer.peek() && (lexer.peek().type.label === '=' || lexer.peek().value === '=')) {
      lexer.advance();
      const def = parseExpression(lexer);
      params.push(mkAssignmentPattern(target, def));
    } else {
      params.push(target);
    }
    if (lexer.peek() && lexer.peek().type.label === ',') {
      lexer.advance();
      // Trailing comma in a parameter list: `function f(a, b,)`.
      if (lexer.peek() && lexer.peek().type.label === ')') break;
      continue;
    }
    break;
  }
  return params;
}

// parseBindingTarget — parses an identifier, object pattern, or
// array pattern. Returns an ESTree node (Identifier,
// ObjectPattern, or ArrayPattern).
//
// Grammar:
//   BindingTarget:
//     Identifier
//     ObjectPattern:
//       { BindingProperty* }
//       BindingProperty: name
//                      | name : BindingTarget
//                      | name = default       (shorthand + default)
//                      | ... BindingTarget    (rest element)
//     ArrayPattern:
//       [ BindingElement* ]
//       BindingElement: BindingTarget
//                     | BindingTarget = default
//                     | ... BindingTarget
//                     | (empty — hole)
function parseBindingTarget(lexer) {
  const t = lexer.peek();
  if (!t) throw parseError(lexer, 'expected binding target');
  if (t.type.label === 'name') {
    lexer.advance();
    return mkIdentifier(t.value, t);
  }
  if (t.type.label === '{') {
    return parseObjectPattern(lexer);
  }
  if (t.type.label === '[') {
    return parseArrayPattern(lexer);
  }
  throw parseError(lexer, 'expected binding target, got `' + t.type.label + '`');
}

function parseObjectPattern(lexer) {
  const startTok = lexer.advance();  // `{`
  const properties = [];
  while (lexer.peek() && lexer.peek().type.label !== '}') {
    // Rest: `...rest`
    if (lexer.peek().type.label === '...') {
      const restTok = lexer.advance();
      const target = parseBindingTarget(lexer);
      properties.push(mkRestElement(target, restTok));
      // Rest must be last in an ObjectPattern, but we don't
      // strictly enforce it — parser is lenient.
      if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
      continue;
    }
    // Property: key [: value] [= default]
    const keyTok = lexer.peek();
    // Keys may be identifiers, string literals or numbers:
    // `{ "a-b": x }` and `{ 0: x }` are both legal patterns.
    // Reserved words are legal keys here too: Vue destructures
    // `const { mixins, extends: r } = t`.
    if (keyTok.type.label !== 'name' && keyTok.type.label !== 'string' &&
        keyTok.type.label !== 'num' && !keyTok.type.keyword) {
      throw parseError(lexer, 'expected property name in destructuring pattern');
    }
    lexer.advance();
    const keyName = String(keyTok.value);
    const key = mkIdentifier(keyName, keyTok);
    let value;
    let shorthand;
    if (lexer.peek() && lexer.peek().type.label === ':') {
      lexer.advance();
      value = parseBindingTarget(lexer);
      shorthand = false;
    } else {
      value = mkIdentifier(keyName, keyTok);
      shorthand = true;
    }
    // Default value. Legal in BOTH forms — `{v = d}` and
    // `{v: alias = d}`. Restricting it to the shorthand form
    // left the `=` unconsumed, so the next loop turn read `=`
    // as a property name and the whole statement failed to
    // parse; every sink in the file went with it.
    if (lexer.peek() && lexer.peek().type.label === '=') {
      lexer.advance();
      const def = parseExpression(lexer);
      value = mkAssignmentPattern(value, def);
    }
    properties.push(mkObjectPatternProperty(key, value, shorthand, keyTok));
    if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
  }
  expect(lexer, '}');
  return mkObjectPattern(properties, startTok);
}

function parseArrayPattern(lexer) {
  const startTok = lexer.advance();  // `[`
  const elements = [];
  while (lexer.peek() && lexer.peek().type.label !== ']') {
    // Hole: `[,`
    if (lexer.peek().type.label === ',') {
      elements.push(null);
      lexer.advance();
      continue;
    }
    // Rest: `...rest`
    if (lexer.peek().type.label === '...') {
      const restTok = lexer.advance();
      const target = parseBindingTarget(lexer);
      elements.push(mkRestElement(target, restTok));
      break;
    }
    let elem = parseBindingTarget(lexer);
    // Default value
    if (lexer.peek() && lexer.peek().type.label === '=') {
      lexer.advance();
      const def = parseExpression(lexer);
      elem = mkAssignmentPattern(elem, def);
    }
    elements.push(elem);
    if (lexer.peek() && lexer.peek().type.label === ',') lexer.advance();
  }
  expect(lexer, ']');
  return mkArrayPattern(elements, startTok);
}

// block_body re-runs itself after each inner statement until `}`.
// The finish_block task (already on the stack, below every
// block_body we push) collects statements into its body array via
// collect_block_stmt — a little shim task that moves the most
// recent output into the finish_block's pending body.
function blockBodyStep(lexer, task, tasks, outputs) {
  // Skip stray semicolons between statements.
  while (lexer.peek() && lexer.peek().type.label === ';') lexer.advance();
  if (lexer.eof() || lexer.peek().type.label === '}') {
    if (lexer.peek() && lexer.peek().type.label === '}') {
      const endTok = lexer.advance();
      for (let i = tasks.length - 1; i >= 0; i--) {
        if (tasks[i].kind === 'finish_block') {
          tasks[i].endTok = endTok;
          break;
        }
      }
    }
    return;
  }
  // Schedule: parse_stmt → collect_block_stmt → block_body (loops).
  tasks.push({ kind: 'block_body' });
  tasks.push({ kind: 'collect_block_stmt' });
  tasks.push({ kind: 'parse_stmt' });
}

function collectBlockStmt(task, tasks, outputs) {
  const stmt = outputs.pop();
  for (let i = tasks.length - 1; i >= 0; i--) {
    if (tasks[i].kind === 'finish_block') {
      tasks[i].body.push(stmt);
      return;
    }
  }
  throw new Error('parse: collect_block_stmt with no finish_block on stack');
}

function finishBlock(task, outputs) {
  outputs.push(mkBlockStatement(task.body, task.startTok, task.endTok || task.startTok));
}

function finishIf(lexer, task, tasks, outputs) {
  const consequent = outputs.pop();
  if (lexer.peek() && lexer.peek().type.label === 'else') {
    lexer.advance();
    tasks.push({ kind: 'finish_if_else', startTok: task.startTok, test: task.test, consequent });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }
  outputs.push(mkIfStatement(task.test, consequent, null, task.startTok));
}

function finishIfElse(task, outputs) {
  const alternate = outputs.pop();
  outputs.push(mkIfStatement(task.test, task.consequent, alternate, task.startTok));
}

function finishWhile(task, outputs) {
  const body = outputs.pop();
  outputs.push(mkWhileStatement(task.test, body, task.startTok));
}

function finishDoWhile(lexer, task, tasks, outputs) {
  // The body has just been parsed — it's at the top of outputs.
  const body = outputs.pop();
  // Now expect `while (test);`.
  expect(lexer, 'while');
  expect(lexer, '(');
  const test = parseCommaExpression(lexer);
  expect(lexer, ')');
  if (lexer.peek() && lexer.peek().type.label === ';') lexer.advance();
  outputs.push(mkDoWhileStatement(body, test, task.startTok));
}

function finishDoWhileTest(task, outputs) {
  // Unused hook placeholder kept for symmetry with tasks added in
  // the parser dispatch; the actual do-while parsing completes in
  // finishDoWhile above.
  outputs;
}

function finishFor(task, outputs) {
  const body = outputs.pop();
  outputs.push(mkForStatement(task.init, task.test, task.update, body, task.startTok));
}

// --- try / catch / finally parsing -------------------------------------
//
// Grammar:
//   TryStatement:
//     try Block Catch
//     try Block Finally
//     try Block Catch Finally
//   Catch:
//     catch/CatchParameter/ Block
//     catch Block                    // ES2019 optional-catch-binding
//
// We use three tasks that run sequentially over the outputs
// stack so the parser stays iterative: finish_try_body,
// finish_try_catch, finish_try_finally.

function finishTryBody(lexer, task, tasks, outputs) {
  // Body block is at outputs top.
  const block = outputs.pop();
  const next = lexer.peek();
  let hasCatch = false;
  let hasFinally = false;
  let catchStartTok = null;
  let catchParam = null;
  if (next && next.type.label === 'catch') {
    hasCatch = true;
    catchStartTok = next;
    lexer.advance();
    // Optional catch-binding: `catch /e/`, `catch /{a, b}/`,
    // `catch /[x, y]/`, or bare `catch` (ES2019 optional-
    // catch-binding). The param accepts any BindingTarget
    // (identifier or destructuring pattern).
    if (lexer.peek() && lexer.peek().type.label === '(') {
      lexer.advance();
      catchParam = parseBindingTarget(lexer);
      expect(lexer, ')');
    }
  }
  const afterCatch = hasCatch ? lexer.peek() : next;
  if (afterCatch && afterCatch.type.label === 'finally') {
    hasFinally = true;
    // Consume `finally` here if no handler was present, so
    // finish_try_catch can detect it as already-consumed.
    // Otherwise leave it for finish_try_catch to see.
  }
  if (hasCatch) {
    // Parse the catch body, then return via finish_try_catch.
    tasks.push({
      kind: 'finish_try_catch',
      startTok: task.startTok,
      block,
      catchStartTok,
      catchParam,
    });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }
  // No catch — must have finally.
  if (hasFinally) {
    lexer.advance();  // consume 'finally'
    tasks.push({
      kind: 'finish_try_finally',
      startTok: task.startTok,
      block,
      handler: null,
    });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }
  // Neither catch nor finally — parse error.
  throw parseError(lexer, 'expected `catch` or `finally` after `try` block');
}

function finishTryCatch(lexer, task, tasks, outputs) {
  const catchBody = outputs.pop();
  const handler = mkCatchClause(task.catchParam, catchBody, task.catchStartTok);
  // Check for finally.
  if (lexer.peek() && lexer.peek().type.label === 'finally') {
    lexer.advance();
    tasks.push({
      kind: 'finish_try_finally',
      startTok: task.startTok,
      block: task.block,
      handler,
    });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }
  // catch only, no finally.
  outputs.push(mkTryStatement(task.block, handler, null, task.startTok));
}

function finishTryFinally(task, outputs) {
  const finalizer = outputs.pop();
  outputs.push(mkTryStatement(task.block, task.handler, finalizer, task.startTok));
}

function finishWith(task, outputs) {
  const body = outputs.pop();
  outputs.push(mkWithStatement(task.obj, body, task.startTok));
}

// parseSwitchCase — `case expr: stmts*` or `default: stmts*`.
// The consequent is a sequence of statements until the next
// `case`, `default`, or the closing `}`. Fall-through is
// preserved: a case without a terminating `break` flows into
// the next case at IR build time.
function parseSwitchCase(lexer) {
  const startTok = lexer.peek();
  if (!startTok) return null;
  let test = null;
  if (startTok.type.label === 'case') {
    lexer.advance();
    test = parseCommaExpression(lexer);
  } else if (startTok.type.label === 'default') {
    lexer.advance();
  } else {
    // Stray token — skip it so we don't loop forever.
    lexer.advance();
    return null;
  }
  expect(lexer, ':');
  // Parse statements until the next case/default/}.
  const consequent = [];
  while (lexer.peek() && lexer.peek().type.label !== 'case' &&
         lexer.peek().type.label !== 'default' &&
         lexer.peek().type.label !== '}') {
    // parseStatement here is the main statement parser, which
    // returns an AST node on `outputs` but we need to run it
    // as a standalone. parseStatement drives its own task
    // loop and returns the single top-of-output.
    const stmt = parseStatement(lexer);
    if (stmt) consequent.push(stmt);
  }
  return mkSwitchCase(test, consequent, startTok);
}

function mkSwitchStatement(disc, cases, startTok) {
  return {
    type: 'SwitchStatement',
    discriminant: disc,
    cases,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start, end: startTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   startTok ? startTok.end : 0,
  };
}

function mkSwitchCase(test, consequent, startTok) {
  return {
    type: 'SwitchCase',
    test,
    consequent,
    loc: startTok && startTok.loc
      ? { start: startTok.loc.start, end: startTok.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   startTok ? startTok.end : 0,
  };
}

function mkWithStatement(object, body, startTok) {
  return {
    type: 'WithStatement',
    object,
    body,
    loc: startTok && startTok.loc && body && body.loc
      ? { start: startTok.loc.start, end: body.loc.end }
      : null,
    start: startTok ? startTok.start : 0,
    end:   body ? body.end : 0,
  };
}

// parseVarDeclarationsInFor — like parseVarDeclarations but does
// NOT consume a trailing `;` because the for-loop header handles
// it explicitly.
function parseVarDeclarationsInFor(lexer, kind, kindTok, outputs) {
  const decls = [];
  while (true) {
    const target = parseBindingTarget(lexer);
    let init = null;
    const next = lexer.peek();
    if (next && next.type.label === '=') {
      lexer.advance();
      // Declarator initialisers in a `for` header carry the same
      // no-in restriction as the bare-expression form.
      init = withNoIn(() => parseExpression(lexer));
    }
    decls.push(mkVariableDeclarator(target, init));
    if (lexer.peek() && lexer.peek().type.label === ',') {
      lexer.advance();
      continue;
    }
    break;
  }
  outputs.push(mkVariableDeclaration(kind, decls, kindTok));
}

function finishForInOf(task, outputs) {
  const body = outputs.pop();
  outputs.push(mkForInOfStatement(
    task.isOf, task.left, task.right, body, task.startTok));
}

function finishFuncDecl(task, outputs) {
  const body = outputs.pop();
  if (!body || body.type !== 'BlockStatement') {
    throw new Error('parse: function body must be a block statement');
  }
  outputs.push(mkFunctionDeclaration(task.id, task.params, body,
    !!task.isAsync, !!task.isGenerator, task.startTok));
}

// --- Location helper (public) -----------------------------------------

function locFromNode(node, filename) {
  if (!node || !node.loc) return { file: filename, line: 0, col: 0, pos: 0 };
  return {
    file: filename,
    line: node.loc.start.line,
    col: node.loc.start.column,
    pos: node.start || 0,
    endPos: node.end || 0,
  };
}

function parseAuto(source, filename) {
  return { ast: parseModule(source, filename), sourceType: 'script' };
}

module.exports = {
  parseModule,
  parseAuto,
  locFromNode,
  // Internals exposed for tests in later phases.
  _internals: {
    createLexer,
    mkProgram,
    mkLiteral,
    mkIdentifier,
    mkBinary,
    parsePrimary,
    parseExpression,
  },
};
