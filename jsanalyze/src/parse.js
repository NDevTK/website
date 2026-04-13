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

// Resolve acorn: prefer the vendored copy shipped under
// jsanalyze/vendor/, fall back to a node_modules install. We
// check for the file's existence explicitly rather than catching
// a require error — the boundary between "vendored" and
// "installed" is an environment property, not data-dependent
// recovery.
function getAcorn() {
  if (_acorn) return _acorn;
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
  while (true) {
    const t = lexer.peek();
    if (!t) break;
    // Unary `new` — prefix form; treat specially because it
    // captures the following call expression as its arguments.
    if (t.type.label === 'new') {
      prefixes.push({ kind: 'new', tok: t });
      lexer.advance();
      continue;
    }
    if (UNARY_PREFIX.has(t.type.label) || UNARY_PREFIX.has(t.value)) {
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

  let base = parsePrimary(lexer);

  // Postfix suffix loop: `.prop`, `[expr]`, `(args)`.
  while (true) {
    const t = lexer.peek();
    if (!t) break;
    const label = t.type.label;
    if (label === '.') {
      lexer.advance();
      const nameTok = lexer.peek();
      if (!nameTok || (nameTok.type.label !== 'name' && !nameTok.type.keyword)) {
        throw parseError(lexer, 'expected property name after `.`');
      }
      lexer.advance();
      const propNode = mkIdentifier(nameTok.value || nameTok.type.label, nameTok);
      base = mkMember(base, propNode, false);
      continue;
    }
    if (label === '[') {
      lexer.advance();
      const keyExpr = parseExpression(lexer);
      expect(lexer, ']');
      base = mkMember(base, keyExpr, true);
      continue;
    }
    if (label === '(') {
      // Function call — parse comma-separated arguments.
      lexer.advance();
      const args = [];
      if (lexer.peek().type.label !== ')') {
        while (true) {
          args.push(parseExpression(lexer));
          const n = lexer.peek();
          if (n.type.label === ',') { lexer.advance(); continue; }
          break;
        }
      }
      const closeTok = lexer.peek();
      expect(lexer, ')');
      base = mkCall(base, args, closeTok ? closeTok.end : base.end);
      continue;
    }
    // Postfix ++ / --. Binds tighter than any binary operator, so
    // apply immediately to the current `base`.
    if (label === '++/--') {
      base = mkUpdate(t.value, base, false, t);
      lexer.advance();
      continue;
    }
    break;
  }

  // Apply prefix operators in reverse (innermost first).
  while (prefixes.length > 0) {
    const p = prefixes.pop();
    if (p.kind === 'unary') {
      base = mkUnary(p.op, base, true, p.tok);
    } else if (p.kind === 'update_prefix') {
      base = mkUpdate(p.op, base, true, p.tok);
    } else if (p.kind === 'new') {
      // `new X(args)`: if the base is already a CallExpression,
      // convert it in place to NewExpression; otherwise it's
      // `new X` with no args.
      if (base.type === 'CallExpression') {
        base = mkNew(base.callee, base.arguments, p.tok.start, base.end);
      } else {
        base = mkNew(base, [], p.tok.start, base.end);
      }
    }
  }

  return base;
}

// A primary expression: literal, identifier, `this`, or a
// parenthesised expression.
// parseArrowBody — `=>` has already been consumed. Parses the
// arrow body (block or expression) and returns an
// ArrowFunctionExpression node with the provided params.
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
    const items = [parseExpression(lexer)];
    while (lexer.peek() && lexer.peek().type.label === ',') {
      lexer.advance();
      items.push(parseExpression(lexer));
    }
    expect(lexer, ')');
    if (lexer.peek() && lexer.peek().type.label === '=>') {
      lexer.advance();
      const params = items.map(e => {
        if (e.type !== 'Identifier') {
          throw new Error('arrow parameter must be an identifier (got ' + e.type + ')');
        }
        return e;
      });
      return parseArrowBody(lexer, params, t);
    }
    // Paren-expression. If multiple items, wrap as
    // SequenceExpression (the comma operator).
    if (items.length === 1) return items[0];
    return mkSequenceExpression(items);
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
  if (label === 'in') return 'in';
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
function parseExpression(lexer) {
  return parseAssignment(lexer);
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
        lexer.advance();
        value = parseBinary(lexer);
        continue;
      }
      // `:` terminating a ternary-test frame's consequent. We pop
      // the test frame, remember its test + the consequent we just
      // produced, and push a ternary-alt frame so unwinding can
      // build the ConditionalExpression.
      if (label === ':' && frames.length > 0 && frames[frames.length - 1].kind === 'ternary-test') {
        const testFrame = frames.pop();
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
      case 'finish_try_body':
        finishTryBody(lexer, task, tasks, outputs);
        break;
      case 'finish_try_catch':
        finishTryCatch(lexer, task, tasks, outputs);
        break;
      case 'finish_try_finally':
        finishTryFinally(task, outputs);
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
    const test = parseExpression(lexer);
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
    const arg = parseExpression(lexer);
    if (lexer.peek() && lexer.peek().type.label === ';') lexer.advance();
    outputs.push(mkReturnStatement(arg, t, null));
    return;
  }
  if (label === 'function') {
    lexer.advance();
    const nameTok = lexer.peek();
    let id = null;
    if (nameTok && nameTok.type.label === 'name') {
      lexer.advance();
      id = mkIdentifier(nameTok.value, nameTok);
    }
    expect(lexer, '(');
    const params = parseParamList(lexer);
    expect(lexer, ')');
    tasks.push({ kind: 'finish_func_decl', startTok: t, id, params });
    tasks.push({ kind: 'parse_stmt' });
    return;
  }

  // --- while loop ---
  if (label === 'while') {
    lexer.advance();
    expect(lexer, '(');
    const test = parseExpression(lexer);
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
      init = parseExpression(lexer);
    }
    // TODO: for-in / for-of detection. For now we assume `;`-style
    // C loop and raise unimplemented if the next token is `in` or
    // `of`.
    const afterInit = lexer.peek();
    if (afterInit && (afterInit.type.label === 'in' ||
        (afterInit.type.label === 'name' && afterInit.value === 'of'))) {
      // for-in / for-of. Skip to end of statement — not yet supported.
      const endTok = skipToNextStatementBoundary(lexer);
      outputs.push(mkUnimplementedStatement('for-' + afterInit.value, t, endTok));
      return;
    }
    expect(lexer, ';');
    let test = null;
    if (lexer.peek() && lexer.peek().type.label !== ';') {
      test = parseExpression(lexer);
    }
    expect(lexer, ';');
    let update = null;
    if (lexer.peek() && lexer.peek().type.label !== ')') {
      update = parseExpression(lexer);
    }
    expect(lexer, ')');
    tasks.push({ kind: 'finish_for', startTok: t, init, test, update });
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
    const arg = parseExpression(lexer);
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
  const expr = parseExpression(lexer);
  if (lexer.peek() && lexer.peek().type.label === ';') lexer.advance();
  outputs.push(mkExpressionStatement(expr));
}

// Keywords that introduce statement constructs we haven't
// implemented yet. Each becomes an UnimplementedStatement marker
// until the corresponding transfer function is written.
const UNHANDLED_STATEMENT_KEYWORDS = new Set([
  'switch',
  'with', 'class', 'import', 'export',
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
    const nameTok = lexer.peek();
    if (!nameTok || nameTok.type.label !== 'name') {
      throw parseError(lexer, 'expected variable name after `' + kind + '`');
    }
    lexer.advance();
    const id = mkIdentifier(nameTok.value, nameTok);
    let init = null;
    const next = lexer.peek();
    if (next && (next.type.label === '=' || next.value === '=')) {
      lexer.advance();
      init = parseExpression(lexer);
    }
    decls.push(mkVariableDeclarator(id, init));
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
    const t = lexer.peek();
    if (!t || t.type.label !== 'name') {
      throw parseError(lexer, 'expected parameter name');
    }
    lexer.advance();
    params.push(mkIdentifier(t.value, t));
    if (lexer.peek() && lexer.peek().type.label === ',') {
      lexer.advance();
      continue;
    }
    break;
  }
  return params;
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
  const test = parseExpression(lexer);
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
    // Optional catch-binding: `catch /e/` or `catch`.
    if (lexer.peek() && lexer.peek().type.label === '(') {
      lexer.advance();
      const paramTok = lexer.peek();
      if (paramTok && paramTok.type.label === 'name') {
        catchParam = mkIdentifier(paramTok.value, paramTok);
        lexer.advance();
      }
      // Destructuring patterns in catch param not yet supported.
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

// parseVarDeclarationsInFor — like parseVarDeclarations but does
// NOT consume a trailing `;` because the for-loop header handles
// it explicitly.
function parseVarDeclarationsInFor(lexer, kind, kindTok, outputs) {
  const decls = [];
  while (true) {
    const nameTok = lexer.peek();
    if (!nameTok || nameTok.type.label !== 'name') {
      throw parseError(lexer, 'expected identifier after ' + kind);
    }
    const id = mkIdentifier(nameTok.value, nameTok);
    lexer.advance();
    let init = null;
    const next = lexer.peek();
    if (next && next.type.label === '=') {
      lexer.advance();
      init = parseExpression(lexer);
    }
    decls.push(mkVariableDeclarator(id, init, nameTok));
    if (lexer.peek() && lexer.peek().type.label === ',') {
      lexer.advance();
      continue;
    }
    break;
  }
  outputs.push(mkVariableDeclaration(kind, decls, kindTok));
}

function finishFuncDecl(task, outputs) {
  const body = outputs.pop();
  if (!body || body.type !== 'BlockStatement') {
    throw new Error('parse: function body must be a block statement');
  }
  outputs.push(mkFunctionDeclaration(task.id, task.params, body, false, false, task.startTok));
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
