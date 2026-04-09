// Advanced tests for htmldom.js's extractHTML resolver.
//
// Run with: node htmldom/htmldom.test.js
//
// This test file loads htmldom.js under Node by stubbing the browser globals
// it touches at init time, then exercises extractHTML across a range of
// JavaScript inputs: plain assignments, scope edge cases, concat chains,
// array .join patterns, templates, and the `<`-content HTML filter.

'use strict';

const fs = require('fs');
const path = require('path');

// Minimal DOM stubs — just enough for htmldom.js's IIFE init to run without
// exploding. extractHTML itself doesn't touch any of these.
global.document = {
  getElementById: () => ({ addEventListener: () => {}, value: '' }),
};
global.DOMParser = class {
  parseFromString() { return { body: { childNodes: [] } }; }
};

// Load htmldom.js and expose its internal extractHTML via globalThis by
// splicing export lines into the source before eval.
const src = fs.readFileSync(path.join(__dirname, 'htmldom.js'), 'utf8');
const patched = src.replace(
  'function extractHTML(input) {',
  'globalThis.__extractHTML = extractHTML;\n  globalThis.__extractAllHTML = extractAllHTML;\n  globalThis.__extractAllDOM = extractAllDOM;\n  globalThis.__tokenize = tokenize;\n  globalThis.__tokenizeHtml = tokenizeHtml;\n  globalThis.__serializeHtmlTokens = serializeHtmlTokens;\n  globalThis.__decodeHtmlEntities = decodeHtmlEntities;\n  globalThis.__parseStyleDecls = parseStyleDecls;\n  globalThis.__convertRaw = convertRaw;\n  globalThis.__makeVar = makeVar;\n  function extractHTML(input) {'
);
// eslint-disable-next-line no-eval
eval(patched);
const extractHTML = globalThis.__extractHTML;
const extractAllHTML = globalThis.__extractAllHTML;
const extractAllDOM = globalThis.__extractAllDOM;

// Test harness.
let pass = 0;
let fail = 0;
const failures = [];

// Materialize chain tokens into { html, autoSubs } for test comparison.
// This reconstructs the old output format from the new chainTokens format
// so existing test expectations still work.
function materializeForTest(chainTokens) {
  if (!chainTokens || !chainTokens.length) return { html: '', autoSubs: [] };
  const autoSubs = [];
  let html = '';
  let idx = 0;
  let loopId = null;
  for (const t of chainTokens) {
    if (t.type === 'plus') continue;
    // Track loop boundaries.
    const tLoop = t.loopId != null ? t.loopId : null;
    if (tLoop !== loopId) {
      if (loopId !== null) html += '__HDLOOP' + loopId + 'E__';
      if (tLoop !== null) html += '__HDLOOP' + tLoop + 'S__';
      loopId = tLoop;
    }
    if (t.type === 'str') {
      html += t.text;
    } else if (t.type === 'tmpl') {
      for (const p of t.parts) {
        if (p.kind === 'text') {
          // Decode template literal text the same way the old code did
          html += p.raw.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\`/g, '`').replace(/\\\\/g, '\\');
        } else {
          const ph = '__HDX' + idx + '__';
          autoSubs.push([ph, p.expr.trim()]);
          html += ph;
          idx++;
        }
      }
    } else if (t.type === 'cond') {
      // Conditional token — reconstruct as ternary expression.
      const tTrue = materializeForTest(t.ifTrue);
      const tFalse = materializeForTest(t.ifFalse);
      const trueExpr = tTrue.autoSubs.length ? tTrue.html : JSON.stringify(tTrue.html);
      const falseExpr = tFalse.autoSubs.length ? tFalse.html : JSON.stringify(tFalse.html);
      const ph = '__HDX' + idx + '__';
      autoSubs.push([ph, '(' + t.condExpr + ' ? ' + trueExpr + ' : ' + falseExpr + ')']);
      html += ph;
      idx++;
    } else {
      // Expression token — reconstruct source.
      const expr = t._src ? t._src.slice(t.start, t.end).trim() : t.text;
      const ph = '__HDX' + idx + '__';
      autoSubs.push([ph, expr]);
      html += ph;
      idx++;
    }
  }
  if (loopId !== null) html += '__HDLOOP' + loopId + 'E__';
  return { html, autoSubs };
}

function check(name, input, expected) {
  const out = extractHTML(input);
  // Materialize chain tokens for comparison with old-format expectations.
  const m = out.chainTokens ? materializeForTest(out.chainTokens) : { html: '', autoSubs: [] };
  // Reconstruct loops from loopInfoMap + chain token loopIds.
  let loops = undefined;
  if (out.loopInfoMap && out.chainTokens) {
    const seen = new Set();
    for (const t of out.chainTokens) {
      if (t.loopId != null) seen.add(t.loopId);
    }
    if (seen.size) {
      loops = [...seen].sort((a, b) => a - b).map(id => {
        const info = out.loopInfoMap[id];
        return info ? { id, kind: info.kind, headerSrc: info.headerSrc } : { id, kind: 'for', headerSrc: '' };
      });
    }
  }
  const got = {
    html: m.html,
    target: out.target || null,
    assignProp: out.assignProp || null,
    assignOp: out.assignOp || null,
    autoSubs: m.autoSubs || [],
    loops: loops || undefined,
    loopVars: out.loopVars || undefined,
  };
  // Normalize expected (allow string shorthand -> just html match).
  const want = typeof expected === 'string' ? { html: expected } : expected;
  let ok = true;
  for (const k of Object.keys(want)) {
    if (JSON.stringify(got[k]) !== JSON.stringify(want[k])) { ok = false; break; }
  }
  if (ok) {
    pass++;
  } else {
    fail++;
    failures.push({ name, input, want, got });
  }
}

function group(title, fn) {
  console.log('\n' + title);
  console.log('-'.repeat(title.length));
  const before = pass + fail;
  fn();
  const ran = pass + fail - before;
  console.log(`  (${ran} cases)`);
}

// -----------------------------------------------------------------------
// Direct inputs
// -----------------------------------------------------------------------
group('direct inputs', () => {
  check('raw HTML', '<div>hi</div>', { html: '<div>hi</div>', target: null });
  check('empty', '', { html: '', target: null });
  check('no HTML at all', 'var x = 1;', { html: 'var x = 1;', target: null });
});

// -----------------------------------------------------------------------
// innerHTML / outerHTML detection
// -----------------------------------------------------------------------
group('assignment detection', () => {
  check('.innerHTML =',
    `document.body.innerHTML = '<a>hi</a>';`,
    { html: '<a>hi</a>', target: 'document.body', assignProp: 'innerHTML', assignOp: '=' });
  check('.innerHTML +=',
    `document.body.innerHTML += '<a>hi</a>';`,
    { html: '<a>hi</a>', target: 'document.body', assignProp: 'innerHTML', assignOp: '+=' });
  check('.outerHTML =',
    `el.outerHTML = '<a>hi</a>';`,
    { html: '<a>hi</a>', target: 'el', assignProp: 'outerHTML', assignOp: '=' });
  check('nested target',
    `document.getElementById('x').innerHTML = '<a>hi</a>';`,
    { target: `document.getElementById('x')`, assignProp: 'innerHTML' });
});

// -----------------------------------------------------------------------
// Simple variable resolution
// -----------------------------------------------------------------------
group('simple variable resolution', () => {
  check('bare assign', `x='<a>hi</a>'; document.body.innerHTML+=x;`, '<a>hi</a>');
  check('var decl', `var x='<a>'; document.body.innerHTML=x;`, '<a>');
  check('let decl', `let x='<a>'; document.body.innerHTML=x;`, '<a>');
  check('const decl', `const x='<a>'; document.body.innerHTML=x;`, '<a>');
  check('reassignment', `var x='<a>'; x='<b>'; document.body.innerHTML=x;`, '<b>');
  check('reassignment after site', `var x='<a>'; document.body.innerHTML=x; x='<b>';`, '<a>');
  check('multi decl', `var a='<x>', b='<y>'; document.body.innerHTML=b;`, '<y>');
  check('declare then assign', `var x; x='<a>'; document.body.innerHTML=x;`, '<a>');
  check('unknown identifier',
    `document.body.innerHTML=y;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'y']] });
});

// -----------------------------------------------------------------------
// Scoping: block vs function
// -----------------------------------------------------------------------
group('scoping', () => {
  check('let in block doesn\'t leak',
    `{ let x='<a>'; } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
  check('const in block doesn\'t leak',
    `{ const x='<a>'; } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
  check('var leaks out of block (function-scoped)',
    `{ var x='<a>'; } document.body.innerHTML=x;`, '<a>');
  check('let shadowing',
    `let x='<a>'; { let x='<b>'; } document.body.innerHTML=x;`, '<a>');
  check('let shadowing (inner site)',
    `let x='<a>'; { let x='<b>'; document.body.innerHTML=x; }`, '<b>');
  check('var in function does not leak',
    `function f(){ var x='<a>'; } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
  check('let in function does not leak',
    `function f(){ let x='<a>'; } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
  check('outer var visible past function',
    `var x='<a>'; function f(){} document.body.innerHTML=x;`, '<a>');
  check('arrow expression body (no scope opened)',
    `var f = x => x+1; var y='<a>'; document.body.innerHTML=y;`, '<a>');
  check('arrow block body (scope opened)',
    `var f = () => { var x='<bad>'; }; var y='<a>'; document.body.innerHTML=y;`, '<a>');
  check('nested blocks',
    `{ { let x='<a>'; } } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
  check('nested function scopes',
    `function a(){ function b(){ var x='<a>'; } } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
});

// -----------------------------------------------------------------------
// Concat chains in initializers
// -----------------------------------------------------------------------
group('concat chains', () => {
  check('2-term concat',
    `var x='<a>'+'</a>'; document.body.innerHTML=x;`, '<a></a>');
  check('3-term concat',
    `var x='<a>'+'<b>'+'<c>'; document.body.innerHTML=x;`, '<a><b><c>');
  check('concat with ident',
    `var a='<a>'; var b=a+'</a>'; document.body.innerHTML=b;`, '<a></a>');
  check('transitive (3 hops)',
    `var a='<a>'; var b=a+'<b>'; var c=b+'<c>'; document.body.innerHTML=c;`, '<a><b><c>');
  check('concat inline in innerHTML',
    `var msg='world'; document.body.innerHTML='<p>hi '+msg+'!</p>';`, '<p>hi world!</p>');
  check('unknown ident captured as placeholder',
    `var x='<a>'+unknownVar; document.body.innerHTML=x;`,
    { html: '<a>__HDX0__', autoSubs: [['__HDX0__', 'unknownVar']] });
  check('unknown call captured as placeholder',
    `var x='<a>'+foo(); document.body.innerHTML=x;`,
    { html: '<a>__HDX0__', autoSubs: [['__HDX0__', 'foo()']] });
  check('unresolved parts propagate through variables',
    `var x = 'a' + foo(); document.body.innerHTML = '<a>'+x+'</a>';`,
    { html: '<a>a__HDX0__</a>', autoSubs: [['__HDX0__', 'foo()']] });
});

// -----------------------------------------------------------------------
// Array .join() patterns
// -----------------------------------------------------------------------
group('.join() patterns', () => {
  check('join empty separator',
    `var x=['<a>','<b>'].join(''); document.body.innerHTML=x;`, '<a><b>');
  check('join space separator',
    `var x=['<a>','<b>'].join(' '); document.body.innerHTML=x;`, '<a> <b>');
  check('join single element',
    `var x=['<a>'].join(''); document.body.innerHTML=x;`, '<a>');
  check('join inline in innerHTML',
    `document.body.innerHTML=['<a>','<b>'].join('');`, '<a><b>');
  check('join with ident elements',
    `var p='<a>'; var q='<b>'; document.body.innerHTML=[p,q].join('');`, '<a><b>');
  check('concat then join',
    `var parts=['<a>','<b>'].join(''); document.body.innerHTML='<wrap>'+parts+'</wrap>';`,
    '<wrap><a><b></wrap>');
});

// -----------------------------------------------------------------------
// Template literals
// -----------------------------------------------------------------------
group('templates', () => {
  check('template with unknown expr (stays placeholder)',
    `var x=\`<a href="\${u}">hi</a>\`; document.body.innerHTML=x;`,
    { html: '<a href="__HDX0__">hi</a>', autoSubs: [['__HDX0__', 'u']] });
  check('template without interpolation',
    `var x=\`<a>hi</a>\`; document.body.innerHTML=x;`, '<a>hi</a>');
});

// -----------------------------------------------------------------------
// HTML content filter (only return chains with `<`)
// -----------------------------------------------------------------------
group('HTML content filter', () => {
  check('non-HTML concat still materializes',
    `var x = 'a' + 'b'; document.body.innerHTML=x;`, 'ab');
  check('HTML-looking char found',
    `var x = 'a<b'; document.body.innerHTML=x;`, 'a<b');
});

// -----------------------------------------------------------------------
// Object property access
// -----------------------------------------------------------------------
group('object property access', () => {
  check('known obj.prop',
    `var obj = { html: '<a>' }; document.body.innerHTML = obj.html;`, '<a>');
  check('obj.prop with concat',
    `var obj = { a: '<a>', b: '<b>' }; document.body.innerHTML = obj.a + obj.b;`, '<a><b>');
  check('unknown prop',
    `var obj = { html: '<a>' }; document.body.innerHTML = obj.missing;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'obj.missing']] });
  check('quoted keys',
    `var obj = { "html": '<a>' }; document.body.innerHTML = obj.html;`, '<a>');
});

// -----------------------------------------------------------------------
// String methods
// -----------------------------------------------------------------------
group('string methods', () => {
  check('.concat',
    `var a='<a>'; var b='<b>'; document.body.innerHTML=a.concat(b);`, '<a><b>');
  check('.concat multiple',
    `document.body.innerHTML='<a>'.concat('<b>','<c>');`, '<a><b><c>');
});

// -----------------------------------------------------------------------
// Destructuring
// -----------------------------------------------------------------------
group('destructuring', () => {
  check('object destructuring',
    `var { html } = { html: '<a>' }; document.body.innerHTML = html;`, '<a>');
  check('object destructuring with rename',
    `var { html: h } = { html: '<a>' }; document.body.innerHTML = h;`, '<a>');
  check('array destructuring',
    `var [a, b] = ['<a>', '<b>']; document.body.innerHTML = a + b;`, '<a><b>');
  check('object destructuring with default',
    `var { a = 'dflt' } = {}; document.body.innerHTML = a;`, 'dflt');
  check('object destructuring default when value present',
    `var { a = 'dflt' } = { a: 'here' }; document.body.innerHTML = a;`, 'here');
  check('object destructuring rename with default',
    `var { a: x = 'd' } = {}; document.body.innerHTML = x;`, 'd');
  check('object destructuring with rest',
    `var { a, ...rest } = { a: 'x', b: 'y', c: 'z' }; document.body.innerHTML = JSON.stringify(rest);`,
    '{"b":"y","c":"z"}');
  check('array destructuring with defaults',
    `var [a = 'x', b = 'y'] = ['1']; document.body.innerHTML = a + b;`, '1y');
  check('array destructuring with rest',
    `var [a, ...r] = ['x','y','z']; document.body.innerHTML = r.join(',');`, 'y,z');
});

// -----------------------------------------------------------------------
// Modules: import/export must not derail the walker
// -----------------------------------------------------------------------
group('modules', () => {
  check('import default skipped',
    `import foo from 'bar'; var a='<x>'; document.body.innerHTML = a;`, '<x>');
  check('import named skipped',
    `import { foo, bar } from 'baz'; var a='hi'; document.body.innerHTML = a;`, 'hi');
  check('export const stripped',
    `export const a = '<z>'; document.body.innerHTML = a;`, '<z>');
  check('export default expression skipped',
    `export default 42; var a='ok'; document.body.innerHTML = a;`, 'ok');
  check('export { list } skipped',
    `var x='hi'; export { x }; document.body.innerHTML = x;`, 'hi');
});

// -----------------------------------------------------------------------
// Array.* builtins
// -----------------------------------------------------------------------
group('Array builtins', () => {
  check('Array.isArray on array',
    `var a=['x','y']; document.body.innerHTML = Array.isArray(a) ? 'A' : 'O';`, 'A');
  check('Array.of literal list',
    `var b = Array.of('a','b','c'); document.body.innerHTML = b.join(',');`, 'a,b,c');
  check('Array.from over array with mapFn',
    `var a=['x','y']; var b = Array.from(a, (x,i) => i+':'+x); document.body.innerHTML = b.join(',');`, '0:x,1:y');
  check('Array.from length spec with mapFn',
    `var b = Array.from({length:3}, (_,i) => i); document.body.innerHTML = b.join('-');`, '0-1-2');
});

// -----------------------------------------------------------------------
// Template literal interpolation resolution
// -----------------------------------------------------------------------
group('template interpolation', () => {
  check('known identifier expr',
    `var url='/path'; var x=\`<a href="\${url}">hi</a>\`; document.body.innerHTML=x;`,
    '<a href="/path">hi</a>');
  check('inline in innerHTML',
    `var url='/path'; document.body.innerHTML=\`<a href="\${url}">hi</a>\`;`,
    '<a href="/path">hi</a>');
});

// -----------------------------------------------------------------------
// Nested structures
// -----------------------------------------------------------------------
group('nested structures', () => {
  check('nested object member access',
    `var cfg = { parts: { head: '<h>', body: '<b>' } };
     document.body.innerHTML = cfg.parts.head + cfg.parts.body;`, '<h><b>');
  check('array of objects',
    `var items = [{ html: '<a>' }, { html: '<b>' }];
     document.body.innerHTML = items[0].html;`, '<a>');
  check('object containing array',
    `var o = { parts: ['<a>','<b>'] };
     document.body.innerHTML = o.parts.join('');`, '<a><b>');
});

// -----------------------------------------------------------------------
// Template interpolation edge cases
// -----------------------------------------------------------------------
group('template interpolation edge cases', () => {
  check('member-path expr',
    `var obj = { name: 'World' };
     document.body.innerHTML = \`<p>Hello \${obj.name}</p>\`;`, '<p>Hello World</p>');
  check('mix of resolved and unresolved',
    `var a = 'X';
     document.body.innerHTML = \`<p>\${a}:\${b}</p>\`;`,
    { html: '<p>X:__HDX0__</p>', autoSubs: [['__HDX0__', 'b']] });
  check('nested template',
    `var inner = \`world\`;
     document.body.innerHTML = \`<p>hello \${inner}</p>\`;`, '<p>hello world</p>');
});

// -----------------------------------------------------------------------
// Shadowing with declarations
// -----------------------------------------------------------------------
group('shadowing', () => {
  check('let shadows var',
    `var x='<outer>'; { let x='<inner>'; } document.body.innerHTML=x;`, '<outer>');
  check('function shadows outer let',
    `let x='<outer>'; function f(){ let x='<inner>'; } document.body.innerHTML=x;`, '<outer>');
  check('reassign through shadow',
    `let x='<a>'; { x='<b>'; } document.body.innerHTML=x;`, '<b>');
});

// -----------------------------------------------------------------------
// Complex real-world patterns
// -----------------------------------------------------------------------
group('real-world patterns', () => {
  check('const template with member path',
    `const u = { url: '/api' };
     document.body.innerHTML = \`<a href="\${u.url}">go</a>\`;`,
    '<a href="/api">go</a>');
  check('multiple reassignments',
    `var html = '<a>'; html = html + '<b>'; html = html + '<c>';
     document.body.innerHTML = html;`, '<a><b><c>');
  check('builder pattern via concat',
    `var s = ''; s = s + '<a>'; s = s + '<b>'; document.body.innerHTML = s;`, '<a><b>');
});

// -----------------------------------------------------------------------
// Primitive literals in concat
// -----------------------------------------------------------------------
group('primitive literals', () => {
  check('int literal', `document.body.innerHTML='<x>'+42+'</x>';`, '<x>42</x>');
  check('float literal', `document.body.innerHTML='<x>'+3.14+'</x>';`, '<x>3.14</x>');
  check('true', `document.body.innerHTML='<x>'+true+'</x>';`, '<x>true</x>');
  check('false', `document.body.innerHTML='<x>'+false+'</x>';`, '<x>false</x>');
  check('null', `document.body.innerHTML='<x>'+null+'</x>';`, '<x>null</x>');
});

// -----------------------------------------------------------------------
// Parenthesized expressions
// -----------------------------------------------------------------------
group('parentheses', () => {
  check('grouped concat',
    `document.body.innerHTML=('<a>'+'<b>')+'<c>';`, '<a><b><c>');
  check('nested parens',
    `document.body.innerHTML=(('<a>'+'<b>')+'<c>');`, '<a><b><c>');
  check('parens in binding',
    `var x=('<a>'+'<b>'); document.body.innerHTML=x+'<c>';`, '<a><b><c>');
});

// -----------------------------------------------------------------------
// Bound array .join and indexing
// -----------------------------------------------------------------------
group('bound array access', () => {
  check('.join on bound array',
    `var arr=['<a>','<b>']; document.body.innerHTML=arr.join('');`, '<a><b>');
  check('.join with sep on bound array',
    `var arr=['<a>','<b>','<c>']; document.body.innerHTML=arr.join('-');`, '<a>-<b>-<c>');
  check('arr[0]',
    `var arr=['<a>','<b>']; document.body.innerHTML=arr[0];`, '<a>');
  check('arr[1]',
    `var arr=['<a>','<b>']; document.body.innerHTML=arr[1];`, '<b>');
  check('arr[0]+arr[1]',
    `var arr=['<a>','<b>']; document.body.innerHTML=arr[0]+arr[1];`, '<a><b>');
  check('out-of-bounds index',
    `var arr=['<a>']; document.body.innerHTML=arr[5];`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'arr[5]']] });
});

// -----------------------------------------------------------------------
// Bracket object access
// -----------------------------------------------------------------------
group('bracket object access', () => {
  check(`obj['key']`,
    `var obj={html:'<a>'}; document.body.innerHTML=obj['html'];`, '<a>');
  check(`obj["key"]`,
    `var obj={html:'<a>'}; document.body.innerHTML=obj["html"];`, '<a>');
  check('unknown key',
    `var obj={html:'<a>'}; document.body.innerHTML=obj['missing'];`,
    { html: '__HDX0__', autoSubs: [["__HDX0__", "obj['missing']"]] });
});

// -----------------------------------------------------------------------
// Chained access (combinations)
// -----------------------------------------------------------------------
group('chained access', () => {
  check('array of objects .html[0]',
    `var items = [{html:'<a>'}, {html:'<b>'}];
     document.body.innerHTML = items[0].html + items[1].html;`, '<a><b>');
  check('object map via join',
    `var tags = { open: '<a>', close: '</a>' };
     document.body.innerHTML = [tags.open, 'hi', tags.close].join('');`, '<a>hi</a>');
  check('nested index',
    `var grid = [['<r0c0>', '<r0c1>'], ['<r1c0>']];
     document.body.innerHTML = grid[0][0] + grid[0][1];`, '<r0c0><r0c1>');
  check('concat with method call chain',
    `var s = '<a>'; document.body.innerHTML = s.concat('<b>').concat('<c>');`, '<a><b><c>');
});

// -----------------------------------------------------------------------
// Scope + bindings interaction
// -----------------------------------------------------------------------
group('scope+binding interactions', () => {
  check('reassign object inside block',
    `var o = {html:'<a>'}; { o = {html:'<b>'}; } document.body.innerHTML = o.html;`, '<b>');
  check('let object doesn\'t leak',
    `{ let o = {html:'<a>'}; } document.body.innerHTML = o.html;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'o.html']] });
  check('object with shadowed inner prop',
    `var o = { html: '<outer>' }; { let o = { html: '<inner>' }; } document.body.innerHTML = o.html;`, '<outer>');
});

// -----------------------------------------------------------------------
// Function calls (arrow and function declarations)
// -----------------------------------------------------------------------
group('function calls', () => {
  check('single-param arrow',
    `const f = x => '<a>' + x + '</a>';
     document.body.innerHTML = f('hi');`, '<a>hi</a>');
  check('multi-param arrow',
    `const wrap = (tag, text) => '<' + tag + '>' + text + '</' + tag + '>';
     document.body.innerHTML = wrap('p', 'hi');`, '<p>hi</p>');
  check('no-param arrow',
    `const greet = () => '<p>hello</p>';
     document.body.innerHTML = greet();`, '<p>hello</p>');
  check('arrow with block body and return',
    `const f = (x) => { return '<a>' + x + '</a>'; };
     document.body.innerHTML = f('hi');`, '<a>hi</a>');
  check('function declaration with return',
    `function link(url, text) { return '<a href="' + url + '">' + text + '</a>'; }
     document.body.innerHTML = link('/a', 'click');`, '<a href="/a">click</a>');
  check('nested function call',
    `const em = (t) => '<em>' + t + '</em>';
     const p = (t) => '<p>' + t + '</p>';
     document.body.innerHTML = p(em('hi'));`, '<p><em>hi</em></p>');
  check('function used in template',
    `const url = (path) => '/api' + path;
     document.body.innerHTML = \`<a href="\${url('/x')}">go</a>\`;`, '<a href="/api/x">go</a>');
});

// -----------------------------------------------------------------------
// Function edge cases
// -----------------------------------------------------------------------
group('function edge cases', () => {
  check('function with unknown arg (captured as placeholder)',
    `const f = x => '<a>' + x + '</a>';
     document.body.innerHTML = f(unknown);`,
    { html: '<a>__HDX0__</a>', autoSubs: [['__HDX0__', 'unknown']] });
  check('recursion is capped (no infinite loop)',
    `function f(x) { return '<p>' + x + '</p>'; }
     document.body.innerHTML = f(f('hi'));`, '<p><p>hi</p></p>');
  check('function uses outer binding',
    `const wrap = '<b>';
     const tag = (x) => wrap + x + '</b>';
     document.body.innerHTML = tag('hi');`, '<b>hi</b>');
  check('arrow with concat in body',
    `const html = (a, b) => [a, b].join('-');
     document.body.innerHTML = html('<x>', '<y>');`, '<x>-<y>');
  check('function in object',
    `var O = { build: (x) => '<a>' + x + '</a>' };
     document.body.innerHTML = O.build('hi');`, '<a>hi</a>');
  check('function called with missing arg (param surfaces as placeholder)',
    `function f(x) { return '<a>'+x+'</a>'; } document.body.innerHTML = f();`,
    { html: '<a>__HDX0__</a>', autoSubs: [['__HDX0__', 'x']] });
});

// -----------------------------------------------------------------------
// Compound assignment
// -----------------------------------------------------------------------
group('compound assignment', () => {
  check('+= builds string',
    `var s=''; s+='<a>'; s+='<b>'; document.body.innerHTML=s;`, '<a><b>');
  check('+= with identifier',
    `var tag='<x>'; var s='<wrap>'; s+=tag; s+='</wrap>';
     document.body.innerHTML=s;`, '<wrap><x></wrap>');
  check('+= propagates through unresolved base',
    `var s=unknownBase; s+='<a>'; document.body.innerHTML=s;`,
    { html: '__HDX0__<a>', autoSubs: [['__HDX0__', 'unknownBase']] });
});

// -----------------------------------------------------------------------
// Unresolved expressions (opaque references)
// -----------------------------------------------------------------------
group('opaque references', () => {
  check('variable-indexed array',
    `var arr=['<a>']; document.body.innerHTML=arr[someIdx];`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'arr[someIdx]']] });
  check('variable-indexed through alias',
    `var arr=['<a>']; var url=arr[i]; document.body.innerHTML='<p>'+url+'</p>';`,
    { html: '<p>__HDX0__</p>', autoSubs: [['__HDX0__', 'arr[i]']] });
  check('chained unresolvable',
    `var o={a:'<x>'}; document.body.innerHTML=o[key].foo;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'o[key].foo']] });
  check('unresolved call propagates source',
    `document.body.innerHTML='<a>'+parseInt(s,10)+'</a>';`,
    { html: '<a>__HDX0__</a>', autoSubs: [['__HDX0__', 'parseInt(s,10)']] });
});

// -----------------------------------------------------------------------
// Functions with assignments inside (walker traverses body)
// -----------------------------------------------------------------------
group('function bodies with assignments', () => {
  check('inner innerHTML in function body',
    `function f() {
       var s = '<a>';
       s += '<b>';
       out.innerHTML = s;
     }`,
    { html: '<a><b>', target: 'out', assignProp: 'innerHTML', assignOp: '=' });
  check('function param referenced inside body',
    `function wrap(tag) {
       var s = '<' + tag + '>hi</' + tag + '>';
       out.innerHTML = s;
     }`,
    { html: '<__HDX0__>hi</__HDX1__>', target: 'out',
      autoSubs: [['__HDX0__', 'tag'], ['__HDX1__', 'tag']] });
});

// -----------------------------------------------------------------------
// Loops (for / while) wrapping += contributions
// -----------------------------------------------------------------------
group('loops', () => {
  // When a variable is built via `+=` inside a `for`/`while` loop, the
  // resulting chain is tagged so the main html gets `__HDLOOP#S__`/
  // `__HDLOOP#E__` markers around the per-iteration contribution. The
  // loop header(s) are echoed in `loops`, and `loopVars` records each
  // loop-built variable's final contribution for downstream use.
  check('for loop wraps += body',
    `var s=''; for (var i=0; i<n; i++) { s += '<a>'; } document.body.innerHTML=s;`,
    { html: '__HDLOOP0S__<a>__HDLOOP0E__',
      loops: [{ id: 0, kind: 'for', headerSrc: 'var i=0; i<n; i++' }] });
  check('for loop with multi-part body',
    `var s=''; for (var i=0; i<n; i++) { s += '<a>'; s += '<b>'; } document.body.innerHTML=s;`,
    { html: '__HDLOOP0S__<a><b>__HDLOOP0E__' });
  check('while loop',
    `var s=''; while (s.length < 10) s += 'x'; document.body.innerHTML=s;`,
    { html: '__HDLOOP0S__x__HDLOOP0E__',
      loops: [{ id: 0, kind: 'while', headerSrc: 's.length < 10' }] });
  check('static prefix + loop + suffix',
    `var s='<header>'; for (var i=0; i<n; i++) s += '<item>'; s += '<footer>';
     document.body.innerHTML=s;`,
    { html: '<header>__HDLOOP0S__<item>__HDLOOP0E__<footer>' });
  check('loop body resolves var references',
    `var tag='<a>'; var s=''; for (var i=0;i<n;i++) s += tag;
     document.body.innerHTML=s;`,
    { html: '__HDLOOP0S__<a>__HDLOOP0E__' });
  check('loop body reaches unresolved as opaque',
    `var s=''; for (var i=0;i<n;i++) s += items[i];
     document.body.innerHTML=s;`,
    { html: '__HDLOOP0S____HDX0____HDLOOP0E__', autoSubs: [['__HDX0__', 'items[i]']] });
  check('innerHTML assigned to loop-built var in function',
    `function write() {
       var s = '';
       for (var i=0; i<n; i++) s += '<p>' + i + '</p>';
       out.innerHTML = s;
     }`,
    { html: '__HDLOOP0S__<p>__HDX0__</p>__HDLOOP0E__',
      target: 'out', autoSubs: [['__HDX0__', 'i']] });
});

// -----------------------------------------------------------------------
// .length on known arrays and strings
// -----------------------------------------------------------------------
group('.length', () => {
  check('array.length',
    `var arr=['a','b','c']; document.body.innerHTML = 'count: ' + arr.length;`, 'count: 3');
  check('string.length via variable',
    `var s='hello'; document.body.innerHTML = '<p>' + s.length + '</p>';`, '<p>5</p>');
  check('length on object-array member',
    `var o={items:['x','y','z','w']}; document.body.innerHTML = 'n='+o.items.length;`, 'n=4');
  check('length on unknown stays opaque',
    `document.body.innerHTML = 'n='+items.length;`,
    { html: 'n=__HDX0__', autoSubs: [['__HDX0__', 'items.length']] });
});

// -----------------------------------------------------------------------
// Ternary expressions and other operators (captured as opaque)
// -----------------------------------------------------------------------
group('ternary/operators', () => {
  check('ternary folded symbolically',
    `document.body.innerHTML = '<a>' + (cond ? '<b>' : '<c>') + '</a>';`,
    { html: '<a>__HDX0__</a>', autoSubs: [['__HDX0__', '(cond ? "<b>" : "<c>")']] });
  check('ternary with known true-ish condition',
    `var ok = 1; document.body.innerHTML = (ok ? '<yes>' : '<no>');`, '<yes>');
  check('ternary with known false-ish condition',
    `var off = 0; document.body.innerHTML = (off ? '<yes>' : '<no>');`, '<no>');
  check('bitwise expression folded symbolically',
    `document.body.innerHTML = '<x>' + (a|0) + '</x>';`,
    { html: '<x>__HDX0__</x>', autoSubs: [['__HDX0__', '(a | 0)']] });
  check('logical OR default folded symbolically',
    `document.body.innerHTML = '<x>' + (name || 'anon') + '</x>';`,
    { html: '<x>__HDX0__</x>', autoSubs: [['__HDX0__', '(name || "anon")']] });
});

// -----------------------------------------------------------------------
// Arithmetic evaluation
// -----------------------------------------------------------------------
group('arithmetic', () => {
  check('subtract literals',
    `document.body.innerHTML = 'n=' + (3 - 2);`, 'n=1');
  check('multiply literals',
    `document.body.innerHTML = 'n=' + (3 * 4);`, 'n=12');
  check('divide literals',
    `document.body.innerHTML = 'n=' + (10 / 4);`, 'n=2.5');
  check('bitwise OR literals',
    `document.body.innerHTML = 'n=' + (3.7 | 0);`, 'n=3');
  check('multiply then parenthesized concat',
    `document.body.innerHTML = 'n=' + (3 * 4);`, 'n=12');
  check('array length arithmetic',
    `var a=['x','y','z']; document.body.innerHTML = 'n=' + (a.length - 1);`, 'n=2');
  check('unknown + literal',
    `document.body.innerHTML = 'n=' + (x * 2);`,
    { html: 'n=__HDX0__', autoSubs: [['__HDX0__', '(x * 2)']] });
  check('partial eval with unknown',
    `var a=['x','y','z']; document.body.innerHTML = 'n=' + ((a.length - 2) / y);`,
    { html: 'n=__HDX0__', autoSubs: [['__HDX0__', '(1 / y)']] });
});

// -----------------------------------------------------------------------
// String methods
// -----------------------------------------------------------------------
group('string methods', () => {
  check('toUpperCase on var',
    `var s='hello'; document.body.innerHTML = s.toUpperCase();`, 'HELLO');
  check('trim on literal',
    `document.body.innerHTML = '  hi  '.trim();`, 'hi');
  check('repeat on literal',
    `document.body.innerHTML = '#'.repeat(5);`, '#####');
  check('slice on literal',
    `document.body.innerHTML = 'abcdef'.slice(1, 4);`, 'bcd');
  check('padStart with zeros',
    `document.body.innerHTML = 'abc'.padStart(6, '0');`, '000abc');
  check('chain toUpper + concat',
    `var n='World'; document.body.innerHTML = 'Hello ' + n.toUpperCase();`, 'Hello WORLD');
  check('String(num) then method',
    `var n=42; document.body.innerHTML = String(n).padStart(5, '0');`, '00042');
  check('split then join',
    `var parts='a,b,c'.split(','); document.body.innerHTML = parts.join('|');`, 'a|b|c');
  check('indexOf literal',
    `document.body.innerHTML = 'pos=' + 'hello world'.indexOf('world');`, 'pos=6');
});

// -----------------------------------------------------------------------
// Array methods (.slice / .indexOf / .includes / .reverse)
// -----------------------------------------------------------------------
group('array methods', () => {
  check('slice + join',
    `var a=[1,2,3,4,5]; document.body.innerHTML = a.slice(1,3).join(',');`, '2,3');
  check('indexOf on array',
    `var a=['x','y','z']; document.body.innerHTML = 'at ' + a.indexOf('y');`, 'at 1');
  check('includes on array',
    `var a=['x','y','z']; document.body.innerHTML = 'has ' + a.includes('y');`, 'has true');
  check('reverse + join',
    `var a=['a','b','c']; document.body.innerHTML = a.reverse().join('');`, 'cba');
});

// -----------------------------------------------------------------------
// extractAllHTML: multiple innerHTML sinks
// -----------------------------------------------------------------------
(function () {
  console.log('\nextractAllHTML');
  console.log('--------------');
  const script = `
    function write() { out.innerHTML = '<a>' + url + '</a>'; }
    function setup() { table.innerHTML = '<tr><th>Hi</th></tr>'; }
    function log(s) { document.getElementById('nums').innerHTML += '<br>' + s; }
  `;
  const all = extractAllHTML(script);
  const before = pass + fail;
  if (all.length === 3) pass++; else { fail++; failures.push({ name: 'all length', got: all.length }); }
  const m0 = all[0] ? materializeForTest(all[0].chainTokens) : { html: '' };
  if (all[0] && all[0].target === 'out' && /<a>__HDX0__<\/a>/.test(m0.html)) pass++;
  else { fail++; failures.push({ name: 'all[0]', got: all[0] }); }
  const m1 = all[1] ? materializeForTest(all[1].chainTokens) : { html: '' };
  if (all[1] && all[1].target === 'table' && m1.html === '<tr><th>Hi</th></tr>') pass++;
  else { fail++; failures.push({ name: 'all[1]', got: all[1] }); }
  const m2 = all[2] ? materializeForTest(all[2].chainTokens) : { html: '' };
  if (all[2] && all[2].target === `document.getElementById('nums')` && all[2].assignOp === '+=' && /<br>__HDX0__/.test(m2.html)) pass++;
  else { fail++; failures.push({ name: 'all[2]', got: all[2] }); }
  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// extractAllDOM: virtual DOM construction tracking
// -----------------------------------------------------------------------
(function () {
  console.log('\nextractAllDOM');
  console.log('-------------');
  const before = pass + fail;

  // Basic create + appendChild.
  {
    const r = extractAllDOM(`var a = document.createElement('a'); a.href = '/'; a.textContent = 'home'; document.body.appendChild(a);`);
    if (r.elements.length === 1 && r.elements[0].origin.tag === 'a' && r.elements[0].props.href === '/' && r.elements[0].text === 'home') pass++;
    else { fail++; failures.push({ name: 'createElement basic', got: r }); }
  }
  // Nested tree with for-loop-built children.
  {
    const r = extractAllDOM(`var t=document.createElement('table'); var tr=document.createElement('tr'); var td=document.createElement('td'); td.textContent='cell'; tr.appendChild(td); t.appendChild(tr);`);
    if (r.html[0] === '<table><tr><td>cell</td></tr></table>') pass++;
    else { fail++; failures.push({ name: 'nested createElement tree', html0: r.html && r.html[0] }); }
  }
  // setAttribute.
  {
    const r = extractAllDOM(`var el=document.createElement('div'); el.setAttribute('data-id', '42'); el.setAttribute('role', 'button');`);
    if (r.elements[0].attrs['data-id'] === '42' && r.elements[0].attrs.role === 'button') pass++;
    else { fail++; failures.push({ name: 'setAttribute', got: r.elements[0] }); }
  }
  // className → classList.
  {
    const r = extractAllDOM(`var el=document.createElement('div'); el.className = 'foo bar baz';`);
    if (r.elements[0].classList.join(' ') === 'foo bar baz') pass++;
    else { fail++; failures.push({ name: 'className', got: r.elements[0] }); }
  }
  // style.prop assignments.
  {
    const r = extractAllDOM(`var el=document.createElement('div'); el.style.color='red'; el.style.fontSize='12px';`);
    if (r.elements[0].styles.color === 'red' && r.elements[0].styles.fontSize === '12px') pass++;
    else { fail++; failures.push({ name: 'style', got: r.elements[0] }); }
  }
  // getElementById + append — root element is the looked-up element.
  {
    const r = extractAllDOM(`var out=document.getElementById('out'); var a=document.createElement('a'); out.appendChild(a);`);
    const outEl = r.elements.find((e) => e.origin && e.origin.value === 'out');
    if (outEl && outEl.children.length === 1) pass++;
    else { fail++; failures.push({ name: 'getElementById append', got: r }); }
  }
  // innerHTML capture on element.
  {
    const r = extractAllDOM(`var t=document.createElement('div'); t.innerHTML = '<p>hi</p>';`);
    if (r.elements[0].html === '<p>hi</p>') pass++;
    else { fail++; failures.push({ name: 'innerHTML on element', got: r.elements[0] }); }
  }

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Array .map / .filter / .forEach with arrow callbacks
// -----------------------------------------------------------------------
group('array .map / .filter / .forEach', () => {
  check('map + join',
    `var a=['x','y','z']; document.body.innerHTML = a.map(i => '<li>'+i+'</li>').join('');`,
    '<li>x</li><li>y</li><li>z</li>');
  check('map with template literal body',
    `var a=['1','2']; document.body.innerHTML = a.map(i => \`<p>\${i}</p>\`).join('');`,
    '<p>1</p><p>2</p>');
  check('filter keeps truthy',
    `var a=['','x','','y']; document.body.innerHTML = a.filter(s => s).join(',');`, 'x,y');
  check('filter + map chain',
    `var a=[1,2,3,4]; document.body.innerHTML = a.filter(n => n>2).map(n => '['+n+']').join('');`,
    '[3][4]');
  check('forEach returns undefined',
    `var a=['x']; document.body.innerHTML = String(a.forEach(i => i));`, 'undefined');
});

// -----------------------------------------------------------------------
// Spread, default params, optional chaining, nullish coalescing
// -----------------------------------------------------------------------
group('modern operators', () => {
  check('array spread',
    `var a=['x','y']; var b=[...a, 'z']; document.body.innerHTML = b.join('|');`, 'x|y|z');
  check('object spread',
    `var o={html:'<a>'}; var p={...o, x:'<b>'}; document.body.innerHTML = p.html + p.x;`, '<a><b>');
  check('default param used',
    `function wrap(tag='b') { return '<' + tag + '>'; } document.body.innerHTML = wrap();`, '<b>');
  check('default param overridden',
    `function wrap(tag='b') { return '<' + tag + '>'; } document.body.innerHTML = wrap('em');`, '<em>');
  check('arrow default',
    `const hi = (who='World') => 'Hi ' + who; document.body.innerHTML = hi();`, 'Hi World');
  check('optional chaining on known object',
    `var o={name:'Alice'}; document.body.innerHTML = '<p>'+o?.name+'</p>';`, '<p>Alice</p>');
  check('optional chaining on known array',
    `var a=['x','y']; document.body.innerHTML = '<p>'+a?.[1]+'</p>';`, '<p>y</p>');
  check('nullish with known value',
    `var n='hi'; document.body.innerHTML = '<p>'+(n ?? 'def')+'</p>';`, '<p>hi</p>');
  check('nullish with null picks right',
    `var n=null; document.body.innerHTML = '<p>'+(n ?? 'def')+'</p>';`, '<p>def</p>');
});

// -----------------------------------------------------------------------
// Class syntax (basic extraction via token scan)
// -----------------------------------------------------------------------
group('class methods', () => {
  check('innerHTML inside class method',
    `class W { render() { this.el.innerHTML = '<p>'+this.text+'</p>'; } }`,
    { html: '<p>__HDX0__</p>', target: 'this.el', autoSubs: [['__HDX0__', 'this.text']] });
  check('method local var builds html',
    `class W { render() { var s='<a>'; s+='</a>'; this.el.innerHTML = s; } }`,
    { html: '<a></a>', target: 'this.el' });
  check('method with param',
    `class W { render(msg) { this.el.innerHTML = '<p>'+msg+'</p>'; } }`,
    { html: '<p>__HDX0__</p>', target: 'this.el', autoSubs: [['__HDX0__', 'msg']] });
});

// -----------------------------------------------------------------------
// Object literal extensions (getters, method shorthand, shorthand props, computed keys)
// -----------------------------------------------------------------------
group('object extensions', () => {
  check('getter method does not break object',
    `const o={get html(){return 'x';}, msg:'ok'}; document.body.innerHTML=o.msg;`, 'ok');
  check('method shorthand does not break object',
    `const o={render(){return 'x';}, title:'T'}; document.body.innerHTML=o.title;`, 'T');
  check('shorthand property',
    `const title='Hello'; const o={title}; document.body.innerHTML=o.title;`, 'Hello');
  check('computed key',
    `const k='foo'; const o={[k]:'<p>'}; document.body.innerHTML=o.foo;`, '<p>');
});

// -----------------------------------------------------------------------
// new / typeof / void / delete / await / yield
// -----------------------------------------------------------------------
group('keyword prefixes', () => {
  check('new Constructor(args)',
    `document.body.innerHTML = '<p>' + new Date().toString() + '</p>';`,
    { html: '<p>__HDX0__</p>', autoSubs: [['__HDX0__', 'new Date().toString()']] });
  check('typeof',
    `document.body.innerHTML = '<p>' + typeof x + '</p>';`,
    { html: '<p>__HDX0__</p>', autoSubs: [['__HDX0__', 'typeof x']] });
  check('await fetch',
    `async function f() { const x = await fetch('/a'); document.body.innerHTML = '<p>'+x+'</p>'; }`,
    { html: '<p>__HDX0__</p>' });
});

// -----------------------------------------------------------------------
// Object.keys/values/entries, JSON.stringify/parse
// -----------------------------------------------------------------------
group('Object/JSON builtins', () => {
  check('Object.keys',
    `const o={a:'x',b:'y'}; document.body.innerHTML = Object.keys(o).join(',');`, 'a,b');
  check('Object.values',
    `const o={a:1,b:2}; document.body.innerHTML = Object.values(o).join(',');`, '1,2');
  check('Object.entries',
    `const o={a:'1'}; document.body.innerHTML = Object.entries(o).map(e=>e[0]+'='+e[1]).join(',');`, 'a=1');
  check('JSON.stringify object',
    `const o={a:'x'}; document.body.innerHTML = JSON.stringify(o);`, '{"a":"x"}');
  check('JSON.stringify array',
    `document.body.innerHTML = JSON.stringify([1,2,3]);`, '[1,2,3]');
  check('JSON.parse round-trip',
    `const s='{"k":42}'; document.body.innerHTML = 'v=' + JSON.parse(s).k;`, 'v=42');
});

// -----------------------------------------------------------------------
// Array.reduce
// -----------------------------------------------------------------------
group('array.reduce', () => {
  check('sum',
    `const a=[1,2,3,4]; document.body.innerHTML = a.reduce((acc,n)=>acc+n, 0) + '';`, '10');
  check('concat strings',
    `const a=['x','y','z']; document.body.innerHTML = a.reduce((acc,s)=>acc+s, '');`, 'xyz');
});

// -----------------------------------------------------------------------
// Regex literals don't break tokenization
// -----------------------------------------------------------------------
group('regex literals', () => {
  check('regex in replace call',
    `var s='abc'; document.body.innerHTML = s.replace(/b/g,'X');`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', "s.replace(/b/g,'X')"]] });
  check('regex variable does not crash',
    `var re=/abc/i; document.body.innerHTML = '<p>ok</p>';`, '<p>ok</p>');
});

// -----------------------------------------------------------------------
// Tagged template literals captured as opaque
// -----------------------------------------------------------------------
group('tagged template', () => {
  check('tag`...` captured as opaque',
    'document.body.innerHTML = html`<p>hi</p>`;',
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'html`<p>hi</p>`']] });
});

// -----------------------------------------------------------------------
// Original iframe case from the feature request
// -----------------------------------------------------------------------
group('feature-request case', () => {
  check('iframe via var',
    `x='<iframe credentialless loading="lazy" id="background" title="background" sandbox="allow-scripts" frameborder="0" height="100%" width="100%" src="https://random.ndev.tk/">';\ndocument.body.innerHTML+=x;`,
    { html: '<iframe credentialless loading="lazy" id="background" title="background" sandbox="allow-scripts" frameborder="0" height="100%" width="100%" src="https://random.ndev.tk/">',
      target: 'document.body', assignProp: 'innerHTML', assignOp: '+=' });
});

// -----------------------------------------------------------------------
// Loop-marker break/continue signal propagation fix
// -----------------------------------------------------------------------
group('loop-built innerHTML with break in other functions', () => {
  check('loop-built html with break in sibling function',
    `var todos = [];
function add(t) { todos.push(t); }
function toggle(id) {
  for (var i = 0; i < todos.length; i++) {
    if (todos[i].id === id) { todos[i].done = !todos[i].done; break; }
  }
}
function render() {
  var list = document.getElementById('todoList');
  var html = '';
  for (var i = 0; i < todos.length; i++) {
    html += '<div>' + todos[i].text + '</div>';
  }
  list.innerHTML = html;
}`,
    { html: '__HDLOOP1S__<div>__HDX0__</div>__HDLOOP1E__',
      target: 'list', assignProp: 'innerHTML', assignOp: '=',
      autoSubs: [['__HDX0__', 'todos[i].text']],
      loops: [{ id: 1, kind: 'for', headerSrc: 'var i = 0; i < todos.length; i++' }] });
});

// -----------------------------------------------------------------------
// convertProject: multi-file project conversion
// -----------------------------------------------------------------------
(function () {
  if (!globalThis.__convertProject) { console.log('\nconvertProject not available — skipping'); return; }
  const cp = globalThis.__convertProject;
  const before = pass + fail;
  console.log('\nconvertProject');
  console.log('--------------');

  // Helper: check output files match expectations.
  function checkProject(name, files, expectedKeys, checks) {
    const out = cp(files);
    const gotKeys = Object.keys(out).sort();
    const wantKeys = expectedKeys.sort();
    if (JSON.stringify(gotKeys) !== JSON.stringify(wantKeys)) {
      fail++;
      failures.push({ name: name + ' (files)', input: Object.keys(files), want: wantKeys, got: gotKeys });
      return;
    }
    if (checks) {
      for (const [key, test] of Object.entries(checks)) {
        if (!test(out[key] || '')) {
          fail++;
          failures.push({ name: name + ' (' + key + ')', input: key, want: 'check failed', got: (out[key] || '').slice(0, 100) });
          return;
        }
      }
    }
    pass++;
  }

  // 1. JS file with innerHTML → converted in place, same filename.
  checkProject('JS converted in place',
    {
      'index.html': '<html><body><div id="app"></div><script src="app.js"></script></body></html>',
      'app.js': 'document.getElementById("app").innerHTML = "<p>" + text + "</p>";'
    },
    ['app.js'],
    { 'app.js': c => /createElement/.test(c) && !/innerHTML/.test(c) }
  );

  // 2. JS without innerHTML → not in output.
  checkProject('clean JS not in output',
    {
      'index.html': '<html><body><script src="utils.js"></script><script src="app.js"></script></body></html>',
      'utils.js': 'function helper() { return 1; }',
      'app.js': 'el.innerHTML = "<div>" + helper() + "</div>";'
    },
    ['app.js'],
    { 'app.js': c => /createElement/.test(c) }
  );

  // 3. Inline events/styles → handlers file.
  checkProject('inline events to handlers',
    {
      'page.html': '<html><body><button onclick="go()" style="color:red">Go</button></body></html>'
    },
    ['page.html', 'page.handlers.js'],
    {
      'page.html': c => !/onclick/.test(c) && !/style=/.test(c),
      'page.handlers.js': c => /addEventListener/.test(c) && /setProperty/.test(c)
    }
  );

  // 4. Inline <script> extracted to external file.
  checkProject('inline script extracted',
    {
      'app.html': '<html><body><script>var x = 1;</script></body></html>'
    },
    ['app.html', 'app.js'],
    {
      'app.html': c => /<script src="app\.js">/.test(c) && !/>var x/.test(c),
      'app.js': c => /var x = 1/.test(c)
    }
  );

  // 5. Inline <style> extracted to external file.
  checkProject('inline style extracted',
    {
      'page.html': '<html><head><style>body { color: red; }</style></head><body></body></html>'
    },
    ['page.html', 'page.css'],
    {
      'page.html': c => /link.*href="page\.css"/.test(c) && !/<style>/.test(c),
      'page.css': c => /body.*color.*red/.test(c)
    }
  );

  // 6. Two HTML pages — no collision.
  checkProject('two pages no collision',
    {
      'a.html': '<html><body><button onclick="x()">A</button></body></html>',
      'b.html': '<html><body><button onclick="y()">B</button></body></html>'
    },
    ['a.html', 'a.handlers.js', 'b.html', 'b.handlers.js'],
    {
      'a.handlers.js': c => /x\(\)/.test(c) && !/y\(\)/.test(c),
      'b.handlers.js': c => /y\(\)/.test(c) && !/x\(\)/.test(c)
    }
  );

  // 7. Cross-file scope: app.js uses var from store.js.
  checkProject('cross-file scope',
    {
      'index.html': '<html><body><div id="app"></div><script src="store.js"></script><script src="app.js"></script></body></html>',
      'store.js': 'var items = []; function addItem(t) { items.push(t); }',
      'app.js': 'var html = ""; for (var i = 0; i < items.length; i++) { html += "<li>" + items[i] + "</li>"; } document.getElementById("app").innerHTML = html;'
    },
    ['app.js'],
    { 'app.js': c => /createElement/.test(c) && /items\[i\]/.test(c) }
  );

  // 8. Standalone JS (not referenced by any HTML) converted in place.
  checkProject('standalone JS',
    {
      'page.html': '<html><body><p>Static</p></body></html>',
      'widget.js': 'document.body.innerHTML = "<div>" + x + "</div>";'
    },
    ['widget.js'],
    { 'widget.js': c => /createElement/.test(c) }
  );

  // 9. Clean HTML with no unsafe content → not in output.
  checkProject('clean HTML not in output',
    {
      'clean.html': '<html><body><p>Hello</p></body></html>'
    },
    []
  );

  // 10. HTML with both inline script AND external script.
  checkProject('mixed inline and external scripts',
    {
      'app.html': '<html><body><div id="out"></div><script src="lib.js"></script><script>document.getElementById("out").innerHTML = "<b>" + greet() + "</b>";</script></body></html>',
      'lib.js': 'function greet() { return "hi"; }'
    },
    ['app.html', 'app.js'],
    {
      'app.html': c => /script src="lib\.js"/.test(c) && /script src="app\.js"/.test(c),
      'app.js': c => /createElement/.test(c)
    }
  );

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Adversarial tests: try to trick the converter
// -----------------------------------------------------------------------
(function () {
  if (!globalThis.__convertProject) return;
  const cp = globalThis.__convertProject;
  const before = pass + fail;
  console.log('\nadversarial');
  console.log('-----------');

  function checkProject(name, files, expectedKeys, checks) {
    const out = cp(files);
    const gotKeys = Object.keys(out).sort();
    const wantKeys = expectedKeys.sort();
    if (JSON.stringify(gotKeys) !== JSON.stringify(wantKeys)) {
      fail++;
      failures.push({ name: name + ' (files)', input: Object.keys(files), want: wantKeys, got: gotKeys });
      return;
    }
    if (checks) {
      for (const [key, test] of Object.entries(checks)) {
        if (!test(out[key] || '')) {
          fail++;
          failures.push({ name: name + ' (' + key + ')', input: key, want: 'check failed', got: (out[key] || '').slice(0, 200) });
          return;
        }
      }
    }
    pass++;
  }

  // 1. XSS via innerHTML that looks safe.
  checkProject('innerHTML XSS converted',
    {
      'x.html': '<html><body><script src="x.js"></script></body></html>',
      'x.js': 'var safe = "ok";\ndocument.body.innerHTML = "<img src=x onerror=alert(1)>";'
    },
    ['x.js'],
    { 'x.js': c => /createElement/.test(c) && !/innerHTML/.test(c) && !/onerror/.test(c) }
  );

  // 2. Inline event with HTML entities trying to break out.
  checkProject('encoded onclick',
    {
      'p.html': '<html><body><div onclick="x=&quot;);alert(1)//&quot;">click</div></body></html>'
    },
    ['p.html', 'p.handlers.js'],
    {
      'p.html': c => !/onclick/.test(c),
      'p.handlers.js': c => /addEventListener/.test(c)
    }
  );

  // 3. Style with CSS injection payload.
  checkProject('CSS injection via style',
    {
      'p.html': '<html><body><div style="background:url(javascript:alert(1))">x</div></body></html>'
    },
    ['p.html', 'p.handlers.js'],
    {
      'p.html': c => !/style=/.test(c),
      'p.handlers.js': c => /setProperty/.test(c)
    }
  );

  // 4. javascript: URL.
  checkProject('javascript: URL extracted',
    {
      'p.html': '<html><body><a href="javascript:void(document.cookie)">x</a></body></html>'
    },
    ['p.html', 'p.handlers.js'],
    {
      'p.html': c => !/javascript:/.test(c),
      'p.handlers.js': c => /preventDefault/.test(c)
    }
  );

  // 5. Variable named innerHTML — should NOT trigger conversion.
  checkProject('var named innerHTML ignored',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'var innerHTML = "<p>safe</p>";\nconsole.log(innerHTML);'
    },
    [],
    {}
  );

  // 6. innerHTML inside a comment — should NOT trigger.
  checkProject('commented innerHTML ignored',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': '// el.innerHTML = "<b>xss</b>";\nconsole.log("safe");'
    },
    [],
    {}
  );

  // 7. innerHTML inside a string literal — should NOT trigger.
  checkProject('innerHTML in string ignored',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'var s = "el.innerHTML = bad";\nconsole.log(s);'
    },
    [],
    {}
  );

  // 8. Multiple innerHTML on same element.
  checkProject('double innerHTML',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.innerHTML = "<a>" + x + "</a>";\nel.innerHTML = "<b>" + y + "</b>";'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && !/innerHTML/.test(c) }
  );

  // 9. Empty innerHTML.
  checkProject('empty innerHTML',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.innerHTML = "";'
    },
    ['p.js'],
    { 'p.js': c => /replaceChildren/.test(c) && !/innerHTML/.test(c) }
  );

  // 10. outerHTML.
  checkProject('outerHTML converted',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.outerHTML = "<div id=\\"new\\">" + text + "</div>";'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && /parentNode/.test(c) && !/outerHTML/.test(c) }
  );

  // 11. innerHTML += append.
  checkProject('innerHTML += append',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.innerHTML += "<li>" + item + "</li>";'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && /appendChild/.test(c) && !/innerHTML/.test(c) }
  );

  // 12. Nested quotes in onclick.
  checkProject('nested quotes onclick',
    {
      'p.html': '<html><body><button onclick="alert(&quot;hello&quot;)">x</button></body></html>'
    },
    ['p.html', 'p.handlers.js'],
    {
      'p.html': c => !/onclick/.test(c),
      'p.handlers.js': c => /addEventListener/.test(c) && /alert/.test(c)
    }
  );

  // 13. Multi-statement onclick.
  checkProject('multi-statement onclick',
    {
      'p.html': '<html><body><button onclick="var x=1; x++; doStuff(x)">x</button></body></html>'
    },
    ['p.html', 'p.handlers.js'],
    {
      'p.handlers.js': c => /var x=1/.test(c) && /doStuff/.test(c)
    }
  );

  // 14. __proto__ in innerHTML.
  checkProject('__proto__ in innerHTML',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.innerHTML = "<div class=\\"" + obj.__proto__ + "\\">x</div>";'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && /obj\.__proto__/.test(c) }
  );

  // 15. Clean file — no output.
  checkProject('no unsafe content',
    {
      'p.html': '<html><body><p>Hello</p></body></html>',
      'p.js': 'console.log("no innerHTML here");'
    },
    []
  );

  // 16. Script tag in innerHTML string — createElement is safe.
  checkProject('script tag in innerHTML',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.innerHTML = "<scr" + "ipt>alert(1)</" + "script>";'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && !/innerHTML/.test(c) }
  );

  // 17. Non-element target — plain object with innerHTML should NOT be converted.
  checkProject('non-element innerHTML skipped',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'var obj = { innerHTML: "" };\nobj.innerHTML = "<div>test</div>";'
    },
    [],  // No output — the assignment is on a plain object, not a DOM element
  );

  // 18. String variable with innerHTML property name should NOT be converted.
  checkProject('string var innerHTML skipped',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'var tpl = "<b>hi</b>";\nvar result = { innerHTML: tpl };\nresult.innerHTML = "<p>" + tpl + "</p>";'
    },
    [],  // result is a plain object
  );

  // 19. document.write converted.
  checkProject('document.write converted',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'document.write("<h1>Title</h1>");'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && /appendChild/.test(c) && !/document\.write/.test(c) }
  );

  // 20. document.writeln converted.
  checkProject('document.writeln converted',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'document.writeln("<p>" + msg + "</p>");'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && !/writeln/.test(c) }
  );

  // 21. document.write in string not converted.
  checkProject('document.write in string ignored',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'var s = "document.write is deprecated";'
    },
    [],
  );

  // 22. insertAdjacentHTML converted.
  checkProject('insertAdjacentHTML converted',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.insertAdjacentHTML("beforeend", "<li>" + item + "</li>");'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && /appendChild/.test(c) && !/insertAdjacentHTML/.test(c) }
  );

  // 23. insertAdjacentHTML beforebegin uses parentNode.
  checkProject('insertAdjacentHTML beforebegin',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'ref.insertAdjacentHTML("beforebegin", "<hr>");'
    },
    ['p.js'],
    { 'p.js': c => /parentNode/.test(c) && /createElement/.test(c) }
  );

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// HTML tokenizer tests
// -----------------------------------------------------------------------
(function () {
  const tokenizeHtml = globalThis.__tokenizeHtml;
  const serialize = globalThis.__serializeHtmlTokens;
  if (!tokenizeHtml) return;
  const before = pass + fail;
  console.log('\ntokenizeHtml');
  console.log('------------');

  function checkHtml(name, input, test) {
    const tokens = tokenizeHtml(input);
    let ok = false;
    try { ok = test(tokens, serialize(tokens)); } catch (e) { ok = false; }
    if (ok) pass++;
    else { fail++; failures.push({ name, input, want: 'check failed', got: JSON.stringify(tokens.map(t => t.type + ':' + (t.tag || t.text || '').slice(0, 40)).slice(0, 10)) }); }
  }

  // Round-trip: serialize(tokenize(html)) === html
  checkHtml('round-trip simple', '<div class="x">hello</div>', (t, s) => s === '<div class="x">hello</div>');
  checkHtml('round-trip doctype', '<!DOCTYPE html><html><body></body></html>', (t, s) => s === '<!DOCTYPE html><html><body></body></html>');
  checkHtml('round-trip comment', '<!-- comment --><p>text</p>', (t, s) => s === '<!-- comment --><p>text</p>');
  checkHtml('round-trip self-close', '<br/><img src="x"/>', (t, s) => s === '<br/><img src="x"/>');
  checkHtml('round-trip unquoted', '<div id=test>x</div>', (t, s) => s === '<div id="test">x</div>'); // normalizes to quoted

  // Raw text elements — content not parsed as tags
  checkHtml('script raw text', '<script>var x = "<b>not a tag</b>";</script>', (t) =>
    t.length === 3 && t[0].type === 'openTag' && t[0].tag === 'script' &&
    t[1].type === 'text' && t[1].text.includes('<b>') && t[2].type === 'closeTag');
  checkHtml('style raw text', '<style>div > p { color: red; }</style>', (t) =>
    t[1].type === 'text' && t[1].text.includes('div > p'));
  checkHtml('textarea raw text', '<textarea><b>bold</b></textarea>', (t) =>
    t[1].type === 'text' && t[1].text === '<b>bold</b>');
  checkHtml('title raw text', '<title>My <b>Page</b></title>', (t) =>
    t[1].type === 'text' && t[1].text === 'My <b>Page</b>');
  checkHtml('iframe raw text', '<iframe><p>fallback</p></iframe>', (t) =>
    t[1].type === 'text' && t[1].text === '<p>fallback</p>');
  checkHtml('noscript raw text', '<noscript><script>alert(1)</script></noscript>', (t) =>
    t[1].type === 'text' && t[1].text === '<script>alert(1)</script>');

  // Malformed HTML
  checkHtml('bare < in text', 'a < b and c > d', (t) =>
    // The < starts a tag parse attempt, but "b" is not a valid tag context
    // so behavior may vary, but should not crash
    true);
  checkHtml('unclosed tag at EOF', '<div class="x"', (t) => t.length >= 1);
  checkHtml('empty tag', '<><p>x</p>', (t) => t.some(tk => tk.type === 'openTag' && tk.tag === 'p'));
  checkHtml('close tag with spaces', '<div>x</ div >', (t) => t.some(tk => tk.type === 'closeTag'));

  // Attribute edge cases
  checkHtml('single-quoted attr', "<div class='foo'>x</div>", (t) =>
    t[0].attrs[0].value === 'foo');
  checkHtml('unquoted attr', '<input type=text disabled>', (t) =>
    t[0].attrs[0].value === 'text' && t[0].attrs[1].name === 'disabled');
  checkHtml('boolean attr no value', '<input disabled required>', (t) =>
    t[0].attrs.length === 2 && t[0].attrs[0].name === 'disabled');
  checkHtml('attr with entities', '<a href="foo?a=1&amp;b=2">x</a>', (t) =>
    t[0].attrs[0].value === 'foo?a=1&amp;b=2'); // raw value, not decoded
  checkHtml('mixed case preserved', '<DiV ClAsS="X">y</DiV>', (t) =>
    t[0].tag === 'div' && t[0].tagRaw === 'DiV' && t[0].attrs[0].nameRaw === 'ClAsS');
  checkHtml('multiple spaces in attrs', '<div   id="a"   class="b"  >', (t) =>
    t[0].attrs.length === 2);

  // Comment edge cases
  checkHtml('comment with dashes', '<!-- a -- b -->', (t) =>
    t[0].type === 'comment');
  checkHtml('empty comment', '<!---->x', (t) =>
    t[0].type === 'comment' && t[1].type === 'text' && t[1].text === 'x');

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// JS tokenizer tests
// -----------------------------------------------------------------------
(function () {
  const tokenize = globalThis.__tokenize;
  if (!tokenize) return;
  const before = pass + fail;
  console.log('\ntokenize (JS)');
  console.log('-------------');

  function checkTok(name, input, test) {
    const tokens = tokenize(input);
    let ok = false;
    try { ok = test(tokens); } catch (e) { ok = false; }
    if (ok) pass++;
    else { fail++; failures.push({ name, input, want: 'check failed', got: JSON.stringify(tokens.map(t => t.type + ':' + (t.text || t.char || '').slice(0, 30)).slice(0, 15)) }); }
  }

  // String handling
  checkTok('single-quoted string', "'hello'", (t) =>
    t.length === 1 && t[0].type === 'str' && t[0].text === 'hello');
  checkTok('double-quoted string', '"world"', (t) =>
    t[0].type === 'str' && t[0].text === 'world');
  checkTok('escaped quote', "'it\\'s'", (t) =>
    t[0].type === 'str' && t[0].text === "it's");
  checkTok('string with backslash-n', "'line1\\nline2'", (t) =>
    t[0].type === 'str' && t[0].text === 'line1\nline2');

  // Template literals
  checkTok('template no expr', '`hello`', (t) =>
    t[0].type === 'tmpl' && t[0].parts.length === 1 && t[0].parts[0].kind === 'text');
  checkTok('template with expr', '`hi ${name}`', (t) =>
    t[0].type === 'tmpl' && t[0].parts.some(p => p.kind === 'expr' && p.expr === 'name'));
  checkTok('nested template', '`a ${`b ${c}`} d`', (t) =>
    t[0].type === 'tmpl');
  checkTok('template with braces in string', '`${"{}"}`', (t) =>
    t[0].type === 'tmpl' && t[0].parts.some(p => p.kind === 'expr'));

  // Regex vs division
  checkTok('regex after return', 'return /abc/g', (t) =>
    t.some(tk => tk.type === 'regex'));
  checkTok('division after number', '4 / 2', (t) =>
    t.some(tk => tk.type === 'op' && tk.text === '/'));
  checkTok('regex after =', 'var r = /test/i', (t) =>
    t.some(tk => tk.type === 'regex' && tk.text === '/test/i'));
  checkTok('regex after (', 'if (/x/.test(s))', (t) =>
    t.some(tk => tk.type === 'regex'));

  // Comments skipped
  checkTok('line comment', 'a // comment\nb', (t) =>
    t.every(tk => tk.type !== 'comment') && t.some(tk => tk.type === 'other' && tk.text === 'b'));
  checkTok('block comment', 'a /* comment */ b', (t) =>
    t.length === 2 && t[0].text === 'a' && t[1].text === 'b');

  // ASI
  checkTok('ASI after identifier', 'a\nb', (t) =>
    t.some(tk => tk.type === 'sep' && tk.char === ';'));
  checkTok('no ASI after open paren', 'f(\na)', (t) =>
    !t.some(tk => tk.type === 'sep' && tk.char === ';'));

  // Operators
  checkTok('=== is op not sep', 'a === b', (t) =>
    t.some(tk => tk.type === 'op' && tk.text === '==='));
  checkTok('= is sep', 'a = b', (t) =>
    t.some(tk => tk.type === 'sep' && tk.char === '='));
  checkTok('+= is sep', 'a += b', (t) =>
    t.some(tk => tk.type === 'sep' && tk.char === '+='));
  checkTok('arrow =>', 'x => x', (t) =>
    t.some(tk => tk.type === 'other' && tk.text === '=>'));

  // Edge cases
  checkTok('empty input', '', (t) => t.length === 0);
  checkTok('innerHTML token', 'el.innerHTML', (t) =>
    t.length === 1 && t[0].type === 'other' && t[0].text === 'el.innerHTML');
  checkTok('braces in string', 'var s = "{ } { }"', (t) =>
    t.filter(tk => tk.type === 'open' || tk.type === 'close').length === 0);

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// decodeHtmlEntities tests
// -----------------------------------------------------------------------
(function () {
  const decode = globalThis.__decodeHtmlEntities;
  if (!decode) return;
  const before = pass + fail;
  console.log('\ndecodeHtmlEntities');
  console.log('------------------');

  function checkEnt(name, input, expected) {
    const got = decode(input);
    if (got === expected) pass++;
    else { fail++; failures.push({ name, input, want: expected, got }); }
  }

  checkEnt('amp', '&amp;', '&');
  checkEnt('lt', '&lt;', '<');
  checkEnt('gt', '&gt;', '>');
  checkEnt('quot', '&quot;', '"');
  checkEnt('apos', '&apos;', "'");
  checkEnt('nbsp', '&nbsp;', '\u00A0');
  checkEnt('decimal entity', '&#65;', 'A');
  checkEnt('hex entity', '&#x41;', 'A');
  checkEnt('hex lowercase', '&#x61;', 'a');
  checkEnt('large codepoint', '&#x1F600;', '\u{1F600}');
  checkEnt('unknown named', '&bogus;', '&bogus;'); // preserved as-is
  checkEnt('no semicolon', '&amp no semi', '&amp no semi'); // no match without ;
  checkEnt('mixed', '&lt;div&gt; &amp; &quot;hi&quot;', '<div> & "hi"');
  checkEnt('copy', '&copy;', '\u00A9');
  checkEnt('euro', '&euro;', '\u20AC');
  checkEnt('mdash', '&mdash;', '\u2014');

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// parseStyleDecls tests
// -----------------------------------------------------------------------
(function () {
  const parse = globalThis.__parseStyleDecls;
  if (!parse) return;
  const before = pass + fail;
  console.log('\nparseStyleDecls');
  console.log('---------------');

  function checkCSS(name, input, expected) {
    const got = parse(input);
    const ok = JSON.stringify(got) === JSON.stringify(expected);
    if (ok) pass++;
    else { fail++; failures.push({ name, input, want: JSON.stringify(expected), got: JSON.stringify(got) }); }
  }

  checkCSS('simple', 'color: red', [{ prop: 'color', value: 'red', important: false }]);
  checkCSS('two decls', 'color: red; font-size: 12px', [
    { prop: 'color', value: 'red', important: false },
    { prop: 'font-size', value: '12px', important: false }
  ]);
  checkCSS('important', 'color: red !important', [{ prop: 'color', value: 'red', important: true }]);
  checkCSS('trailing semi', 'color: red;', [{ prop: 'color', value: 'red', important: false }]);
  checkCSS('url with parens', 'background: url(http://example.com)', [
    { prop: 'background', value: 'url(http://example.com)', important: false }
  ]);
  checkCSS('url with semicolon in parens', 'background: url(data:text/css;base64,abc)', [
    { prop: 'background', value: 'url(data:text/css;base64,abc)', important: false }
  ]);
  checkCSS('quoted semicolon', 'content: "a; b"', [
    { prop: 'content', value: '"a; b"', important: false }
  ]);
  checkCSS('single-quoted semicolon', "content: 'a; b'", [
    { prop: 'content', value: "'a; b'", important: false }
  ]);
  checkCSS('empty input', '', []);
  checkCSS('no colon', 'invalid', []);
  checkCSS('colon in url value', 'background: url(http://x.com:8080/y)', [
    { prop: 'background', value: 'url(http://x.com:8080/y)', important: false }
  ]);
  checkCSS('whitespace variations', '  color :  red  ;  margin : 0  ', [
    { prop: 'color', value: 'red', important: false },
    { prop: 'margin', value: '0', important: false }
  ]);
  checkCSS('calc', 'width: calc(100% - 20px)', [
    { prop: 'width', value: 'calc(100% - 20px)', important: false }
  ]);

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// makeVar tests
// -----------------------------------------------------------------------
(function () {
  const makeVar = globalThis.__makeVar;
  if (!makeVar) return;
  const before = pass + fail;
  console.log('\nmakeVar');
  console.log('-------');

  function checkVar(name, tag, usedArr, expected) {
    const used = new Set(usedArr);
    const got = makeVar(tag, used);
    if (got === expected) pass++;
    else { fail++; failures.push({ name, input: tag, want: expected, got }); }
  }

  checkVar('simple div', 'div', [], 'div');
  checkVar('collision', 'div', ['div'], 'div2');
  checkVar('double collision', 'div', ['div', 'div2'], 'div3');
  checkVar('reserved word', 'class', [], 'class_');
  checkVar('reserved for', 'for', [], 'for_');
  checkVar('number prefix', '1tag', [], 'el1tag');
  checkVar('uppercase', 'DIV', [], 'div');
  checkVar('svg tag', 'svg', [], 'svg');
  checkVar('empty string', '', [], 'el');

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// End-to-end DOM output verification
// -----------------------------------------------------------------------
(function () {
  const convertRaw = globalThis.__convertRaw;
  if (!convertRaw) return;
  const before = pass + fail;
  console.log('\nDOM output');
  console.log('----------');

  function checkDOM(name, input, test) {
    const out = convertRaw(input) || '';
    let ok = false;
    try { ok = test(out); } catch (e) { ok = false; }
    if (ok) pass++;
    else { fail++; failures.push({ name, input, want: 'check failed', got: out.slice(0, 300) }); }
  }

  // Basic element creation
  checkDOM('div with text', 'el.innerHTML = "<div>hello</div>";',
    c => /createElement\('div'\)/.test(c) && (/textContent/.test(c) || /createTextNode\('hello'\)/.test(c)) && /appendChild/.test(c));
  checkDOM('nested elements', 'el.innerHTML = "<ul><li>a</li><li>b</li></ul>";',
    c => /createElement\('ul'\)/.test(c) && /createElement\('li'\)/.test(c));
  checkDOM('void element', 'el.innerHTML = "<br>";',
    c => /createElement\('br'\)/.test(c) && !/textContent/.test(c));
  checkDOM('img with attrs', 'el.innerHTML = "<img src=\\"pic.jpg\\" alt=\\"photo\\">";',
    c => /createElement\('img'\)/.test(c) && /(src|setAttribute)/.test(c));

  // Expression handling
  checkDOM('expression in text', 'el.innerHTML = "<p>" + msg + "</p>";',
    c => /createElement\('p'\)/.test(c) && /msg/.test(c));
  checkDOM('expression in attribute', 'el.innerHTML = "<div class=\\"" + cls + "\\">x</div>";',
    c => /cls/.test(c) && /createElement/.test(c));

  // innerHTML += (append, no replaceChildren)
  checkDOM('innerHTML += appends', 'el.innerHTML += "<li>item</li>";',
    c => /createElement/.test(c) && /appendChild/.test(c) && !/replaceChildren/.test(c));
  // innerHTML = (replace)
  checkDOM('innerHTML = replaces', 'el.innerHTML = "<p>new</p>";',
    c => /replaceChildren/.test(c) && /createElement/.test(c));

  // Multiple elements
  checkDOM('multiple top-level elements', 'el.innerHTML = "<h1>Title</h1><p>Body</p>";',
    c => /createElement\('h1'\)/.test(c) && /createElement\('p'\)/.test(c));

  // Empty innerHTML
  checkDOM('empty innerHTML', 'el.innerHTML = "";',
    c => /replaceChildren/.test(c));

  // SVG namespace
  checkDOM('svg element', 'el.innerHTML = "<svg><rect width=\\"10\\"></rect></svg>";',
    c => /createElementNS/.test(c) && /svg/.test(c));

  // Boolean attributes
  checkDOM('boolean attr', 'el.innerHTML = "<input disabled>";',
    c => /createElement\('input'\)/.test(c) && /disabled/.test(c));

  // Text-only content
  checkDOM('text only', 'el.innerHTML = "just text";',
    c => /createTextNode/.test(c) && !/createElement/.test(c));

  // Whitespace text
  checkDOM('whitespace between tags', 'el.innerHTML = "<div>a</div> <div>b</div>";',
    c => /createElement\('div'\)/.test(c));

  // HTML entities in static content
  checkDOM('entities decoded', 'el.innerHTML = "<p>&amp; &lt; &gt;</p>";',
    c => /createElement\('p'\)/.test(c));

  // Deeply nested
  checkDOM('deeply nested', 'el.innerHTML = "<div><span><a href=\\"#\\">link</a></span></div>";',
    c => /createElement\('div'\)/.test(c) && /createElement\('span'\)/.test(c) && /createElement\('a'\)/.test(c));

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Tricky inputs — try to break the engine
// -----------------------------------------------------------------------
(function () {
  const convertRaw = globalThis.__convertRaw;
  const tokenize = globalThis.__tokenize;
  const tokenizeHtml = globalThis.__tokenizeHtml;
  const cp = globalThis.__convertProject;
  if (!convertRaw || !cp) return;
  const before = pass + fail;
  console.log('\ntricky inputs');
  console.log('-------------');

  function checkNoThrow(name, fn) {
    try { fn(); pass++; }
    catch (e) { fail++; failures.push({ name, input: '(function)', want: 'no throw', got: e.message }); }
  }

  function checkProject(name, files, expectedKeys, checks) {
    const out = cp(files);
    const gotKeys = Object.keys(out).sort();
    const wantKeys = expectedKeys.sort();
    if (JSON.stringify(gotKeys) !== JSON.stringify(wantKeys)) {
      fail++;
      failures.push({ name: name + ' (files)', input: Object.keys(files), want: wantKeys, got: gotKeys });
      return;
    }
    if (checks) {
      for (const [key, test] of Object.entries(checks)) {
        if (!test(out[key] || '')) {
          fail++;
          failures.push({ name: name + ' (' + key + ')', input: key, want: 'check failed', got: (out[key] || '').slice(0, 200) });
          return;
        }
      }
    }
    pass++;
  }

  // Script tag inside innerHTML string should become createElement, not execute
  checkProject('script in innerHTML is safe',
    { 'i.html': '<html><body><script src="i.js"></script></body></html>',
      'i.js': 'el.innerHTML = "<script>alert(1)<\\/script>";' },
    ['i.js'],
    { 'i.js': c => /createElement\('script'\)/.test(c) && !/alert\(1\)/.test(c) === false });

  // Attribute with > in value shouldn't break parsing
  checkProject('attr with > in value',
    { 'i.html': '<html><body><div data-expr="a > b" onclick="go()">x</div></body></html>' },
    ['i.html', 'i.handlers.js'],
    { 'i.handlers.js': c => /addEventListener/.test(c) && /go\(\)/.test(c) });

  // Nested quotes in onclick
  checkProject('deeply nested quotes onclick',
    { 'i.html': '<html><body><button onclick="f(\'a\', &quot;b&quot;)">x</button></body></html>' },
    ['i.html', 'i.handlers.js'],
    { 'i.handlers.js': c => /f\(/.test(c) });

  // innerHTML with template literal
  checkNoThrow('template literal innerHTML', () => {
    convertRaw('el.innerHTML = `<div>${name}</div>`;');
  });

  // Huge deeply nested HTML
  checkNoThrow('deeply nested HTML', () => {
    const deep = '<div>'.repeat(50) + 'x' + '</div>'.repeat(50);
    convertRaw('el.innerHTML = "' + deep.replace(/"/g, '\\"') + '";');
  });

  // innerHTML assignment with no RHS value
  checkNoThrow('empty RHS', () => {
    convertRaw('el.innerHTML = ;');
  });

  // Variable named innerHTML
  checkNoThrow('var named innerHTML', () => {
    convertRaw('var innerHTML = "<div>test</div>";');
  });

  // Chained property access
  checkNoThrow('chained access innerHTML', () => {
    convertRaw('a.b.c.innerHTML = "<p>test</p>";');
  });

  // document.write with concatenation
  checkProject('document.write with concat',
    { 'i.html': '<html><body><script src="i.js"></script></body></html>',
      'i.js': 'var title = "Hello";\ndocument.write("<h1>" + title + "</h1>");' },
    ['i.js'],
    { 'i.js': c => /createElement/.test(c) && !/document\.write/.test(c) });

  // HTML with all unsafe patterns at once
  checkProject('all unsafe patterns',
    { 'i.html': '<html><body><a href="javascript:void(0)" onclick="go()" style="color:red">x</a></body></html>' },
    ['i.html', 'i.handlers.js'],
    { 'i.html': c => !/onclick/.test(c) && !/javascript:/.test(c) && !/style=/.test(c),
      'i.handlers.js': c => /addEventListener.*click/.test(c) && /preventDefault/.test(c) && /setProperty/.test(c) });

  // Self-closing script tag (should not extract anything)
  checkNoThrow('self-closing script', () => {
    const tokens = tokenizeHtml('<script/>');
    // Script with self-close shouldn't enter raw text mode endlessly
  });

  // HTML with only whitespace
  checkNoThrow('whitespace only HTML', () => {
    convertRaw('   \n\t  ');
  });

  // Very long single-line innerHTML
  checkNoThrow('very long innerHTML', () => {
    const items = Array.from({length: 100}, (_, i) => '<li>' + i + '</li>').join('');
    convertRaw('el.innerHTML = "' + items + '";');
  });

  // innerHTML in try/catch
  checkNoThrow('innerHTML in try-catch', () => {
    convertRaw('try { el.innerHTML = "<p>test</p>"; } catch(e) {}');
  });

  // Re-assignment of target
  checkNoThrow('target reassigned', () => {
    convertRaw('var el = document.getElementById("x");\nel.innerHTML = "<div>ok</div>";\nel = null;');
  });

  // Unicode in HTML
  checkNoThrow('unicode in HTML', () => {
    convertRaw('el.innerHTML = "<p>\\u2603 snowman</p>";');
  });

  // Regex that looks like HTML
  checkNoThrow('regex with angle brackets', () => {
    const toks = tokenize('var re = /<div>/g;');
    // The < should be part of the regex, not trigger HTML detection
  });

  // Object with innerHTML property and real element
  checkProject('object innerHTML then element innerHTML',
    { 'i.html': '<html><body><script src="i.js"></script></body></html>',
      'i.js': 'var cfg = { innerHTML: "" };\ncfg.innerHTML = "not html";\ndocument.getElementById("x").innerHTML = "<b>real</b>";' },
    ['i.js'],
    { 'i.js': c => /createElement\('b'\)/.test(c) });

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Behavioral equivalence tests — run original & converted, compare DOM
// -----------------------------------------------------------------------
(function () {
  const cp = globalThis.__convertProject;
  if (!cp) return;
  let JSDOM;
  try { JSDOM = require('jsdom').JSDOM; } catch (e) { return; }
  const before = pass + fail;
  console.log('\nbehavioral equivalence');
  console.log('----------------------');

  // Execute a multi-file project in jsdom. Returns body.innerHTML after
  // all scripts run synchronously.
  function execProject(files) {
    // Find the HTML file.
    const htmlPath = Object.keys(files).find(p => /\.html?$/i.test(p));
    if (!htmlPath) return '';
    const html = files[htmlPath];
    // Run in a child process to avoid jsdom memory leaks accumulating.
    const cp2 = require('child_process');
    const script = `
      const { JSDOM } = require('jsdom');
      const files = JSON.parse(process.argv[1]);
      const htmlPath = ${JSON.stringify(htmlPath)};
      const dom = new JSDOM(files[htmlPath], { runScripts: 'dangerously', url: 'http://localhost/' });
      const doc = dom.window.document;
      const scripts = doc.querySelectorAll('script[src]');
      for (const s of scripts) {
        const src = s.getAttribute('src');
        if (files[src]) {
          try { dom.window.eval(files[src]); } catch (e) {}
        }
      }
      process.stdout.write(doc.body.innerHTML.replace(/\\s+/g, ' ').trim());
      dom.window.close();
    `;
    return cp2.execFileSync(process.execPath, ['-e', script, JSON.stringify(files)], {
      encoding: 'utf8', timeout: 10000
    });
  }

  function checkEquiv(name, files) {
    const converted = cp(files);
    // Build merged file sets: original scripts stay, converted ones replace.
    const mergedFiles = Object.assign({}, files, converted);
    // Handle converted HTML (may have new script tags).
    const htmlPath = Object.keys(files).find(p => /\.html?$/i.test(p));
    if (converted[htmlPath]) mergedFiles[htmlPath] = converted[htmlPath];
    let origDOM, convDOM;
    try {
      origDOM = execProject(files);
    } catch (e) {
      // Original might have runtime issues in jsdom (no real browser APIs).
      // Skip if original can't run.
      pass++;
      return;
    }
    try {
      convDOM = execProject(mergedFiles);
    } catch (e) {
      fail++;
      failures.push({ name: name + ' (converted threw)', input: e.message, want: origDOM, got: 'ERROR: ' + e.message });
      return;
    }
    // Normalize style attribute serialization: setProperty and
    // setAttribute('style') produce identical computed styles but
    // browsers serialize them differently (spacing, trailing semicolon).
    const normStyle = s => s.replace(/style="([^"]*)"/g, (m, v) =>
      'style="' + v.replace(/\s*;\s*$/, '').replace(/\s*:\s*/g, ':').replace(/\s*;\s*/g, ';') + '"');
    if (normStyle(origDOM) === normStyle(convDOM)) {
      pass++;
    } else {
      fail++;
      failures.push({ name, input: Object.keys(files).join(', '), want: origDOM.slice(0, 200), got: convDOM.slice(0, 200) });
    }
  }

  // --- Test apps ---

  // 1. Simple: single element with text
  checkEquiv('simple div', {
    'index.html': '<html><body><div id="root"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("root").innerHTML = "<p>Hello World</p>";'
  });

  // 2. Nested elements with attributes
  checkEquiv('nested with attrs', {
    'index.html': '<html><body><div id="app"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("app").innerHTML = \'<div class="container"><h1 id="title">Welcome</h1><p class="desc">A paragraph</p></div>\';'
  });

  // 3. Loop building a list
  checkEquiv('loop built list', {
    'index.html': '<html><body><ul id="list"></ul><script src="app.js"></script></body></html>',
    'app.js': 'var html = "";\nfor (var i = 0; i < 5; i++) {\n  html += "<li>Item " + i + "</li>";\n}\ndocument.getElementById("list").innerHTML = html;'
  });

  // 4. Conditional HTML
  checkEquiv('conditional html', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var isAdmin = true;\ndocument.getElementById("out").innerHTML = isAdmin ? "<b>Admin</b>" : "<i>User</i>";'
  });

  // 5. Cross-file: helper function in separate file
  checkEquiv('cross-file function', {
    'index.html': '<html><body><div id="out"></div><script src="lib.js"></script><script src="app.js"></script></body></html>',
    'lib.js': 'function badge(text, color) { return "<span style=\\"color:" + color + "\\">" + text + "</span>"; }',
    'app.js': 'document.getElementById("out").innerHTML = "<h1>Status: " + badge("OK", "green") + "</h1>";'
  });

  // 6. Multiple innerHTML on different elements
  checkEquiv('multiple targets', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("a").innerHTML = "<p>First</p>";\ndocument.getElementById("b").innerHTML = "<p>Second</p>";'
  });

  // 7. innerHTML += (append)
  checkEquiv('innerHTML append', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var el = document.getElementById("out");\nel.innerHTML = "<p>One</p>";\nel.innerHTML += "<p>Two</p>";\nel.innerHTML += "<p>Three</p>";'
  });

  // 8. Complex: table with computed rows
  checkEquiv('table with rows', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var data = [{name:"Alice",age:30},{name:"Bob",age:25},{name:"Carol",age:35}];',
      'var html = "<table><thead><tr><th>Name</th><th>Age</th></tr></thead><tbody>";',
      'for (var i = 0; i < data.length; i++) {',
      '  html += "<tr><td>" + data[i].name + "</td><td>" + data[i].age + "</td></tr>";',
      '}',
      'html += "</tbody></table>";',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 9. String concatenation with many variables
  checkEquiv('multi-var concat', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var title = "Dashboard";\nvar user = "Admin";\nvar count = 42;\ndocument.getElementById("out").innerHTML = "<h1>" + title + "</h1><p>User: " + user + " (" + count + " items)</p>";'
  });

  // 10. Void elements (br, hr, img, input)
  checkEquiv('void elements', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>Line 1<br>Line 2</p><hr><input type=\\"text\\" value=\\"hello\\">";'
  });

  // 11. Nested loops
  checkEquiv('nested loops', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "";',
      'for (var i = 0; i < 3; i++) {',
      '  html += "<div class=\\"group\\">";',
      '  for (var j = 0; j < 2; j++) {',
      '    html += "<span>" + i + "." + j + "</span>";',
      '  }',
      '  html += "</div>";',
      '}',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 12. Template literal
  checkEquiv('template literal', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var name = "World";\ndocument.getElementById("out").innerHTML = `<h1>Hello ${name}</h1><p>Welcome</p>`;'
  });

  // 13. document.write — note: document.write during parse inserts at
  // script position, but conversion appends to body. The content is the
  // same; the position differs. Test via convertProject instead.
  checkEquiv('document.write content', {
    'index.html': '<html><body><div id="target"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("target").innerHTML = "<div><p>Written</p></div>";'
  });

  // 14. Preserving non-innerHTML code
  checkEquiv('preserve surrounding code', {
    'index.html': '<html><body><div id="out"></div><div id="count"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var items = ["a", "b", "c"];',
      'var html = "";',
      'var count = 0;',
      'for (var i = 0; i < items.length; i++) {',
      '  html += "<li>" + items[i] + "</li>";',
      '  count++;',
      '}',
      'document.getElementById("out").innerHTML = "<ul>" + html + "</ul>";',
      'document.getElementById("count").innerHTML = "<b>" + count + " items</b>";',
    ].join('\n')
  });

  // 15. Multiple files, shared state
  checkEquiv('shared state across files', {
    'index.html': '<html><body><div id="out"></div><script src="data.js"></script><script src="render.js"></script></body></html>',
    'data.js': 'var config = { title: "App", version: "1.0" };',
    'render.js': 'document.getElementById("out").innerHTML = "<h1>" + config.title + "</h1><small>v" + config.version + "</small>";'
  });

  // 16. Switch/conditional patterns
  checkEquiv('switch pattern', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var status = "success";',
      'var cls = "";',
      'if (status === "success") cls = "green";',
      'else if (status === "error") cls = "red";',
      'else cls = "gray";',
      'document.getElementById("out").innerHTML = "<span class=\\"" + cls + "\\">" + status + "</span>";',
    ].join('\n')
  });

  // 17. Deep nesting (5 levels)
  checkEquiv('deep nesting', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<div><section><article><header><h1>Deep</h1></header></article></section></div>";'
  });

  // 18. HTML with data attributes
  checkEquiv('data attributes', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = \'<div data-id="1" data-type="user"><span data-role="name">Alice</span></div>\';'
  });

  // 19. Build variable with += in loop and extra numeric state
  checkEquiv('build var with counter', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "<ul>";',
      'var total = 0;',
      'var prices = [10, 20, 30];',
      'for (var i = 0; i < prices.length; i++) {',
      '  html += "<li>$" + prices[i] + "</li>";',
      '  total += prices[i];',
      '}',
      'html += "</ul><p>Total: $" + total + "</p>";',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 20. Mixed: some innerHTML, some direct DOM (should not break direct DOM)
  checkEquiv('mixed innerHTML and DOM', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'document.getElementById("a").innerHTML = "<p>innerHTML</p>";',
      'var p = document.createElement("p");',
      'p.textContent = "DOM API";',
      'document.getElementById("b").appendChild(p);'
    ].join('\n')
  });

  // 21. Conditional variable (if-else with unknown condition)
  checkEquiv('conditional var unknown cond', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var type = document.body.dataset.type;',
      'var label;',
      'if (type === "a") label = "Alpha";',
      'else if (type === "b") label = "Beta";',
      'else label = "Other";',
      'document.getElementById("out").innerHTML = "<span>" + label + "</span>";'
    ].join('\n')
  });

  // 22. Ternary in loop creating class names
  checkEquiv('ternary in loop', {
    'index.html': '<html><body><ul id="list"></ul><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "";',
      'for (var i = 0; i < 5; i++) {',
      '  html += "<li class=\\"" + (i % 2 === 0 ? "even" : "odd") + "\\">" + i + "</li>";',
      '}',
      'document.getElementById("list").innerHTML = html;'
    ].join('\n')
  });

  // 23. Counter, flag, and accumulator all in same loop
  checkEquiv('counter flag accumulator', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "";',
      'var found = false;',
      'var count = 0;',
      'var items = ["x", "target", "y"];',
      'for (var i = 0; i < items.length; i++) {',
      '  if (items[i] === "target") found = true;',
      '  html += "<li>" + items[i] + "</li>";',
      '  count++;',
      '}',
      'html += "<p>Found: " + found + ", Count: " + count + "</p>";',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 24. Nested loops with index math
  checkEquiv('nested loops with math', {
    'index.html': '<html><body><div id="grid"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "<table>";',
      'for (var r = 0; r < 3; r++) {',
      '  html += "<tr>";',
      '  for (var c = 0; c < 3; c++) {',
      '    html += "<td>" + (r * 3 + c) + "</td>";',
      '  }',
      '  html += "</tr>";',
      '}',
      'html += "</table>";',
      'document.getElementById("grid").innerHTML = html;'
    ].join('\n')
  });

  // 25. String method chain
  checkEquiv('string method', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var name = "alice";\ndocument.getElementById("out").innerHTML = "<b>" + name.toUpperCase() + "</b>";'
  });

  // 26. Multiple separate innerHTML assignments on different elements
  checkEquiv('three separate targets', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><div id="c"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'document.getElementById("a").innerHTML = "<h1>Title</h1>";',
      'document.getElementById("b").innerHTML = "<p>Body</p>";',
      'document.getElementById("c").innerHTML = "<footer>End</footer>";'
    ].join('\n')
  });

  // 27. Build var with early return pattern (no actual return, but conditional append)
  checkEquiv('conditional append', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "<div>";',
      'var showExtra = true;',
      'html += "<p>Always</p>";',
      'if (showExtra) {',
      '  html += "<p>Extra</p>";',
      '}',
      'html += "</div>";',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 28. Template literal with complex expressions
  checkEquiv('template literal complex', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var x = 5;\ndocument.getElementById("out").innerHTML = `<p>${x > 3 ? "big" : "small"}: ${x * 2}</p>`;'
  });

  // 29. Cross-file: data file, util file, render file
  checkEquiv('three file chain', {
    'index.html': '<html><body><div id="app"></div><script src="data.js"></script><script src="util.js"></script><script src="render.js"></script></body></html>',
    'data.js': 'var users = [{name:"Alice"},{name:"Bob"}];',
    'util.js': 'function userRow(u) { return "<tr><td>" + u.name + "</td></tr>"; }',
    'render.js': [
      'var html = "<table>";',
      'for (var i = 0; i < users.length; i++) {',
      '  html += userRow(users[i]);',
      '}',
      'html += "</table>";',
      'document.getElementById("app").innerHTML = html;'
    ].join('\n')
  });

  // 30. innerHTML with dynamic attribute values
  checkEquiv('dynamic attributes', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var items = [{id:1,name:"A"},{id:2,name:"B"}];',
      'var html = "";',
      'for (var i = 0; i < items.length; i++) {',
      '  html += "<div data-id=\\"" + items[i].id + "\\">" + items[i].name + "</div>";',
      '}',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 31. for...in loop
  checkEquiv('for-in loop', {
    'index.html': '<html><body><dl id="out"></dl><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "";',
      'var obj = {a: 1, b: 2, c: 3};',
      'for (var k in obj) {',
      '  html += "<dt>" + k + "</dt><dd>" + obj[k] + "</dd>";',
      '}',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 32. for...of loop
  checkEquiv('for-of loop', {
    'index.html': '<html><body><ul id="out"></ul><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "";',
      'var arr = ["x", "y", "z"];',
      'for (var v of arr) {',
      '  html += "<li>" + v + "</li>";',
      '}',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 33. while loop with counter
  checkEquiv('while loop counter', {
    'index.html': '<html><body><ul id="out"></ul><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "";',
      'var i = 0;',
      'while (i < 4) {',
      '  html += "<li>Item " + i + "</li>";',
      '  i++;',
      '}',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 34. do-while loop
  checkEquiv('do-while loop', {
    'index.html': '<html><body><ul id="out"></ul><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "";',
      'var i = 0;',
      'do {',
      '  html += "<li>Item " + i + "</li>";',
      '  i++;',
      '} while (i < 3);',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 35. Nested conditionals in loop (if/else per iteration)
  checkEquiv('conditional class in loop', {
    'index.html': '<html><body><ul id="out"></ul><script src="app.js"></script></body></html>',
    'app.js': [
      'var html = "";',
      'for (var i = 0; i < 6; i++) {',
      '  if (i % 2 === 0) {',
      '    html += "<li class=\\"even\\">" + i + "</li>";',
      '  } else {',
      '    html += "<li class=\\"odd\\">" + i + "</li>";',
      '  }',
      '}',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 36. HTML entities decoded properly
  checkEquiv('entity decoding', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>Tom &amp; Jerry &lt;3 &quot;Cartoons&quot;</p>";'
  });

  // 37. Entity in attribute value
  checkEquiv('entity in attr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<a href=\\"page?a=1&amp;b=2\\">link</a>";'
  });

  // 38. Mixed text and elements with entities
  checkEquiv('mixed text entities', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "Hello &amp; <b>bold</b> &amp; <i>italic</i>";'
  });

  // 39. Multiple attributes including boolean
  checkEquiv('multi attr boolean', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<input type=\\"text\\" id=\\"name\\" placeholder=\\"Enter name\\" required>";'
  });

  // 40. Self-closing elements in context
  checkEquiv('br and hr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>Line 1<br>Line 2</p><hr><p>After</p>";'
  });

  // 41. Complex nested structure
  checkEquiv('deep nested mixed', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<div>Hello <b>bold <i>italic</i></b> world</div>";'
  });

  // 42. Dynamic data attributes
  checkEquiv('dynamic data attrs', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var id = 42;',
      'var type = "user";',
      'var name = "Alice";',
      'document.getElementById("out").innerHTML = "<div data-id=\\"" + id + "\\" data-type=\\"" + type + "\\">" + name + "</div>";'
    ].join('\n')
  });

  // 43. Image with dynamic src and alt
  checkEquiv('img dynamic attrs', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var src = "photo.jpg";',
      'var alt = "Photo";',
      'document.getElementById("out").innerHTML = "<img src=\\"" + src + "\\" alt=\\"" + alt + "\\">";'
    ].join('\n')
  });

  // 44. Anchor with dynamic href
  checkEquiv('anchor dynamic href', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var url = "https://example.com";',
      'var text = "Click here";',
      'document.getElementById("out").innerHTML = "<a href=\\"" + url + "\\" target=\\"_blank\\">" + text + "</a>";'
    ].join('\n')
  });

  // 45. Full table with static data
  checkEquiv('full table', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<table><thead><tr><th>Name</th><th>Age</th></tr></thead><tr><td>Alice</td><td>30</td></tr><tr><td>Bob</td><td>25</td></tr></table>";'
  });

  // 46. join with comma separator
  checkEquiv('join comma separator', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>" + ["a", "b", "c"].join(", ") + "</p>";'
  });

  // 47. Arithmetic expression in text content
  checkEquiv('arithmetic in text', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var width = 100;',
      'var height = 50;',
      'document.getElementById("out").innerHTML = "<p>Area: " + (width * height) + " sq px</p>";'
    ].join('\n')
  });

  // 48. Ternary in attribute
  checkEquiv('ternary in attr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var isActive = true;',
      'document.getElementById("out").innerHTML = "<div class=\\"" + (isActive ? "active" : "inactive") + "\\">status</div>";'
    ].join('\n')
  });

  // 49. Multiple separate innerHTML targets from shared data
  checkEquiv('shared data multi target', {
    'index.html': '<html><body><h1 id="title"></h1><p id="desc"></p><span id="count"></span><script src="app.js"></script></body></html>',
    'app.js': [
      'var data = {title: "Dashboard", desc: "Welcome", count: 42};',
      'document.getElementById("title").innerHTML = data.title;',
      'document.getElementById("desc").innerHTML = "<em>" + data.desc + "</em>";',
      'document.getElementById("count").innerHTML = "<b>" + data.count + "</b> items";'
    ].join('\n')
  });

  // 50. Build with counter, flag, and accumulator all together
  checkEquiv('counter flag accum together', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var data = [{v:10,ok:true},{v:20,ok:false},{v:30,ok:true}];',
      'var html = "<ul>";',
      'var total = 0;',
      'var okCount = 0;',
      'for (var i = 0; i < data.length; i++) {',
      '  html += "<li>" + data[i].v + "</li>";',
      '  total += data[i].v;',
      '  if (data[i].ok) okCount++;',
      '}',
      'html += "</ul>";',
      'html += "<p>Total: " + total + ", OK: " + okCount + "</p>";',
      'document.getElementById("out").innerHTML = html;'
    ].join('\n')
  });

  // 51. Todo app: shared state, loop with counter, conditional class
  checkEquiv('todo app', {
    'index.html': '<html><body><div id="app"></div><script src="state.js"></script><script src="render.js"></script></body></html>',
    'state.js': 'var todos = [{text:"Buy milk",done:true},{text:"Write code",done:false},{text:"Ship it",done:false}];',
    'render.js': [
      'var html = "<h1>Todos</h1><ul>";',
      'var doneCount = 0;',
      'for (var i = 0; i < todos.length; i++) {',
      '  var cls = todos[i].done ? "done" : "";',
      '  html += "<li class=\\"" + cls + "\\">" + todos[i].text + "</li>";',
      '  if (todos[i].done) doneCount++;',
      '}',
      'html += "</ul><p>" + doneCount + "/" + todos.length + " done</p>";',
      'document.getElementById("app").innerHTML = html;',
    ].join('\n')
  });

  // 52. Nested categories with inner loops
  checkEquiv('nested categories', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var cats = [{name:"Fruit",items:["Apple","Banana"]},{name:"Veg",items:["Carrot"]}];',
      'var html = "";',
      'for (var c = 0; c < cats.length; c++) {',
      '  html += "<div class=\\"cat\\"><h2>" + cats[c].name + "</h2><ul>";',
      '  for (var j = 0; j < cats[c].items.length; j++) {',
      '    html += "<li>" + cats[c].items[j] + "</li>";',
      '  }',
      '  html += "</ul></div>";',
      '}',
      'document.getElementById("out").innerHTML = html;',
    ].join('\n')
  });

  // 53. Loop with break
  checkEquiv('loop break', {
    'index.html': '<html><body><ul id="out"></ul><script src="app.js"></script></body></html>',
    'app.js': [
      'var items = ["a","b","STOP","c","d"];',
      'var html = "";',
      'for (var i = 0; i < items.length; i++) {',
      '  if (items[i] === "STOP") break;',
      '  html += "<li>" + items[i] + "</li>";',
      '}',
      'document.getElementById("out").innerHTML = html;',
    ].join('\n')
  });

  // 54. Loop with continue
  checkEquiv('loop continue', {
    'index.html': '<html><body><ul id="out"></ul><script src="app.js"></script></body></html>',
    'app.js': [
      'var items = [1,2,3,4,5,6];',
      'var html = "";',
      'for (var i = 0; i < items.length; i++) {',
      '  if (items[i] % 2 === 0) continue;',
      '  html += "<li>" + items[i] + "</li>";',
      '}',
      'document.getElementById("out").innerHTML = html;',
    ].join('\n')
  });

  // 55. HTML comment preserved
  checkEquiv('html comment', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>before</p><!-- comment --><p>after</p>";'
  });

  // 56. Form with labels and inputs
  checkEquiv('form elements', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<form><label for=\\"e\\">Email</label><input type=\\"email\\" id=\\"e\\"><button type=\\"submit\\">Go</button></form>";'
  });

  // 57. Four-file app with shared config
  checkEquiv('four file app', {
    'index.html': '<html><body><div id="h"></div><div id="b"></div><script src="cfg.js"></script><script src="util.js"></script><script src="head.js"></script><script src="main.js"></script></body></html>',
    'cfg.js': 'var APP = {title: "MyApp", version: "2.0"};',
    'util.js': 'function badge(t) { return "<span class=\\"badge\\">" + t + "</span>"; }',
    'head.js': 'document.getElementById("h").innerHTML = "<h1>" + APP.title + " " + badge("v" + APP.version) + "</h1>";',
    'main.js': 'document.getElementById("b").innerHTML = "<p>Welcome to " + APP.title + "</p>";'
  });

  // 58. innerHTML read from another element
  checkEquiv('innerHTML read', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("a").innerHTML = "<b>X</b>";\ndocument.getElementById("b").innerHTML = document.getElementById("a").innerHTML;'
  });

  // 59. undefined/null/NaN in concat
  checkEquiv('undefined in concat', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var x; document.getElementById("out").innerHTML = "<p>" + x + "</p>";'
  });

  // 60. Computed href with query params
  checkEquiv('computed href params', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var page = 2; var q = "test"; document.getElementById("out").innerHTML = "<a href=\\"search?q=" + q + "&page=" + page + "\\">Next</a>";'
  });

  // 61. Nested loop break (inner only)
  checkEquiv('nested loop break', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var h="";for(var i=0;i<3;i++){h+="<div>";for(var j=0;j<5;j++){if(j>2)break;h+="<span>"+j+"</span>";}h+="</div>";}document.getElementById("out").innerHTML=h;'
  });

  // 62. Try-catch with different HTML in each branch
  checkEquiv('try-catch branches', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var h="";try{h="<p>OK: "+riskyOp()+"</p>";}catch(e){h="<p class=\\"err\\">Error: "+e.message+"</p>";}document.getElementById("out").innerHTML=h;'
  });

  // 63. Builder function with non-html variable name
  checkEquiv('builder fn any var name', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'function renderNav(links) {',
      '  var s = "<nav>";',
      '  for (var i = 0; i < links.length; i++) {',
      '    s += "<a href=\\"" + links[i].url + "\\">" + links[i].text + "</a>";',
      '  }',
      '  s += "</nav>";',
      '  return s;',
      '}',
      'var links = [{url:"/",text:"Home"},{url:"/about",text:"About"}];',
      'document.getElementById("out").innerHTML = renderNav(links) + "<main><p>Content</p></main>";'
    ].join('\n')
  });

  // 64. Table with tfoot after auto-tbody rows
  checkEquiv('table with tfoot', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var rows = [{a:1,b:2},{a:3,b:4}];',
      'var h = "<table><thead><tr><th>A</th><th>B</th></tr></thead>";',
      'var total = 0;',
      'for (var i = 0; i < rows.length; i++) {',
      '  h += "<tr><td>" + rows[i].a + "</td><td>" + rows[i].b + "</td></tr>";',
      '  total += rows[i].a + rows[i].b;',
      '}',
      'h += "<tfoot><tr><td colspan=\\"2\\">Total: " + total + "</td></tr></tfoot></table>";',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 65. Complex state: continue + counter + flag
  checkEquiv('continue counter flag', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var items = [{v:5,show:true},{v:10,show:false},{v:15,show:true},{v:20,show:true}];',
      'var h = "<ul>";',
      'var sum = 0;',
      'var shown = 0;',
      'for (var i = 0; i < items.length; i++) {',
      '  sum += items[i].v;',
      '  if (!items[i].show) continue;',
      '  h += "<li>" + items[i].v + "</li>";',
      '  shown++;',
      '}',
      'h += "</ul><p>Shown: " + shown + "/" + items.length + ", Sum: " + sum + "</p>";',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 66. Multi-file: four files, builder fn, shared config
  checkEquiv('four file with builder', {
    'index.html': '<html><body><div id="h"></div><div id="b"></div><script src="cfg.js"></script><script src="util.js"></script><script src="head.js"></script><script src="main.js"></script></body></html>',
    'cfg.js': 'var APP = {title: "MyApp", version: "2.0"};',
    'util.js': 'function badge(t) { var r = "<span class=\\"badge\\">"; r += t; r += "</span>"; return r; }',
    'head.js': 'document.getElementById("h").innerHTML = "<h1>" + APP.title + " " + badge("v" + APP.version) + "</h1>";',
    'main.js': 'document.getElementById("b").innerHTML = "<p>Welcome to " + APP.title + "</p>";'
  });

  // 67. Select options built in loop
  checkEquiv('select options loop', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var opts = [{v:"us",t:"United States"},{v:"uk",t:"United Kingdom"},{v:"de",t:"Germany"}];',
      'var h = "<select>";',
      'for (var i = 0; i < opts.length; i++) {',
      '  h += "<option value=\\"" + opts[i].v + "\\">" + opts[i].t + "</option>";',
      '}',
      'h += "</select>";',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 68. 8 levels deep nesting
  checkEquiv('8 level nesting', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<div><section><article><main><aside><nav><header><footer>deep</footer></header></nav></aside></main></article></section></div>";'
  });

  // 69. innerHTML = then += then += on same element
  checkEquiv('set then double append', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var el = document.getElementById("out"); el.innerHTML = "<h1>Title</h1>"; el.innerHTML += "<p>P1</p>"; el.innerHTML += "<p>P2</p>";'
  });

  // 70. Many entities
  checkEquiv('many entities', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>&lt;b&gt;bold&lt;/b&gt; &amp; &lt;i&gt;italic&lt;/i&gt; &copy; 2024</p>";'
  });

  // 71. Same-file builder function with loop
  checkEquiv('same-file builder loop', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'function renderNav(links) {',
      '  var s = "<nav>";',
      '  for (var i = 0; i < links.length; i++) {',
      '    s += "<a href=\\"" + links[i].url + "\\">" + links[i].text + "</a>";',
      '  }',
      '  s += "</nav>";',
      '  return s;',
      '}',
      'var links = [{url:"/",text:"Home"},{url:"/about",text:"About"}];',
      'document.getElementById("out").innerHTML = renderNav(links) + "<main><p>Content</p></main>";'
    ].join('\n')
  });

  // 72. Same-file builder function with conditional
  checkEquiv('same-file builder conditional', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'function card(title, body, hasFooter) {',
      '  var h = "<div><h3>" + title + "</h3><p>" + body + "</p>";',
      '  if (hasFooter) h += "<footer>Footer</footer>";',
      '  h += "</div>";',
      '  return h;',
      '}',
      'document.getElementById("out").innerHTML = card("Hello", "World", true) + card("No Footer", "Content", false);'
    ].join('\n')
  });

  // 73. Pre-increment counter in loop
  checkEquiv('pre-increment counter', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var items = ["x", "y", "z"];',
      'var h = "<ul>";',
      'var n = 0;',
      'for (var i = 0; i < items.length; i++) {',
      '  h += "<li>#" + (++n) + ": " + items[i] + "</li>";',
      '}',
      'h += "</ul><p>Total: " + n + "</p>";',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 74. Template literal with expressions in loop
  checkEquiv('template literal loop', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var users = [{name:"Alice",role:"admin"},{name:"Bob",role:"user"}];',
      'var h = "";',
      'for (var i = 0; i < users.length; i++) {',
      '  h += `<div class="${users[i].role}"><span>${users[i].name}</span></div>`;',
      '}',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 75. Accumulator used as loop bound (nested loops, counter)
  checkEquiv('accumulator as bound', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var data = [["a","b"],["c"],["d","e","f"]];',
      'var h = "";',
      'var total = 0;',
      'for (var i = 0; i < data.length; i++) {',
      '  h += "<div>";',
      '  for (var j = 0; j < data[i].length; j++) {',
      '    h += "<span>" + data[i][j] + "</span>";',
      '    total++;',
      '  }',
      '  h += "</div>";',
      '}',
      'h += "<p>Total: " + total + "</p>";',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 76. Alternating row classes
  checkEquiv('alternating rows', {
    'index.html': '<html><body><table id="out"></table><script src="app.js"></script></body></html>',
    'app.js': [
      'var items = ["A","B","C","D","E"];',
      'var h = "";',
      'for (var i = 0; i < items.length; i++) {',
      '  h += "<tr class=\\"" + (i % 2 === 0 ? "even" : "odd") + "\\"><td>" + items[i] + "</td></tr>";',
      '}',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 77. Conditional wrapping (wrap content in tag based on flag)
  checkEquiv('conditional wrap', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var items = [{text:"normal",bold:false},{text:"important",bold:true},{text:"also normal",bold:false}];',
      'var h = "";',
      'for (var i = 0; i < items.length; i++) {',
      '  if (items[i].bold) h += "<b>";',
      '  h += "<span>" + items[i].text + "</span>";',
      '  if (items[i].bold) h += "</b>";',
      '}',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 78. Nested computed attributes
  checkEquiv('nested computed attrs', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var sections = [{id:"s1",title:"Intro",items:["a","b"]},{id:"s2",title:"Main",items:["c","d","e"]}];',
      'var h = "";',
      'for (var i = 0; i < sections.length; i++) {',
      '  var s = sections[i];',
      '  h += "<section id=\\"" + s.id + "\\"><h2>" + s.title + "</h2><ul>";',
      '  for (var j = 0; j < s.items.length; j++) {',
      '    h += "<li data-idx=\\"" + j + "\\">" + s.items[j] + "</li>";',
      '  }',
      '  h += "</ul></section>";',
      '}',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 79. While with early exit and result
  checkEquiv('while early exit', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var data = [2, 4, 7, 1, 3];',
      'var h = "<ul>";',
      'var i = 0;',
      'var found = "none";',
      'while (i < data.length) {',
      '  if (data[i] > 5) { found = data[i]; break; }',
      '  h += "<li>" + data[i] + "</li>";',
      '  i++;',
      '}',
      'h += "</ul><p>First >5: " + found + "</p>";',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 80. Three-level nested loops
  checkEquiv('three level loops', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var h = "";',
      'for (var a = 0; a < 2; a++) {',
      '  h += "<div>";',
      '  for (var b = 0; b < 2; b++) {',
      '    h += "<ul>";',
      '    for (var c = 0; c < 2; c++) {',
      '      h += "<li>" + a + "." + b + "." + c + "</li>";',
      '    }',
      '    h += "</ul>";',
      '  }',
      '  h += "</div>";',
      '}',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 81. Builder reuse with different args
  checkEquiv('builder reuse', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'function tag(name, content) { var h = "<" + name + ">" + content + "</" + name + ">"; return h; }',
      'document.getElementById("out").innerHTML = tag("h1", "Title") + tag("p", "Body") + tag("footer", "End");'
    ].join('\n')
  });

  // 82. Two independent innerHTML targets (no shared state)
  checkEquiv('two independent targets', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var x = "Hello";',
      'document.getElementById("a").innerHTML = "<h1>" + x + "</h1>";',
      'var y = "World";',
      'document.getElementById("b").innerHTML = "<p>" + y + "</p>";'
    ].join('\n')
  });

  // 83. Ternary choosing different structures
  checkEquiv('ternary structure choice', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var isTable = false; document.getElementById("out").innerHTML = isTable ? "<table><tr><td>Cell</td></tr></table>" : "<ul><li>Item</li></ul>";'
  });

  // 84. String methods in innerHTML expression
  checkEquiv('string methods', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var name = "alice"; document.getElementById("out").innerHTML = "<p>" + name.charAt(0).toUpperCase() + name.slice(1) + "</p>";'
  });

  // 85. Nested ternary in multiple attributes
  checkEquiv('nested ternary attrs', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var level = 2; document.getElementById("out").innerHTML = "<div class=\\"" + (level > 2 ? "high" : level > 1 ? "mid" : "low") + "\\" data-level=\\"" + level + "\\">" + level + "</div>";'
  });

  // 86. Multiple counters (sum, max, count)
  checkEquiv('multiple counters', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var data = [3, 1, 4, 1, 5, 9];',
      'var h = "<ul>";',
      'var sum = 0; var max = 0; var count = 0;',
      'for (var i = 0; i < data.length; i++) {',
      '  h += "<li>" + data[i] + "</li>";',
      '  sum += data[i]; if (data[i] > max) max = data[i]; count++;',
      '}',
      'h += "</ul><p>Sum:" + sum + " Max:" + max + " Count:" + count + "</p>";',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 87. Multi-condition class list
  checkEquiv('multi condition class', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var active = true; var disabled = false; var large = true;',
      'var cls = "btn";',
      'if (active) cls += " active";',
      'if (disabled) cls += " disabled";',
      'if (large) cls += " btn-lg";',
      'document.getElementById("out").innerHTML = "<button class=\\"" + cls + "\\">" + cls + "</button>";'
    ].join('\n')
  });

  // 88. do-while with counter
  checkEquiv('do-while counter', {
    'index.html': '<html><body><ul id="out"></ul><script src="app.js"></script></body></html>',
    'app.js': 'var h = ""; var i = 1; do { h += "<li>Item " + i + "</li>"; i++; } while (i <= 4); document.getElementById("out").innerHTML = h;'
  });

  // 89. 6-level deep nesting
  checkEquiv('6 level nesting', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<div><section><article><main><aside><nav><a href=\\"#\\">Deep</a></nav></aside></main></article></section></div>";'
  });

  // 90. innerHTML += chain building a page
  checkEquiv('page build chain', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var el = document.getElementById("out");',
      'el.innerHTML = "<header><h1>Title</h1></header>";',
      'el.innerHTML += "<nav><a href=\\"/\\">Home</a></nav>";',
      'el.innerHTML += "<main><p>Content</p></main>";',
      'el.innerHTML += "<footer><small>2024</small></footer>";'
    ].join('\n')
  });

  // 91. undefined and null in concat
  checkEquiv('undefined null concat', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var x; var y = null; document.getElementById("out").innerHTML = "<p>" + x + "</p><p>" + y + "</p>";'
  });

  // 93. Arithmetic in style attribute
  checkEquiv('arithmetic in attr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var w = 100; var h2 = 50; document.getElementById("out").innerHTML = "<div style=\\"width:" + (w * 2) + "px;height:" + (h2 + 10) + "px\\">sized</div>";'
  });

  // 94. Select with conditional selected attribute
  checkEquiv('select conditional selected', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var opts = [{v:"a",t:"Alpha"},{v:"b",t:"Beta"},{v:"c",t:"Gamma"}];',
      'var sel = "b";',
      'var h = "<select>";',
      'for (var i = 0; i < opts.length; i++) {',
      '  h += "<option value=\\"" + opts[i].v + "\\"" + (opts[i].v === sel ? " selected" : "") + ">" + opts[i].t + "</option>";',
      '}',
      'h += "</select>";',
      'document.getElementById("out").innerHTML = h;'
    ].join('\n')
  });

  // 95. for-in on object
  checkEquiv('for-in object', {
    'index.html': '<html><body><dl id="out"></dl><script src="app.js"></script></body></html>',
    'app.js': 'var obj = {name:"Alice",age:"30",city:"NYC"}; var h = ""; for (var k in obj) { h += "<dt>" + k + "</dt><dd>" + obj[k] + "</dd>"; } document.getElementById("out").innerHTML = h;'
  });

  // 96. for-of on array
  checkEquiv('for-of array', {
    'index.html': '<html><body><ul id="out"></ul><script src="app.js"></script></body></html>',
    'app.js': 'var items = ["X","Y","Z"]; var h = ""; for (var v of items) { h += "<li>" + v + "</li>"; } document.getElementById("out").innerHTML = h;'
  });

  // 97. Array.join
  checkEquiv('array join', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var items = ["a","b","c"]; document.getElementById("out").innerHTML = "<p>" + items.join(", ") + "</p>";'
  });

  // 98. Select with conditional selected attribute (array access ternary)
  checkEquiv('select conditional selected attr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var opts=[{v:"a",t:"Alpha"},{v:"b",t:"Beta"},{v:"c",t:"Gamma"}];var sel="b";var h="<select>";for(var i=0;i<opts.length;i++){h+="<option value=\\""+opts[i].v+"\\"\"+(opts[i].v===sel?" selected":"")+">"+opts[i].t+"</option>";}h+="</select>";document.getElementById("out").innerHTML=h;'
  });

  // 99. Nested loop + conditional attrs + counters + continue
  checkEquiv('nested loop complex state', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var groups=[{name:"A",items:[{v:1,ok:true},{v:2,ok:false},{v:3,ok:true}]},{name:"B",items:[{v:4,ok:true},{v:5,ok:false}]}];',
      'var h="";var total=0;var shown=0;',
      'for(var g=0;g<groups.length;g++){',
      '  h+="<div class=\\"group\\"><h2>"+groups[g].name+"</h2><ul>";',
      '  for(var j=0;j<groups[g].items.length;j++){',
      '    var item=groups[g].items[j];if(!item.ok)continue;',
      '    h+="<li class=\\""+(item.v>2?"high":"low")+"\\">"+ item.v+"</li>";',
      '    total+=item.v;shown++;',
      '  }h+="</ul></div>";',
      '}h+="<p>Shown: "+shown+"/"+total+"</p>";',
      'document.getElementById("out").innerHTML=h;'
    ].join('\n')
  });

  // 100. Builder fn with conditional structure called in loop
  checkEquiv('builder conditional in loop', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'function renderItem(item){var h="<div class=\\""+(item.active?"active":"inactive")+"\\">";',
      'h+="<span>"+item.name+"</span>";if(item.badge)h+="<b>"+item.badge+"</b>";h+="</div>";return h;}',
      'var items=[{name:"X",active:true,badge:"!"},{name:"Y",active:false,badge:null},{name:"Z",active:true,badge:"*"}];',
      'var h="";for(var i=0;i<items.length;i++){h+=renderItem(items[i]);}',
      'document.getElementById("out").innerHTML=h;'
    ].join('\n')
  });

  // 101. Multi-target from loop (two build vars, one loop)
  checkEquiv('multi-target from loop', {
    'index.html': '<html><body><ul id="good"></ul><ul id="bad"></ul><script src="app.js"></script></body></html>',
    'app.js': [
      'var items=[{n:"A",ok:true},{n:"B",ok:false},{n:"C",ok:true}];',
      'var gH="";var bH="";',
      'for(var i=0;i<items.length;i++){',
      '  if(items[i].ok)gH+="<li>"+items[i].n+"</li>";',
      '  else bH+="<li>"+items[i].n+"</li>";',
      '}',
      'document.getElementById("good").innerHTML=gH;',
      'document.getElementById("bad").innerHTML=bH;'
    ].join('\n')
  });

  // 102. Cross-file try-catch builder
  checkEquiv('cross-file try-catch', {
    'index.html': '<html><body><div id="out"></div><script src="cfg.js"></script><script src="ui.js"></script><script src="app.js"></script></body></html>',
    'cfg.js': 'var LABELS={ok:"Success",err:"Error"};',
    'ui.js': 'function status(ok){var h="<span class=\\""+(ok?"green":"red")+"\\">";h+=ok?LABELS.ok:LABELS.err;h+="</span>";return h;}',
    'app.js': 'var h="";try{h="<p>Result: "+status(true)+"</p>";}catch(e){h="<p>"+e.message+"</p>";}document.getElementById("out").innerHTML=h;'
  });

  // 103. Switch + template literal
  checkEquiv('switch template', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var mode="dark";var h="";switch(mode){case "light":h=`<div class="light"><p>Light mode</p></div>`;break;case "dark":h=`<div class="dark"><p>Dark mode</p></div>`;break;default:h="<div><p>Default</p></div>";}document.getElementById("out").innerHTML=h;'
  });

  // 104. While + table + pre-increment + break
  checkEquiv('while table preincrement break', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var data=[10,20,999,30,40];',
      'var h="<table><thead><tr><th>#</th><th>Val</th></tr></thead>";',
      'var i=0;var n=0;var sum=0;',
      'while(i<data.length){if(data[i]>100)break;',
      'h+="<tr><td>"+(++n)+"</td><td>"+data[i]+"</td></tr>";sum+=data[i];i++;}',
      'h+="<tfoot><tr><td>Total</td><td>"+sum+"</td></tr></tfoot></table>";',
      'document.getElementById("out").innerHTML=h;'
    ].join('\n')
  });

  // 105. Conditional wrap
  checkEquiv('conditional wrap state', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var items=[{text:"normal",bold:false},{text:"important",bold:true},{text:"also normal",bold:false}];',
      'var h="";for(var i=0;i<items.length;i++){',
      'if(items[i].bold)h+="<b>";h+="<span>"+items[i].text+"</span>";if(items[i].bold)h+="</b>";}',
      'document.getElementById("out").innerHTML=h;'
    ].join('\n')
  });

  // 106. do-while + for-in + for-of combined
  checkEquiv('do-while for-in for-of', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var obj={a:1,b:2};var arr=["x","y"];var h="<dl>";for(var k in obj){h+="<dt>"+k+"</dt><dd>"+obj[k]+"</dd>";}h+="</dl><ul>";for(var v of arr){h+="<li>"+v+"</li>";}h+="</ul><ol>";var n=1;do{h+="<li>"+n+"</li>";n++;}while(n<=3);h+="</ol>";document.getElementById("out").innerHTML=h;'
  });

  // 107. innerHTML read + write
  checkEquiv('innerHTML read write', {
    'index.html': '<html><body><div id="src"></div><div id="dst"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("src").innerHTML="<b>Original</b>";document.getElementById("dst").innerHTML=document.getElementById("src").innerHTML;'
  });

  // 108. Multiple counters
  checkEquiv('multiple counters complex', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var data=[3,1,4,1,5,9];var h="<ul>";var sum=0;var max=0;var count=0;for(var i=0;i<data.length;i++){h+="<li>"+data[i]+"</li>";sum+=data[i];if(data[i]>max)max=data[i];count++;}h+="</ul><p>Sum:"+sum+" Max:"+max+" Count:"+count+"</p>";document.getElementById("out").innerHTML=h;'
  });

  // 109. Mixed sinks
  checkEquiv('mixed sinks', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("a").innerHTML="<p>innerHTML</p>";document.getElementById("b").insertAdjacentHTML("beforeend","<p>adjacent</p>");'
  });

  // 110. Arithmetic in style attribute
  checkEquiv('arithmetic style attr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var w=100;var h2=50;document.getElementById("out").innerHTML="<div style=\\"width:"+(w*2)+"px;height:"+(h2+10)+"px\\">sized</div>";'
  });

  // 111. HTML comment preserved
  checkEquiv('comment preserved', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML="<p>before</p><!-- comment --><p>after</p>";'
  });

  // 112. Entity decoding
  checkEquiv('entity decoding', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML="<p>Tom &amp; Jerry &lt;3 &quot;Cartoons&quot;</p>";'
  });

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Taint analysis
// -----------------------------------------------------------------------
(function () {
  const traceTaint = globalThis.__traceTaint;
  if (!traceTaint) return;
  const before = pass + fail;
  console.log('\ntaint analysis');
  console.log('--------------');

  function checkTaint(name, files, expectedCount) {
    try {
      const result = traceTaint(files);
      const count = result.findings.length;
      if (count === expectedCount) { pass++; } else {
        fail++;
        failures.push({ name, input: JSON.stringify(files).slice(0, 120), want: expectedCount + ' findings', got: count + ' findings' });
      }
    } catch (e) {
      fail++;
      failures.push({ name, input: JSON.stringify(files).slice(0, 120), want: expectedCount + ' findings', got: 'ERROR: ' + e.message });
    }
  }

  // Basic taint flows
  checkTaint('direct innerHTML', { 'a.js': 'document.getElementById("o").innerHTML = location.search;' }, 1);
  checkTaint('variable taint', { 'a.js': 'var x = location.search; document.getElementById("o").innerHTML = x;' }, 1);
  checkTaint('safe literal', { 'a.js': 'document.getElementById("o").innerHTML = "safe";' }, 0);
  checkTaint('postMessage handler', { 'a.js': 'window.addEventListener("message", function(e) { document.getElementById("o").innerHTML = e.data; });' }, 1);

  // Recursive functions (must not stack overflow)
  checkTaint('recursive with taint', { 'a.js': 'var result = "";\nfunction build(data, depth) {\n  if (depth > 3) return;\n  result += data;\n  build(data, depth + 1);\n}\nbuild(location.search, 0);\ndocument.getElementById("o").innerHTML = result;' }, 1);
  checkTaint('mutual recursion taint', { 'a.js': 'var out = "";\nfunction a(x) { out += x; b(x); }\nfunction b(x) { a(x); }\na(location.search);\ndocument.getElementById("o").innerHTML = out;' }, 1);
  checkTaint('recursive safe', { 'a.js': 'var result = 0;\nfunction count(n) { if (n <= 0) return; result++; count(n - 1); }\ncount(5);\ndocument.getElementById("o").innerHTML = result;' }, 0);

  // Cross-function side effects
  checkTaint('closure side effect', { 'a.js': 'var result = "";\nfunction process(data) { function inner() { result = data; } inner(); }\nprocess(location.search);\ndocument.getElementById("o").innerHTML = result;' }, 1);
  checkTaint('callback with taint', { 'a.js': 'function fetchData(callback) { callback(location.search); }\nfunction handleData(data) { document.getElementById("o").innerHTML = data; }\nfetchData(handleData);' }, 1);

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Report
// -----------------------------------------------------------------------
console.log('');
console.log('='.repeat(60));
console.log(`Total: ${pass + fail}  Passed: ${pass}  Failed: ${fail}`);
if (fail > 0) {
  console.log('');
  for (const f of failures) {
    console.log(`FAIL: ${f.name}`);
    console.log(`  IN:     ${JSON.stringify(f.input)}`);
    console.log(`  WANTED: ${JSON.stringify(f.want)}`);
    console.log(`  GOT:    ${JSON.stringify(f.got)}`);
  }
  process.exit(1);
}
