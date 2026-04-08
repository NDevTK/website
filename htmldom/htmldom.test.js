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
  'globalThis.__extractHTML = extractHTML;\n  globalThis.__extractAllHTML = extractAllHTML;\n  globalThis.__extractAllDOM = extractAllDOM;\n  function extractHTML(input) {'
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
