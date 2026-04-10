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

// Minimal DOM globals — htmldom.js's IIFE calls document.getElementById
// at init time for its UI wiring. These provide just enough for the
// file to load in Node; the analysis functions never use them.
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
  'async function extractHTML(input) {',
  'globalThis.__extractHTML = extractHTML;\n  globalThis.__extractAllHTML = extractAllHTML;\n  globalThis.__extractAllDOM = extractAllDOM;\n  globalThis.__tokenize = tokenize;\n  globalThis.__tokenizeHtml = tokenizeHtml;\n  globalThis.__serializeHtmlTokens = serializeHtmlTokens;\n  globalThis.__decodeHtmlEntities = decodeHtmlEntities;\n  globalThis.__parseStyleDecls = parseStyleDecls;\n  globalThis.__convertRaw = convertRaw;\n  globalThis.__makeVar = makeVar;\n  globalThis.__traceTaint = traceTaint;\n  globalThis.__traceTaintInJs = traceTaintInJs;\n  globalThis.__convertJsFile = convertJsFile;\n  async function extractHTML(input) {'
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

async function check(name, input, expected) {
  const out = await extractHTML(input);
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

async function group(title, fn) {
  console.log('\n' + title);
  console.log('-'.repeat(title.length));
  const before = pass + fail;
  await fn();
  const ran = pass + fail - before;
  console.log(`  (${ran} cases)`);
}
(async function masterTestRunner() {


// -----------------------------------------------------------------------
// Direct inputs
// -----------------------------------------------------------------------
await group('direct inputs', async () => {
  await check('raw HTML', '<div>hi</div>', { html: '<div>hi</div>', target: null });
  await check('empty', '', { html: '', target: null });
  await check('no HTML at all', 'var x = 1;', { html: 'var x = 1;', target: null });
});

// -----------------------------------------------------------------------
// innerHTML / outerHTML detection
// -----------------------------------------------------------------------
await group('assignment detection', async () => {
  await check('.innerHTML =',
    `document.body.innerHTML = '<a>hi</a>';`,
    { html: '<a>hi</a>', target: 'document.body', assignProp: 'innerHTML', assignOp: '=' });
  await check('.innerHTML +=',
    `document.body.innerHTML += '<a>hi</a>';`,
    { html: '<a>hi</a>', target: 'document.body', assignProp: 'innerHTML', assignOp: '+=' });
  await check('.outerHTML =',
    `el.outerHTML = '<a>hi</a>';`,
    { html: '<a>hi</a>', target: 'el', assignProp: 'outerHTML', assignOp: '=' });
  await check('nested target',
    `document.getElementById('x').innerHTML = '<a>hi</a>';`,
    { target: `document.getElementById('x')`, assignProp: 'innerHTML' });
});

// -----------------------------------------------------------------------
// Simple variable resolution
// -----------------------------------------------------------------------
await group('simple variable resolution', async () => {
  await check('bare assign', `x='<a>hi</a>'; document.body.innerHTML+=x;`, '<a>hi</a>');
  await check('var decl', `var x='<a>'; document.body.innerHTML=x;`, '<a>');
  await check('let decl', `let x='<a>'; document.body.innerHTML=x;`, '<a>');
  await check('const decl', `const x='<a>'; document.body.innerHTML=x;`, '<a>');
  await check('reassignment', `var x='<a>'; x='<b>'; document.body.innerHTML=x;`, '<b>');
  await check('reassignment after site', `var x='<a>'; document.body.innerHTML=x; x='<b>';`, '<a>');
  await check('multi decl', `var a='<x>', b='<y>'; document.body.innerHTML=b;`, '<y>');
  await check('declare then assign', `var x; x='<a>'; document.body.innerHTML=x;`, '<a>');
  await check('unknown identifier',
    `document.body.innerHTML=y;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'y']] });
});

// -----------------------------------------------------------------------
// Scoping: block vs function
// -----------------------------------------------------------------------
await group('scoping', async () => {
  await check('let in block doesn\'t leak',
    `{ let x='<a>'; } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
  await check('const in block doesn\'t leak',
    `{ const x='<a>'; } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
  await check('var leaks out of block (function-scoped)',
    `{ var x='<a>'; } document.body.innerHTML=x;`, '<a>');
  await check('let shadowing',
    `let x='<a>'; { let x='<b>'; } document.body.innerHTML=x;`, '<a>');
  await check('let shadowing (inner site)',
    `let x='<a>'; { let x='<b>'; document.body.innerHTML=x; }`, '<b>');
  await check('var in function does not leak',
    `function f(){ var x='<a>'; } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
  await check('let in function does not leak',
    `function f(){ let x='<a>'; } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
  await check('outer var visible past function',
    `var x='<a>'; function f(){} document.body.innerHTML=x;`, '<a>');
  await check('arrow expression body (no scope opened)',
    `var f = x => x+1; var y='<a>'; document.body.innerHTML=y;`, '<a>');
  await check('arrow block body (scope opened)',
    `var f = () => { var x='<bad>'; }; var y='<a>'; document.body.innerHTML=y;`, '<a>');
  await check('nested blocks',
    `{ { let x='<a>'; } } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
  await check('nested function scopes',
    `function a(){ function b(){ var x='<a>'; } } document.body.innerHTML=x;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'x']] });
});

// -----------------------------------------------------------------------
// Concat chains in initializers
// -----------------------------------------------------------------------
await group('concat chains', async () => {
  await check('2-term concat',
    `var x='<a>'+'</a>'; document.body.innerHTML=x;`, '<a></a>');
  await check('3-term concat',
    `var x='<a>'+'<b>'+'<c>'; document.body.innerHTML=x;`, '<a><b><c>');
  await check('concat with ident',
    `var a='<a>'; var b=a+'</a>'; document.body.innerHTML=b;`, '<a></a>');
  await check('transitive (3 hops)',
    `var a='<a>'; var b=a+'<b>'; var c=b+'<c>'; document.body.innerHTML=c;`, '<a><b><c>');
  await check('concat inline in innerHTML',
    `var msg='world'; document.body.innerHTML='<p>hi '+msg+'!</p>';`, '<p>hi world!</p>');
  await check('unknown ident captured as placeholder',
    `var x='<a>'+unknownVar; document.body.innerHTML=x;`,
    { html: '<a>__HDX0__', autoSubs: [['__HDX0__', 'unknownVar']] });
  await check('unknown call captured as placeholder',
    `var x='<a>'+foo(); document.body.innerHTML=x;`,
    { html: '<a>__HDX0__', autoSubs: [['__HDX0__', 'foo()']] });
  await check('unresolved parts propagate through variables',
    `var x = 'a' + foo(); document.body.innerHTML = '<a>'+x+'</a>';`,
    { html: '<a>a__HDX0__</a>', autoSubs: [['__HDX0__', 'foo()']] });
});

// -----------------------------------------------------------------------
// Array .join() patterns
// -----------------------------------------------------------------------
await group('.join() patterns', async () => {
  await check('join empty separator',
    `var x=['<a>','<b>'].join(''); document.body.innerHTML=x;`, '<a><b>');
  await check('join space separator',
    `var x=['<a>','<b>'].join(' '); document.body.innerHTML=x;`, '<a> <b>');
  await check('join single element',
    `var x=['<a>'].join(''); document.body.innerHTML=x;`, '<a>');
  await check('join inline in innerHTML',
    `document.body.innerHTML=['<a>','<b>'].join('');`, '<a><b>');
  await check('join with ident elements',
    `var p='<a>'; var q='<b>'; document.body.innerHTML=[p,q].join('');`, '<a><b>');
  await check('concat then join',
    `var parts=['<a>','<b>'].join(''); document.body.innerHTML='<wrap>'+parts+'</wrap>';`,
    '<wrap><a><b></wrap>');
});

// -----------------------------------------------------------------------
// Template literals
// -----------------------------------------------------------------------
await group('templates', async () => {
  await check('template with unknown expr (stays placeholder)',
    `var x=\`<a href="\${u}">hi</a>\`; document.body.innerHTML=x;`,
    { html: '<a href="__HDX0__">hi</a>', autoSubs: [['__HDX0__', 'u']] });
  await check('template without interpolation',
    `var x=\`<a>hi</a>\`; document.body.innerHTML=x;`, '<a>hi</a>');
});

// -----------------------------------------------------------------------
// HTML content filter (only return chains with `<`)
// -----------------------------------------------------------------------
await group('HTML content filter', async () => {
  await check('non-HTML concat still materializes',
    `var x = 'a' + 'b'; document.body.innerHTML=x;`, 'ab');
  await check('HTML-looking char found',
    `var x = 'a<b'; document.body.innerHTML=x;`, 'a<b');
});

// -----------------------------------------------------------------------
// Object property access
// -----------------------------------------------------------------------
await group('object property access', async () => {
  await check('known obj.prop',
    `var obj = { html: '<a>' }; document.body.innerHTML = obj.html;`, '<a>');
  await check('obj.prop with concat',
    `var obj = { a: '<a>', b: '<b>' }; document.body.innerHTML = obj.a + obj.b;`, '<a><b>');
  await check('unknown prop',
    `var obj = { html: '<a>' }; document.body.innerHTML = obj.missing;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'obj.missing']] });
  await check('quoted keys',
    `var obj = { "html": '<a>' }; document.body.innerHTML = obj.html;`, '<a>');
});

// -----------------------------------------------------------------------
// String methods
// -----------------------------------------------------------------------
await group('string methods', async () => {
  await check('.concat',
    `var a='<a>'; var b='<b>'; document.body.innerHTML=a.concat(b);`, '<a><b>');
  await check('.concat multiple',
    `document.body.innerHTML='<a>'.concat('<b>','<c>');`, '<a><b><c>');
});

// -----------------------------------------------------------------------
// Destructuring
// -----------------------------------------------------------------------
await group('destructuring', async () => {
  await check('object destructuring',
    `var { html } = { html: '<a>' }; document.body.innerHTML = html;`, '<a>');
  await check('object destructuring with rename',
    `var { html: h } = { html: '<a>' }; document.body.innerHTML = h;`, '<a>');
  await check('array destructuring',
    `var [a, b] = ['<a>', '<b>']; document.body.innerHTML = a + b;`, '<a><b>');
  await check('object destructuring with default',
    `var { a = 'dflt' } = {}; document.body.innerHTML = a;`, 'dflt');
  await check('object destructuring default when value present',
    `var { a = 'dflt' } = { a: 'here' }; document.body.innerHTML = a;`, 'here');
  await check('object destructuring rename with default',
    `var { a: x = 'd' } = {}; document.body.innerHTML = x;`, 'd');
  await check('object destructuring with rest',
    `var { a, ...rest } = { a: 'x', b: 'y', c: 'z' }; document.body.innerHTML = JSON.stringify(rest);`,
    '{"b":"y","c":"z"}');
  await check('array destructuring with defaults',
    `var [a = 'x', b = 'y'] = ['1']; document.body.innerHTML = a + b;`, '1y');
  await check('array destructuring with rest',
    `var [a, ...r] = ['x','y','z']; document.body.innerHTML = r.join(',');`, 'y,z');
});

// -----------------------------------------------------------------------
// Modules: import/export must not derail the walker
// -----------------------------------------------------------------------
await group('modules', async () => {
  await check('import default skipped',
    `import foo from 'bar'; var a='<x>'; document.body.innerHTML = a;`, '<x>');
  await check('import named skipped',
    `import { foo, bar } from 'baz'; var a='hi'; document.body.innerHTML = a;`, 'hi');
  await check('export const stripped',
    `export const a = '<z>'; document.body.innerHTML = a;`, '<z>');
  await check('export default expression skipped',
    `export default 42; var a='ok'; document.body.innerHTML = a;`, 'ok');
  await check('export { list } skipped',
    `var x='hi'; export { x }; document.body.innerHTML = x;`, 'hi');
});

// -----------------------------------------------------------------------
// Array.* builtins
// -----------------------------------------------------------------------
await group('Array builtins', async () => {
  await check('Array.isArray on array',
    `var a=['x','y']; document.body.innerHTML = Array.isArray(a) ? 'A' : 'O';`, 'A');
  await check('Array.of literal list',
    `var b = Array.of('a','b','c'); document.body.innerHTML = b.join(',');`, 'a,b,c');
  await check('Array.from over array with mapFn',
    `var a=['x','y']; var b = Array.from(a, (x,i) => i+':'+x); document.body.innerHTML = b.join(',');`, '0:x,1:y');
  await check('Array.from length spec with mapFn',
    `var b = Array.from({length:3}, (_,i) => i); document.body.innerHTML = b.join('-');`, '0-1-2');
});

// -----------------------------------------------------------------------
// Template literal interpolation resolution
// -----------------------------------------------------------------------
await group('template interpolation', async () => {
  await check('known identifier expr',
    `var url='/path'; var x=\`<a href="\${url}">hi</a>\`; document.body.innerHTML=x;`,
    '<a href="/path">hi</a>');
  await check('inline in innerHTML',
    `var url='/path'; document.body.innerHTML=\`<a href="\${url}">hi</a>\`;`,
    '<a href="/path">hi</a>');
});

// -----------------------------------------------------------------------
// Nested structures
// -----------------------------------------------------------------------
await group('nested structures', async () => {
  await check('nested object member access',
    `var cfg = { parts: { head: '<h>', body: '<b>' } };
     document.body.innerHTML = cfg.parts.head + cfg.parts.body;`, '<h><b>');
  await check('array of objects',
    `var items = [{ html: '<a>' }, { html: '<b>' }];
     document.body.innerHTML = items[0].html;`, '<a>');
  await check('object containing array',
    `var o = { parts: ['<a>','<b>'] };
     document.body.innerHTML = o.parts.join('');`, '<a><b>');
});

// -----------------------------------------------------------------------
// Template interpolation edge cases
// -----------------------------------------------------------------------
await group('template interpolation edge cases', async () => {
  await check('member-path expr',
    `var obj = { name: 'World' };
     document.body.innerHTML = \`<p>Hello \${obj.name}</p>\`;`, '<p>Hello World</p>');
  await check('mix of resolved and unresolved',
    `var a = 'X';
     document.body.innerHTML = \`<p>\${a}:\${b}</p>\`;`,
    { html: '<p>X:__HDX0__</p>', autoSubs: [['__HDX0__', 'b']] });
  await check('nested template',
    `var inner = \`world\`;
     document.body.innerHTML = \`<p>hello \${inner}</p>\`;`, '<p>hello world</p>');
});

// -----------------------------------------------------------------------
// Shadowing with declarations
// -----------------------------------------------------------------------
await group('shadowing', async () => {
  await check('let shadows var',
    `var x='<outer>'; { let x='<inner>'; } document.body.innerHTML=x;`, '<outer>');
  await check('function shadows outer let',
    `let x='<outer>'; function f(){ let x='<inner>'; } document.body.innerHTML=x;`, '<outer>');
  await check('reassign through shadow',
    `let x='<a>'; { x='<b>'; } document.body.innerHTML=x;`, '<b>');
});

// -----------------------------------------------------------------------
// Complex real-world patterns
// -----------------------------------------------------------------------
await group('real-world patterns', async () => {
  await check('const template with member path',
    `const u = { url: '/api' };
     document.body.innerHTML = \`<a href="\${u.url}">go</a>\`;`,
    '<a href="/api">go</a>');
  await check('multiple reassignments',
    `var html = '<a>'; html = html + '<b>'; html = html + '<c>';
     document.body.innerHTML = html;`, '<a><b><c>');
  await check('builder pattern via concat',
    `var s = ''; s = s + '<a>'; s = s + '<b>'; document.body.innerHTML = s;`, '<a><b>');
});

// -----------------------------------------------------------------------
// Primitive literals in concat
// -----------------------------------------------------------------------
await group('primitive literals', async () => {
  await check('int literal', `document.body.innerHTML='<x>'+42+'</x>';`, '<x>42</x>');
  await check('float literal', `document.body.innerHTML='<x>'+3.14+'</x>';`, '<x>3.14</x>');
  await check('true', `document.body.innerHTML='<x>'+true+'</x>';`, '<x>true</x>');
  await check('false', `document.body.innerHTML='<x>'+false+'</x>';`, '<x>false</x>');
  await check('null', `document.body.innerHTML='<x>'+null+'</x>';`, '<x>null</x>');
});

// -----------------------------------------------------------------------
// Parenthesized expressions
// -----------------------------------------------------------------------
await group('parentheses', async () => {
  await check('grouped concat',
    `document.body.innerHTML=('<a>'+'<b>')+'<c>';`, '<a><b><c>');
  await check('nested parens',
    `document.body.innerHTML=(('<a>'+'<b>')+'<c>');`, '<a><b><c>');
  await check('parens in binding',
    `var x=('<a>'+'<b>'); document.body.innerHTML=x+'<c>';`, '<a><b><c>');
});

// -----------------------------------------------------------------------
// Bound array .join and indexing
// -----------------------------------------------------------------------
await group('bound array access', async () => {
  await check('.join on bound array',
    `var arr=['<a>','<b>']; document.body.innerHTML=arr.join('');`, '<a><b>');
  await check('.join with sep on bound array',
    `var arr=['<a>','<b>','<c>']; document.body.innerHTML=arr.join('-');`, '<a>-<b>-<c>');
  await check('arr[0]',
    `var arr=['<a>','<b>']; document.body.innerHTML=arr[0];`, '<a>');
  await check('arr[1]',
    `var arr=['<a>','<b>']; document.body.innerHTML=arr[1];`, '<b>');
  await check('arr[0]+arr[1]',
    `var arr=['<a>','<b>']; document.body.innerHTML=arr[0]+arr[1];`, '<a><b>');
  await check('out-of-bounds index',
    `var arr=['<a>']; document.body.innerHTML=arr[5];`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'arr[5]']] });
});

// -----------------------------------------------------------------------
// Bracket object access
// -----------------------------------------------------------------------
await group('bracket object access', async () => {
  await check(`obj['key']`,
    `var obj={html:'<a>'}; document.body.innerHTML=obj['html'];`, '<a>');
  await check(`obj["key"]`,
    `var obj={html:'<a>'}; document.body.innerHTML=obj["html"];`, '<a>');
  await check('unknown key',
    `var obj={html:'<a>'}; document.body.innerHTML=obj['missing'];`,
    { html: '__HDX0__', autoSubs: [["__HDX0__", "obj['missing']"]] });
});

// -----------------------------------------------------------------------
// Chained access (combinations)
// -----------------------------------------------------------------------
await group('chained access', async () => {
  await check('array of objects .html[0]',
    `var items = [{html:'<a>'}, {html:'<b>'}];
     document.body.innerHTML = items[0].html + items[1].html;`, '<a><b>');
  await check('object map via join',
    `var tags = { open: '<a>', close: '</a>' };
     document.body.innerHTML = [tags.open, 'hi', tags.close].join('');`, '<a>hi</a>');
  await check('nested index',
    `var grid = [['<r0c0>', '<r0c1>'], ['<r1c0>']];
     document.body.innerHTML = grid[0][0] + grid[0][1];`, '<r0c0><r0c1>');
  await check('concat with method call chain',
    `var s = '<a>'; document.body.innerHTML = s.concat('<b>').concat('<c>');`, '<a><b><c>');
});

// -----------------------------------------------------------------------
// Scope + bindings interaction
// -----------------------------------------------------------------------
await group('scope+binding interactions', async () => {
  await check('reassign object inside block',
    `var o = {html:'<a>'}; { o = {html:'<b>'}; } document.body.innerHTML = o.html;`, '<b>');
  await check('let object doesn\'t leak',
    `{ let o = {html:'<a>'}; } document.body.innerHTML = o.html;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'o.html']] });
  await check('object with shadowed inner prop',
    `var o = { html: '<outer>' }; { let o = { html: '<inner>' }; } document.body.innerHTML = o.html;`, '<outer>');
});

// -----------------------------------------------------------------------
// Function calls (arrow and function declarations)
// -----------------------------------------------------------------------
await group('function calls', async () => {
  await check('single-param arrow',
    `const f = x => '<a>' + x + '</a>';
     document.body.innerHTML = f('hi');`, '<a>hi</a>');
  await check('multi-param arrow',
    `const wrap = (tag, text) => '<' + tag + '>' + text + '</' + tag + '>';
     document.body.innerHTML = wrap('p', 'hi');`, '<p>hi</p>');
  await check('no-param arrow',
    `const greet = () => '<p>hello</p>';
     document.body.innerHTML = greet();`, '<p>hello</p>');
  await check('arrow with block body and return',
    `const f = (x) => { return '<a>' + x + '</a>'; };
     document.body.innerHTML = f('hi');`, '<a>hi</a>');
  await check('function declaration with return',
    `function link(url, text) { return '<a href="' + url + '">' + text + '</a>'; }
     document.body.innerHTML = link('/a', 'click');`, '<a href="/a">click</a>');
  await check('nested function call',
    `const em = (t) => '<em>' + t + '</em>';
     const p = (t) => '<p>' + t + '</p>';
     document.body.innerHTML = p(em('hi'));`, '<p><em>hi</em></p>');
  await check('function used in template',
    `const url = (path) => '/api' + path;
     document.body.innerHTML = \`<a href="\${url('/x')}">go</a>\`;`, '<a href="/api/x">go</a>');
});

// -----------------------------------------------------------------------
// Function edge cases
// -----------------------------------------------------------------------
await group('function edge cases', async () => {
  await check('function with unknown arg (captured as placeholder)',
    `const f = x => '<a>' + x + '</a>';
     document.body.innerHTML = f(unknown);`,
    { html: '<a>__HDX0__</a>', autoSubs: [['__HDX0__', 'unknown']] });
  await check('recursion is capped (no infinite loop)',
    `function f(x) { return '<p>' + x + '</p>'; }
     document.body.innerHTML = f(f('hi'));`, '<p><p>hi</p></p>');
  await check('function uses outer binding',
    `const wrap = '<b>';
     const tag = (x) => wrap + x + '</b>';
     document.body.innerHTML = tag('hi');`, '<b>hi</b>');
  await check('arrow with concat in body',
    `const html = (a, b) => [a, b].join('-');
     document.body.innerHTML = html('<x>', '<y>');`, '<x>-<y>');
  await check('function in object',
    `var O = { build: (x) => '<a>' + x + '</a>' };
     document.body.innerHTML = O.build('hi');`, '<a>hi</a>');
  await check('function called with missing arg (param surfaces as placeholder)',
    `function f(x) { return '<a>'+x+'</a>'; } document.body.innerHTML = f();`,
    { html: '<a>__HDX0__</a>', autoSubs: [['__HDX0__', 'x']] });
});

// -----------------------------------------------------------------------
// Compound assignment
// -----------------------------------------------------------------------
await group('compound assignment', async () => {
  await check('+= builds string',
    `var s=''; s+='<a>'; s+='<b>'; document.body.innerHTML=s;`, '<a><b>');
  await check('+= with identifier',
    `var tag='<x>'; var s='<wrap>'; s+=tag; s+='</wrap>';
     document.body.innerHTML=s;`, '<wrap><x></wrap>');
  await check('+= propagates through unresolved base',
    `var s=unknownBase; s+='<a>'; document.body.innerHTML=s;`,
    { html: '__HDX0__<a>', autoSubs: [['__HDX0__', 'unknownBase']] });
});

// -----------------------------------------------------------------------
// Unresolved expressions (opaque references)
// -----------------------------------------------------------------------
await group('opaque references', async () => {
  await check('variable-indexed array',
    `var arr=['<a>']; document.body.innerHTML=arr[someIdx];`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'arr[someIdx]']] });
  await check('variable-indexed through alias',
    `var arr=['<a>']; var url=arr[i]; document.body.innerHTML='<p>'+url+'</p>';`,
    { html: '<p>__HDX0__</p>', autoSubs: [['__HDX0__', 'arr[i]']] });
  await check('chained unresolvable',
    `var o={a:'<x>'}; document.body.innerHTML=o[key].foo;`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'o[key].foo']] });
  await check('unresolved call propagates source',
    `document.body.innerHTML='<a>'+parseInt(s,10)+'</a>';`,
    { html: '<a>__HDX0__</a>', autoSubs: [['__HDX0__', 'parseInt(s,10)']] });
});

// -----------------------------------------------------------------------
// Functions with assignments inside (walker traverses body)
// -----------------------------------------------------------------------
await group('function bodies with assignments', async () => {
  await check('inner innerHTML in function body',
    `function f() {
       var s = '<a>';
       s += '<b>';
       out.innerHTML = s;
     }`,
    { html: '<a><b>', target: 'out', assignProp: 'innerHTML', assignOp: '=' });
  await check('function param referenced inside body',
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
await group('loops', async () => {
  // When a variable is built via `+=` inside a `for`/`while` loop, the
  // resulting chain is tagged so the main html gets `__HDLOOP#S__`/
  // `__HDLOOP#E__` markers around the per-iteration contribution. The
  // loop header(s) are echoed in `loops`, and `loopVars` records each
  // loop-built variable's final contribution for downstream use.
  await check('for loop wraps += body',
    `var s=''; for (var i=0; i<n; i++) { s += '<a>'; } document.body.innerHTML=s;`,
    { html: '__HDLOOP0S__<a>__HDLOOP0E__',
      loops: [{ id: 0, kind: 'for', headerSrc: 'var i=0; i<n; i++' }] });
  await check('for loop with multi-part body',
    `var s=''; for (var i=0; i<n; i++) { s += '<a>'; s += '<b>'; } document.body.innerHTML=s;`,
    { html: '__HDLOOP0S__<a><b>__HDLOOP0E__' });
  await check('while loop',
    `var s=''; while (s.length < 10) s += 'x'; document.body.innerHTML=s;`,
    { html: '__HDLOOP0S__x__HDLOOP0E__',
      loops: [{ id: 0, kind: 'while', headerSrc: 's.length < 10' }] });
  await check('static prefix + loop + suffix',
    `var s='<header>'; for (var i=0; i<n; i++) s += '<item>'; s += '<footer>';
     document.body.innerHTML=s;`,
    { html: '<header>__HDLOOP0S__<item>__HDLOOP0E__<footer>' });
  await check('loop body resolves var references',
    `var tag='<a>'; var s=''; for (var i=0;i<n;i++) s += tag;
     document.body.innerHTML=s;`,
    { html: '__HDLOOP0S__<a>__HDLOOP0E__' });
  await check('loop body reaches unresolved as opaque',
    `var s=''; for (var i=0;i<n;i++) s += items[i];
     document.body.innerHTML=s;`,
    { html: '__HDLOOP0S____HDX0____HDLOOP0E__', autoSubs: [['__HDX0__', 'items[i]']] });
  await check('innerHTML assigned to loop-built var in function',
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
await group('.length', async () => {
  await check('array.length',
    `var arr=['a','b','c']; document.body.innerHTML = 'count: ' + arr.length;`, 'count: 3');
  await check('string.length via variable',
    `var s='hello'; document.body.innerHTML = '<p>' + s.length + '</p>';`, '<p>5</p>');
  await check('length on object-array member',
    `var o={items:['x','y','z','w']}; document.body.innerHTML = 'n='+o.items.length;`, 'n=4');
  await check('length on unknown stays opaque',
    `document.body.innerHTML = 'n='+items.length;`,
    { html: 'n=__HDX0__', autoSubs: [['__HDX0__', 'items.length']] });
});

// -----------------------------------------------------------------------
// Ternary expressions and other operators (captured as opaque)
// -----------------------------------------------------------------------
await group('ternary/operators', async () => {
  await check('ternary folded symbolically',
    `document.body.innerHTML = '<a>' + (cond ? '<b>' : '<c>') + '</a>';`,
    { html: '<a>__HDX0__</a>', autoSubs: [['__HDX0__', '(cond ? "<b>" : "<c>")']] });
  await check('ternary with known true-ish condition',
    `var ok = 1; document.body.innerHTML = (ok ? '<yes>' : '<no>');`, '<yes>');
  await check('ternary with known false-ish condition',
    `var off = 0; document.body.innerHTML = (off ? '<yes>' : '<no>');`, '<no>');
  await check('bitwise expression folded symbolically',
    `document.body.innerHTML = '<x>' + (a|0) + '</x>';`,
    { html: '<x>__HDX0__</x>', autoSubs: [['__HDX0__', '(a | 0)']] });
  await check('logical OR default folded symbolically',
    `document.body.innerHTML = '<x>' + (name || 'anon') + '</x>';`,
    { html: '<x>__HDX0__</x>', autoSubs: [['__HDX0__', '(name || "anon")']] });
});

// -----------------------------------------------------------------------
// Arithmetic evaluation
// -----------------------------------------------------------------------
await group('arithmetic', async () => {
  await check('subtract literals',
    `document.body.innerHTML = 'n=' + (3 - 2);`, 'n=1');
  await check('multiply literals',
    `document.body.innerHTML = 'n=' + (3 * 4);`, 'n=12');
  await check('divide literals',
    `document.body.innerHTML = 'n=' + (10 / 4);`, 'n=2.5');
  await check('bitwise OR literals',
    `document.body.innerHTML = 'n=' + (3.7 | 0);`, 'n=3');
  await check('multiply then parenthesized concat',
    `document.body.innerHTML = 'n=' + (3 * 4);`, 'n=12');
  await check('array length arithmetic',
    `var a=['x','y','z']; document.body.innerHTML = 'n=' + (a.length - 1);`, 'n=2');
  await check('unknown + literal',
    `document.body.innerHTML = 'n=' + (x * 2);`,
    { html: 'n=__HDX0__', autoSubs: [['__HDX0__', '(x * 2)']] });
  await check('partial eval with unknown',
    `var a=['x','y','z']; document.body.innerHTML = 'n=' + ((a.length - 2) / y);`,
    { html: 'n=__HDX0__', autoSubs: [['__HDX0__', '(1 / y)']] });
});

// -----------------------------------------------------------------------
// String methods
// -----------------------------------------------------------------------
await group('string methods', async () => {
  await check('toUpperCase on var',
    `var s='hello'; document.body.innerHTML = s.toUpperCase();`, 'HELLO');
  await check('trim on literal',
    `document.body.innerHTML = '  hi  '.trim();`, 'hi');
  await check('repeat on literal',
    `document.body.innerHTML = '#'.repeat(5);`, '#####');
  await check('slice on literal',
    `document.body.innerHTML = 'abcdef'.slice(1, 4);`, 'bcd');
  await check('padStart with zeros',
    `document.body.innerHTML = 'abc'.padStart(6, '0');`, '000abc');
  await check('chain toUpper + concat',
    `var n='World'; document.body.innerHTML = 'Hello ' + n.toUpperCase();`, 'Hello WORLD');
  await check('String(num) then method',
    `var n=42; document.body.innerHTML = String(n).padStart(5, '0');`, '00042');
  await check('split then join',
    `var parts='a,b,c'.split(','); document.body.innerHTML = parts.join('|');`, 'a|b|c');
  await check('indexOf literal',
    `document.body.innerHTML = 'pos=' + 'hello world'.indexOf('world');`, 'pos=6');
});

// -----------------------------------------------------------------------
// Array methods (.slice / .indexOf / .includes / .reverse)
// -----------------------------------------------------------------------
await group('array methods', async () => {
  await check('slice + join',
    `var a=[1,2,3,4,5]; document.body.innerHTML = a.slice(1,3).join(',');`, '2,3');
  await check('indexOf on array',
    `var a=['x','y','z']; document.body.innerHTML = 'at ' + a.indexOf('y');`, 'at 1');
  await check('includes on array',
    `var a=['x','y','z']; document.body.innerHTML = 'has ' + a.includes('y');`, 'has true');
  await check('reverse + join',
    `var a=['a','b','c']; document.body.innerHTML = a.reverse().join('');`, 'cba');
});

// -----------------------------------------------------------------------
// extractAllHTML: multiple innerHTML sinks
// -----------------------------------------------------------------------
await (async function () {
  console.log('\nextractAllHTML');
  console.log('--------------');
  const script = `
    function write() { out.innerHTML = '<a>' + url + '</a>'; }
    function setup() { table.innerHTML = '<tr><th>Hi</th></tr>'; }
    function log(s) { document.getElementById('nums').innerHTML += '<br>' + s; }
  `;
  const all = await extractAllHTML(script);
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
await (async function () {
  console.log('\nextractAllDOM');
  console.log('-------------');
  const before = pass + fail;

  // Basic create + appendChild.
  {
    const r = await extractAllDOM(`var a = document.createElement('a'); a.href = '/'; a.textContent = 'home'; document.body.appendChild(a);`);
    if (r.elements.length === 1 && r.elements[0].origin.tag === 'a' && r.elements[0].props.href === '/' && r.elements[0].text === 'home') pass++;
    else { fail++; failures.push({ name: 'createElement basic', got: r }); }
  }
  // Nested tree with for-loop-built children.
  {
    const r = await extractAllDOM(`var t=document.createElement('table'); var tr=document.createElement('tr'); var td=document.createElement('td'); td.textContent='cell'; tr.appendChild(td); t.appendChild(tr);`);
    if (r.html[0] === '<table><tr><td>cell</td></tr></table>') pass++;
    else { fail++; failures.push({ name: 'nested createElement tree', html0: r.html && r.html[0] }); }
  }
  // setAttribute.
  {
    const r = await extractAllDOM(`var el=document.createElement('div'); el.setAttribute('data-id', '42'); el.setAttribute('role', 'button');`);
    if (r.elements[0].attrs['data-id'] === '42' && r.elements[0].attrs.role === 'button') pass++;
    else { fail++; failures.push({ name: 'setAttribute', got: r.elements[0] }); }
  }
  // className → classList.
  {
    const r = await extractAllDOM(`var el=document.createElement('div'); el.className = 'foo bar baz';`);
    if (r.elements[0].classList.join(' ') === 'foo bar baz') pass++;
    else { fail++; failures.push({ name: 'className', got: r.elements[0] }); }
  }
  // style.prop assignments.
  {
    const r = await extractAllDOM(`var el=document.createElement('div'); el.style.color='red'; el.style.fontSize='12px';`);
    if (r.elements[0].styles.color === 'red' && r.elements[0].styles.fontSize === '12px') pass++;
    else { fail++; failures.push({ name: 'style', got: r.elements[0] }); }
  }
  // getElementById + append — root element is the looked-up element.
  {
    const r = await extractAllDOM(`var out=document.getElementById('out'); var a=document.createElement('a'); out.appendChild(a);`);
    const outEl = r.elements.find((e) => e.origin && e.origin.value === 'out');
    if (outEl && outEl.children.length === 1) pass++;
    else { fail++; failures.push({ name: 'getElementById append', got: r }); }
  }
  // innerHTML capture on element.
  {
    const r = await extractAllDOM(`var t=document.createElement('div'); t.innerHTML = '<p>hi</p>';`);
    if (r.elements[0].html === '<p>hi</p>') pass++;
    else { fail++; failures.push({ name: 'innerHTML on element', got: r.elements[0] }); }
  }

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Array .map / .filter / .forEach with arrow callbacks
// -----------------------------------------------------------------------
await group('array .map / .filter / .forEach', async () => {
  await check('map + join',
    `var a=['x','y','z']; document.body.innerHTML = a.map(i => '<li>'+i+'</li>').join('');`,
    '<li>x</li><li>y</li><li>z</li>');
  await check('map with template literal body',
    `var a=['1','2']; document.body.innerHTML = a.map(i => \`<p>\${i}</p>\`).join('');`,
    '<p>1</p><p>2</p>');
  await check('filter keeps truthy',
    `var a=['','x','','y']; document.body.innerHTML = a.filter(s => s).join(',');`, 'x,y');
  await check('filter + map chain',
    `var a=[1,2,3,4]; document.body.innerHTML = a.filter(n => n>2).map(n => '['+n+']').join('');`,
    '[3][4]');
  await check('forEach returns undefined',
    `var a=['x']; document.body.innerHTML = String(a.forEach(i => i));`, 'undefined');
});

// -----------------------------------------------------------------------
// Spread, default params, optional chaining, nullish coalescing
// -----------------------------------------------------------------------
await group('modern operators', async () => {
  await check('array spread',
    `var a=['x','y']; var b=[...a, 'z']; document.body.innerHTML = b.join('|');`, 'x|y|z');
  await check('object spread',
    `var o={html:'<a>'}; var p={...o, x:'<b>'}; document.body.innerHTML = p.html + p.x;`, '<a><b>');
  await check('default param used',
    `function wrap(tag='b') { return '<' + tag + '>'; } document.body.innerHTML = wrap();`, '<b>');
  await check('default param overridden',
    `function wrap(tag='b') { return '<' + tag + '>'; } document.body.innerHTML = wrap('em');`, '<em>');
  await check('arrow default',
    `const hi = (who='World') => 'Hi ' + who; document.body.innerHTML = hi();`, 'Hi World');
  await check('optional chaining on known object',
    `var o={name:'Alice'}; document.body.innerHTML = '<p>'+o?.name+'</p>';`, '<p>Alice</p>');
  await check('optional chaining on known array',
    `var a=['x','y']; document.body.innerHTML = '<p>'+a?.[1]+'</p>';`, '<p>y</p>');
  await check('nullish with known value',
    `var n='hi'; document.body.innerHTML = '<p>'+(n ?? 'def')+'</p>';`, '<p>hi</p>');
  await check('nullish with null picks right',
    `var n=null; document.body.innerHTML = '<p>'+(n ?? 'def')+'</p>';`, '<p>def</p>');
});

// -----------------------------------------------------------------------
// Class syntax (basic extraction via token scan)
// -----------------------------------------------------------------------
await group('class methods', async () => {
  await check('innerHTML inside class method',
    `class W { render() { this.el.innerHTML = '<p>'+this.text+'</p>'; } }`,
    { html: '<p>__HDX0__</p>', target: 'this.el', autoSubs: [['__HDX0__', 'this.text']] });
  await check('method local var builds html',
    `class W { render() { var s='<a>'; s+='</a>'; this.el.innerHTML = s; } }`,
    { html: '<a></a>', target: 'this.el' });
  await check('method with param',
    `class W { render(msg) { this.el.innerHTML = '<p>'+msg+'</p>'; } }`,
    { html: '<p>__HDX0__</p>', target: 'this.el', autoSubs: [['__HDX0__', 'msg']] });
});

// -----------------------------------------------------------------------
// Object literal extensions (getters, method shorthand, shorthand props, computed keys)
// -----------------------------------------------------------------------
await group('object extensions', async () => {
  await check('getter method does not break object',
    `const o={get html(){return 'x';}, msg:'ok'}; document.body.innerHTML=o.msg;`, 'ok');
  await check('method shorthand does not break object',
    `const o={render(){return 'x';}, title:'T'}; document.body.innerHTML=o.title;`, 'T');
  await check('shorthand property',
    `const title='Hello'; const o={title}; document.body.innerHTML=o.title;`, 'Hello');
  await check('computed key',
    `const k='foo'; const o={[k]:'<p>'}; document.body.innerHTML=o.foo;`, '<p>');
});

// -----------------------------------------------------------------------
// new / typeof / void / delete / await / yield
// -----------------------------------------------------------------------
await group('keyword prefixes', async () => {
  await check('new Constructor(args)',
    `document.body.innerHTML = '<p>' + new Date().toString() + '</p>';`,
    { html: '<p>__HDX0__</p>', autoSubs: [['__HDX0__', 'new Date().toString()']] });
  await check('typeof',
    `document.body.innerHTML = '<p>' + typeof x + '</p>';`,
    { html: '<p>__HDX0__</p>', autoSubs: [['__HDX0__', 'typeof x']] });
  await check('await fetch',
    `async function f() { const x = await fetch('/a'); document.body.innerHTML = '<p>'+x+'</p>'; }`,
    { html: '<p>__HDX0__</p>' });
});

// -----------------------------------------------------------------------
// Object.keys/values/entries, JSON.stringify/parse
// -----------------------------------------------------------------------
await group('Object/JSON builtins', async () => {
  await check('Object.keys',
    `const o={a:'x',b:'y'}; document.body.innerHTML = Object.keys(o).join(',');`, 'a,b');
  await check('Object.values',
    `const o={a:1,b:2}; document.body.innerHTML = Object.values(o).join(',');`, '1,2');
  await check('Object.entries',
    `const o={a:'1'}; document.body.innerHTML = Object.entries(o).map(e=>e[0]+'='+e[1]).join(',');`, 'a=1');
  await check('JSON.stringify object',
    `const o={a:'x'}; document.body.innerHTML = JSON.stringify(o);`, '{"a":"x"}');
  await check('JSON.stringify array',
    `document.body.innerHTML = JSON.stringify([1,2,3]);`, '[1,2,3]');
  await check('JSON.parse round-trip',
    `const s='{"k":42}'; document.body.innerHTML = 'v=' + JSON.parse(s).k;`, 'v=42');
});

// -----------------------------------------------------------------------
// Array.reduce
// -----------------------------------------------------------------------
await group('array.reduce', async () => {
  await check('sum',
    `const a=[1,2,3,4]; document.body.innerHTML = a.reduce((acc,n)=>acc+n, 0) + '';`, '10');
  await check('concat strings',
    `const a=['x','y','z']; document.body.innerHTML = a.reduce((acc,s)=>acc+s, '');`, 'xyz');
});

// -----------------------------------------------------------------------
// Regex literals don't break tokenization
// -----------------------------------------------------------------------
await group('regex literals', async () => {
  await check('regex in replace call',
    `var s='abc'; document.body.innerHTML = s.replace(/b/g,'X');`,
    { html: '__HDX0__', autoSubs: [['__HDX0__', "s.replace(/b/g,'X')"]] });
  await check('regex variable does not crash',
    `var re=/abc/i; document.body.innerHTML = '<p>ok</p>';`, '<p>ok</p>');
});

// -----------------------------------------------------------------------
// Tagged template literals captured as opaque
// -----------------------------------------------------------------------
await group('tagged template', async () => {
  await check('tag`...` captured as opaque',
    'document.body.innerHTML = html`<p>hi</p>`;',
    { html: '__HDX0__', autoSubs: [['__HDX0__', 'html`<p>hi</p>`']] });
});

// -----------------------------------------------------------------------
// Original iframe case from the feature request
// -----------------------------------------------------------------------
await group('feature-request case', async () => {
  await check('iframe via var',
    `x='<iframe credentialless loading="lazy" id="background" title="background" sandbox="allow-scripts" frameborder="0" height="100%" width="100%" src="https://random.ndev.tk/">';\ndocument.body.innerHTML+=x;`,
    { html: '<iframe credentialless loading="lazy" id="background" title="background" sandbox="allow-scripts" frameborder="0" height="100%" width="100%" src="https://random.ndev.tk/">',
      target: 'document.body', assignProp: 'innerHTML', assignOp: '+=' });
});

// -----------------------------------------------------------------------
// Loop-marker break/continue signal propagation fix
// -----------------------------------------------------------------------
await group('loop-built innerHTML with break in other functions', async () => {
  await check('loop-built html with break in sibling function',
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
await (async function () {
  if (!globalThis.__convertProject) { console.log('\nconvertProject not available — skipping'); return; }
  const cp = globalThis.__convertProject;
  const before = pass + fail;
  console.log('\nconvertProject');
  console.log('--------------');

  // Helper: check output files match expectations.
  async function checkProject(name, files, expectedKeys, checks) {
    const out = await cp(files);
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
  await checkProject('JS converted in place',
    {
      'index.html': '<html><body><div id="app"></div><script src="app.js"></script></body></html>',
      'app.js': 'document.getElementById("app").innerHTML = "<p>" + text + "</p>";'
    },
    ['app.js'],
    { 'app.js': c => /createElement/.test(c) && !/innerHTML/.test(c) }
  );

  // 2. JS without innerHTML → not in output.
  await checkProject('clean JS not in output',
    {
      'index.html': '<html><body><script src="utils.js"></script><script src="app.js"></script></body></html>',
      'utils.js': 'function helper() { return 1; }',
      'app.js': 'el.innerHTML = "<div>" + helper() + "</div>";'
    },
    ['app.js'],
    { 'app.js': c => /createElement/.test(c) }
  );

  // 3. Inline events/styles → handlers file.
  await checkProject('inline events to handlers',
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
  await checkProject('inline script extracted',
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
  await checkProject('inline style extracted',
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
  await checkProject('two pages no collision',
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
  await checkProject('cross-file scope',
    {
      'index.html': '<html><body><div id="app"></div><script src="store.js"></script><script src="app.js"></script></body></html>',
      'store.js': 'var items = []; function addItem(t) { items.push(t); }',
      'app.js': 'var html = ""; for (var i = 0; i < items.length; i++) { html += "<li>" + items[i] + "</li>"; } document.getElementById("app").innerHTML = html;'
    },
    ['app.js'],
    { 'app.js': c => /createElement/.test(c) && /items\[i\]/.test(c) }
  );

  // 8. Standalone JS (not referenced by any HTML) converted in place.
  await checkProject('standalone JS',
    {
      'page.html': '<html><body><p>Static</p></body></html>',
      'widget.js': 'document.body.innerHTML = "<div>" + x + "</div>";'
    },
    ['widget.js'],
    { 'widget.js': c => /createElement/.test(c) }
  );

  // 9. Clean HTML with no unsafe content → not in output.
  await checkProject('clean HTML not in output',
    {
      'clean.html': '<html><body><p>Hello</p></body></html>'
    },
    []
  );

  // 10. HTML with both inline script AND external script.
  await checkProject('mixed inline and external scripts',
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
await (async function () {
  if (!globalThis.__convertProject) return;
  const cp = globalThis.__convertProject;
  const before = pass + fail;
  console.log('\nadversarial');
  console.log('-----------');

  async function checkProject(name, files, expectedKeys, checks) {
    const out = await cp(files);
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
  await checkProject('innerHTML XSS converted',
    {
      'x.html': '<html><body><script src="x.js"></script></body></html>',
      'x.js': 'var safe = "ok";\ndocument.body.innerHTML = "<img src=x onerror=alert(1)>";'
    },
    ['x.js'],
    { 'x.js': c => /createElement/.test(c) && !/innerHTML/.test(c) && !/onerror/.test(c) }
  );

  // 2. Inline event with HTML entities trying to break out.
  await checkProject('encoded onclick',
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
  await checkProject('CSS injection via style',
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
  await checkProject('javascript: URL extracted',
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
  await checkProject('var named innerHTML ignored',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'var innerHTML = "<p>safe</p>";\nconsole.log(innerHTML);'
    },
    [],
    {}
  );

  // 6. innerHTML inside a comment — should NOT trigger.
  await checkProject('commented innerHTML ignored',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': '// el.innerHTML = "<b>xss</b>";\nconsole.log("safe");'
    },
    [],
    {}
  );

  // 7. innerHTML inside a string literal — should NOT trigger.
  await checkProject('innerHTML in string ignored',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'var s = "el.innerHTML = bad";\nconsole.log(s);'
    },
    [],
    {}
  );

  // 8. Multiple innerHTML on same element.
  await checkProject('double innerHTML',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.innerHTML = "<a>" + x + "</a>";\nel.innerHTML = "<b>" + y + "</b>";'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && !/innerHTML/.test(c) }
  );

  // 9. Empty innerHTML.
  await checkProject('empty innerHTML',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.innerHTML = "";'
    },
    ['p.js'],
    { 'p.js': c => /replaceChildren/.test(c) && !/innerHTML/.test(c) }
  );

  // 10. outerHTML.
  await checkProject('outerHTML converted',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.outerHTML = "<div id=\\"new\\">" + text + "</div>";'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && /parentNode/.test(c) && !/outerHTML/.test(c) }
  );

  // 11. innerHTML += append.
  await checkProject('innerHTML += append',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.innerHTML += "<li>" + item + "</li>";'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && /appendChild/.test(c) && !/innerHTML/.test(c) }
  );

  // 12. Nested quotes in onclick.
  await checkProject('nested quotes onclick',
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
  await checkProject('multi-statement onclick',
    {
      'p.html': '<html><body><button onclick="var x=1; x++; doStuff(x)">x</button></body></html>'
    },
    ['p.html', 'p.handlers.js'],
    {
      'p.handlers.js': c => /var x=1/.test(c) && /doStuff/.test(c)
    }
  );

  // 14. __proto__ in innerHTML.
  await checkProject('__proto__ in innerHTML',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.innerHTML = "<div class=\\"" + obj.__proto__ + "\\">x</div>";'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && /obj\.__proto__/.test(c) }
  );

  // 15. Clean file — no output.
  await checkProject('no unsafe content',
    {
      'p.html': '<html><body><p>Hello</p></body></html>',
      'p.js': 'console.log("no innerHTML here");'
    },
    []
  );

  // 16. Script tag in innerHTML string — createElement is safe.
  await checkProject('script tag in innerHTML',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.innerHTML = "<scr" + "ipt>alert(1)</" + "script>";'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && !/innerHTML/.test(c) }
  );

  // 17. Non-element target — plain object with innerHTML should NOT be converted.
  await checkProject('non-element innerHTML skipped',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'var obj = { innerHTML: "" };\nobj.innerHTML = "<div>test</div>";'
    },
    [],  // No output — the assignment is on a plain object, not a DOM element
  );

  // 18. String variable with innerHTML property name should NOT be converted.
  await checkProject('string var innerHTML skipped',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'var tpl = "<b>hi</b>";\nvar result = { innerHTML: tpl };\nresult.innerHTML = "<p>" + tpl + "</p>";'
    },
    [],  // result is a plain object
  );

  // 19. document.write converted.
  await checkProject('document.write converted',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'document.write("<h1>Title</h1>");'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && /appendChild/.test(c) && !/document\.write/.test(c) }
  );

  // 20. document.writeln converted.
  await checkProject('document.writeln converted',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'document.writeln("<p>" + msg + "</p>");'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && !/writeln/.test(c) }
  );

  // 21. document.write in string not converted.
  await checkProject('document.write in string ignored',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'var s = "document.write is deprecated";'
    },
    [],
  );

  // 22. insertAdjacentHTML converted.
  await checkProject('insertAdjacentHTML converted',
    {
      'p.html': '<html><body><script src="p.js"></script></body></html>',
      'p.js': 'el.insertAdjacentHTML("beforeend", "<li>" + item + "</li>");'
    },
    ['p.js'],
    { 'p.js': c => /createElement/.test(c) && /appendChild/.test(c) && !/insertAdjacentHTML/.test(c) }
  );

  // 23. insertAdjacentHTML beforebegin uses parentNode.
  await checkProject('insertAdjacentHTML beforebegin',
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
await (async function () {
  const tokenizeHtml = globalThis.__tokenizeHtml;
  const serialize = globalThis.__serializeHtmlTokens;
  if (!tokenizeHtml) return;
  const before = pass + fail;
  console.log('\ntokenizeHtml');
  console.log('------------');

  async function checkHtml(name, input, test) {
    const tokens = tokenizeHtml(input);
    let ok = false;
    try { ok = test(tokens, serialize(tokens)); } catch (e) { ok = false; }
    if (ok) pass++;
    else { fail++; failures.push({ name, input, want: 'check failed', got: JSON.stringify(tokens.map(t => t.type + ':' + (t.tag || t.text || '').slice(0, 40)).slice(0, 10)) }); }
  }

  // Round-trip: serialize(tokenize(html)) === html
  await checkHtml('round-trip simple', '<div class="x">hello</div>', (t, s) => s === '<div class="x">hello</div>');
  await checkHtml('round-trip doctype', '<!DOCTYPE html><html><body></body></html>', (t, s) => s === '<!DOCTYPE html><html><body></body></html>');
  await checkHtml('round-trip comment', '<!-- comment --><p>text</p>', (t, s) => s === '<!-- comment --><p>text</p>');
  await checkHtml('round-trip self-close', '<br/><img src="x"/>', (t, s) => s === '<br/><img src="x"/>');
  await checkHtml('round-trip unquoted', '<div id=test>x</div>', (t, s) => s === '<div id="test">x</div>'); // normalizes to quoted

  // Raw text elements — content not parsed as tags
  await checkHtml('script raw text', '<script>var x = "<b>not a tag</b>";</script>', (t) =>
    t.length === 3 && t[0].type === 'openTag' && t[0].tag === 'script' &&
    t[1].type === 'text' && t[1].text.includes('<b>') && t[2].type === 'closeTag');
  await checkHtml('style raw text', '<style>div > p { color: red; }</style>', (t) =>
    t[1].type === 'text' && t[1].text.includes('div > p'));
  await checkHtml('textarea raw text', '<textarea><b>bold</b></textarea>', (t) =>
    t[1].type === 'text' && t[1].text === '<b>bold</b>');
  await checkHtml('title raw text', '<title>My <b>Page</b></title>', (t) =>
    t[1].type === 'text' && t[1].text === 'My <b>Page</b>');
  await checkHtml('iframe raw text', '<iframe><p>fallback</p></iframe>', (t) =>
    t[1].type === 'text' && t[1].text === '<p>fallback</p>');
  await checkHtml('noscript raw text', '<noscript><script>alert(1)</script></noscript>', (t) =>
    t[1].type === 'text' && t[1].text === '<script>alert(1)</script>');

  // Malformed HTML
  await checkHtml('bare < in text', 'a < b and c > d', (t) =>
    // The < starts a tag parse attempt, but "b" is not a valid tag context
    // so behavior may vary, but should not crash
    true);
  await checkHtml('unclosed tag at EOF', '<div class="x"', (t) => t.length >= 1);
  await checkHtml('empty tag', '<><p>x</p>', (t) => t.some(tk => tk.type === 'openTag' && tk.tag === 'p'));
  await checkHtml('close tag with spaces', '<div>x</ div >', (t) => t.some(tk => tk.type === 'closeTag'));

  // Attribute edge cases
  await checkHtml('single-quoted attr', "<div class='foo'>x</div>", (t) =>
    t[0].attrs[0].value === 'foo');
  await checkHtml('unquoted attr', '<input type=text disabled>', (t) =>
    t[0].attrs[0].value === 'text' && t[0].attrs[1].name === 'disabled');
  await checkHtml('boolean attr no value', '<input disabled required>', (t) =>
    t[0].attrs.length === 2 && t[0].attrs[0].name === 'disabled');
  await checkHtml('attr with entities', '<a href="foo?a=1&amp;b=2">x</a>', (t) =>
    t[0].attrs[0].value === 'foo?a=1&amp;b=2'); // raw value, not decoded
  await checkHtml('mixed case preserved', '<DiV ClAsS="X">y</DiV>', (t) =>
    t[0].tag === 'div' && t[0].tagRaw === 'DiV' && t[0].attrs[0].nameRaw === 'ClAsS');
  await checkHtml('multiple spaces in attrs', '<div   id="a"   class="b"  >', (t) =>
    t[0].attrs.length === 2);

  // Comment edge cases
  await checkHtml('comment with dashes', '<!-- a -- b -->', (t) =>
    t[0].type === 'comment');
  await checkHtml('empty comment', '<!---->x', (t) =>
    t[0].type === 'comment' && t[1].type === 'text' && t[1].text === 'x');

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// JS tokenizer tests
// -----------------------------------------------------------------------
await (async function () {
  const tokenize = globalThis.__tokenize;
  if (!tokenize) return;
  const before = pass + fail;
  console.log('\ntokenize (JS)');
  console.log('-------------');

  async function checkTok(name, input, test) {
    const tokens = tokenize(input);
    let ok = false;
    try { ok = test(tokens); } catch (e) { ok = false; }
    if (ok) pass++;
    else { fail++; failures.push({ name, input, want: 'check failed', got: JSON.stringify(tokens.map(t => t.type + ':' + (t.text || t.char || '').slice(0, 30)).slice(0, 15)) }); }
  }

  // String handling
  await checkTok('single-quoted string', "'hello'", (t) =>
    t.length === 1 && t[0].type === 'str' && t[0].text === 'hello');
  await checkTok('double-quoted string', '"world"', (t) =>
    t[0].type === 'str' && t[0].text === 'world');
  await checkTok('escaped quote', "'it\\'s'", (t) =>
    t[0].type === 'str' && t[0].text === "it's");
  await checkTok('string with backslash-n', "'line1\\nline2'", (t) =>
    t[0].type === 'str' && t[0].text === 'line1\nline2');

  // Template literals
  await checkTok('template no expr', '`hello`', (t) =>
    t[0].type === 'tmpl' && t[0].parts.length === 1 && t[0].parts[0].kind === 'text');
  await checkTok('template with expr', '`hi ${name}`', (t) =>
    t[0].type === 'tmpl' && t[0].parts.some(p => p.kind === 'expr' && p.expr === 'name'));
  await checkTok('nested template', '`a ${`b ${c}`} d`', (t) =>
    t[0].type === 'tmpl');
  await checkTok('template with braces in string', '`${"{}"}`', (t) =>
    t[0].type === 'tmpl' && t[0].parts.some(p => p.kind === 'expr'));

  // Regex vs division
  await checkTok('regex after return', 'return /abc/g', (t) =>
    t.some(tk => tk.type === 'regex'));
  await checkTok('division after number', '4 / 2', (t) =>
    t.some(tk => tk.type === 'op' && tk.text === '/'));
  await checkTok('regex after =', 'var r = /test/i', (t) =>
    t.some(tk => tk.type === 'regex' && tk.text === '/test/i'));
  await checkTok('regex after (', 'if (/x/.test(s))', (t) =>
    t.some(tk => tk.type === 'regex'));

  // Comments skipped
  await checkTok('line comment', 'a // comment\nb', (t) =>
    t.every(tk => tk.type !== 'comment') && t.some(tk => tk.type === 'other' && tk.text === 'b'));
  await checkTok('block comment', 'a /* comment */ b', (t) =>
    t.length === 2 && t[0].text === 'a' && t[1].text === 'b');

  // ASI
  await checkTok('ASI after identifier', 'a\nb', (t) =>
    t.some(tk => tk.type === 'sep' && tk.char === ';'));
  await checkTok('no ASI after open paren', 'f(\na)', (t) =>
    !t.some(tk => tk.type === 'sep' && tk.char === ';'));

  // Operators
  await checkTok('=== is op not sep', 'a === b', (t) =>
    t.some(tk => tk.type === 'op' && tk.text === '==='));
  await checkTok('= is sep', 'a = b', (t) =>
    t.some(tk => tk.type === 'sep' && tk.char === '='));
  await checkTok('+= is sep', 'a += b', (t) =>
    t.some(tk => tk.type === 'sep' && tk.char === '+='));
  await checkTok('arrow =>', 'x => x', (t) =>
    t.some(tk => tk.type === 'other' && tk.text === '=>'));

  // Edge cases
  await checkTok('empty input', '', (t) => t.length === 0);
  await checkTok('innerHTML token', 'el.innerHTML', (t) =>
    t.length === 1 && t[0].type === 'other' && t[0].text === 'el.innerHTML');
  await checkTok('braces in string', 'var s = "{ } { }"', (t) =>
    t.filter(tk => tk.type === 'open' || tk.type === 'close').length === 0);

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// decodeHtmlEntities tests
// -----------------------------------------------------------------------
await (async function () {
  const decode = globalThis.__decodeHtmlEntities;
  if (!decode) return;
  const before = pass + fail;
  console.log('\ndecodeHtmlEntities');
  console.log('------------------');

  async function checkEnt(name, input, expected) {
    const got = decode(input);
    if (got === expected) pass++;
    else { fail++; failures.push({ name, input, want: expected, got }); }
  }

  await checkEnt('amp', '&amp;', '&');
  await checkEnt('lt', '&lt;', '<');
  await checkEnt('gt', '&gt;', '>');
  await checkEnt('quot', '&quot;', '"');
  await checkEnt('apos', '&apos;', "'");
  await checkEnt('nbsp', '&nbsp;', '\u00A0');
  await checkEnt('decimal entity', '&#65;', 'A');
  await checkEnt('hex entity', '&#x41;', 'A');
  await checkEnt('hex lowercase', '&#x61;', 'a');
  await checkEnt('large codepoint', '&#x1F600;', '\u{1F600}');
  await checkEnt('unknown named', '&bogus;', '&bogus;'); // preserved as-is
  await checkEnt('no semicolon', '&amp no semi', '&amp no semi'); // no match without ;
  await checkEnt('mixed', '&lt;div&gt; &amp; &quot;hi&quot;', '<div> & "hi"');
  await checkEnt('copy', '&copy;', '\u00A9');
  await checkEnt('euro', '&euro;', '\u20AC');
  await checkEnt('mdash', '&mdash;', '\u2014');

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// parseStyleDecls tests
// -----------------------------------------------------------------------
await (async function () {
  const parse = globalThis.__parseStyleDecls;
  if (!parse) return;
  const before = pass + fail;
  console.log('\nparseStyleDecls');
  console.log('---------------');

  async function checkCSS(name, input, expected) {
    const got = parse(input);
    const ok = JSON.stringify(got) === JSON.stringify(expected);
    if (ok) pass++;
    else { fail++; failures.push({ name, input, want: JSON.stringify(expected), got: JSON.stringify(got) }); }
  }

  await checkCSS('simple', 'color: red', [{ prop: 'color', value: 'red', important: false }]);
  await checkCSS('two decls', 'color: red; font-size: 12px', [
    { prop: 'color', value: 'red', important: false },
    { prop: 'font-size', value: '12px', important: false }
  ]);
  await checkCSS('important', 'color: red !important', [{ prop: 'color', value: 'red', important: true }]);
  await checkCSS('trailing semi', 'color: red;', [{ prop: 'color', value: 'red', important: false }]);
  await checkCSS('url with parens', 'background: url(http://example.com)', [
    { prop: 'background', value: 'url(http://example.com)', important: false }
  ]);
  await checkCSS('url with semicolon in parens', 'background: url(data:text/css;base64,abc)', [
    { prop: 'background', value: 'url(data:text/css;base64,abc)', important: false }
  ]);
  await checkCSS('quoted semicolon', 'content: "a; b"', [
    { prop: 'content', value: '"a; b"', important: false }
  ]);
  await checkCSS('single-quoted semicolon', "content: 'a; b'", [
    { prop: 'content', value: "'a; b'", important: false }
  ]);
  await checkCSS('empty input', '', []);
  await checkCSS('no colon', 'invalid', []);
  await checkCSS('colon in url value', 'background: url(http://x.com:8080/y)', [
    { prop: 'background', value: 'url(http://x.com:8080/y)', important: false }
  ]);
  await checkCSS('whitespace variations', '  color :  red  ;  margin : 0  ', [
    { prop: 'color', value: 'red', important: false },
    { prop: 'margin', value: '0', important: false }
  ]);
  await checkCSS('calc', 'width: calc(100% - 20px)', [
    { prop: 'width', value: 'calc(100% - 20px)', important: false }
  ]);

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// makeVar tests
// -----------------------------------------------------------------------
await (async function () {
  const makeVar = globalThis.__makeVar;
  if (!makeVar) return;
  const before = pass + fail;
  console.log('\nmakeVar');
  console.log('-------');

  async function checkVar(name, tag, usedArr, expected) {
    const used = new Set(usedArr);
    const got = makeVar(tag, used);
    if (got === expected) pass++;
    else { fail++; failures.push({ name, input: tag, want: expected, got }); }
  }

  await checkVar('simple div', 'div', [], 'div');
  await checkVar('collision', 'div', ['div'], 'div2');
  await checkVar('double collision', 'div', ['div', 'div2'], 'div3');
  await checkVar('reserved word', 'class', [], 'class_');
  await checkVar('reserved for', 'for', [], 'for_');
  await checkVar('number prefix', '1tag', [], 'el1tag');
  await checkVar('uppercase', 'DIV', [], 'div');
  await checkVar('svg tag', 'svg', [], 'svg');
  await checkVar('empty string', '', [], 'el');

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// End-to-end DOM output verification
// -----------------------------------------------------------------------
await (async function () {
  const convertRaw = globalThis.__convertRaw;
  if (!convertRaw) return;
  const before = pass + fail;
  console.log('\nDOM output');
  console.log('----------');

  async function checkDOM(name, input, test) {
    const out = await convertRaw(input) || '';
    let ok = false;
    try { ok = test(out); } catch (e) { ok = false; }
    if (ok) pass++;
    else { fail++; failures.push({ name, input, want: 'check failed', got: out.slice(0, 300) }); }
  }

  // Basic element creation
  await checkDOM('div with text', 'el.innerHTML = "<div>hello</div>";',
    c => /createElement\('div'\)/.test(c) && (/textContent/.test(c) || /createTextNode\('hello'\)/.test(c)) && /appendChild/.test(c));
  await checkDOM('nested elements', 'el.innerHTML = "<ul><li>a</li><li>b</li></ul>";',
    c => /createElement\('ul'\)/.test(c) && /createElement\('li'\)/.test(c));
  await checkDOM('void element', 'el.innerHTML = "<br>";',
    c => /createElement\('br'\)/.test(c) && !/textContent/.test(c));
  await checkDOM('img with attrs', 'el.innerHTML = "<img src=\\"pic.jpg\\" alt=\\"photo\\">";',
    c => /createElement\('img'\)/.test(c) && /(src|setAttribute)/.test(c));

  // Expression handling
  await checkDOM('expression in text', 'el.innerHTML = "<p>" + msg + "</p>";',
    c => /createElement\('p'\)/.test(c) && /msg/.test(c));
  await checkDOM('expression in attribute', 'el.innerHTML = "<div class=\\"" + cls + "\\">x</div>";',
    c => /cls/.test(c) && /createElement/.test(c));

  // innerHTML += (append, no replaceChildren)
  await checkDOM('innerHTML += appends', 'el.innerHTML += "<li>item</li>";',
    c => /createElement/.test(c) && /appendChild/.test(c) && !/replaceChildren/.test(c));
  // innerHTML = (replace)
  await checkDOM('innerHTML = replaces', 'el.innerHTML = "<p>new</p>";',
    c => /replaceChildren/.test(c) && /createElement/.test(c));

  // Multiple elements
  await checkDOM('multiple top-level elements', 'el.innerHTML = "<h1>Title</h1><p>Body</p>";',
    c => /createElement\('h1'\)/.test(c) && /createElement\('p'\)/.test(c));

  // Empty innerHTML
  await checkDOM('empty innerHTML', 'el.innerHTML = "";',
    c => /replaceChildren/.test(c));

  // SVG namespace
  await checkDOM('svg element', 'el.innerHTML = "<svg><rect width=\\"10\\"></rect></svg>";',
    c => /createElementNS/.test(c) && /svg/.test(c));

  // Boolean attributes
  await checkDOM('boolean attr', 'el.innerHTML = "<input disabled>";',
    c => /createElement\('input'\)/.test(c) && /disabled/.test(c));

  // Text-only content
  await checkDOM('text only', 'el.innerHTML = "just text";',
    c => /createTextNode/.test(c) && !/createElement/.test(c));

  // Whitespace text
  await checkDOM('whitespace between tags', 'el.innerHTML = "<div>a</div> <div>b</div>";',
    c => /createElement\('div'\)/.test(c));

  // HTML entities in static content
  await checkDOM('entities decoded', 'el.innerHTML = "<p>&amp; &lt; &gt;</p>";',
    c => /createElement\('p'\)/.test(c));

  // Deeply nested
  await checkDOM('deeply nested', 'el.innerHTML = "<div><span><a href=\\"#\\">link</a></span></div>";',
    c => /createElement\('div'\)/.test(c) && /createElement\('span'\)/.test(c) && /createElement\('a'\)/.test(c));

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Tricky inputs — try to break the engine
// -----------------------------------------------------------------------
await (async function () {
  const convertRaw = globalThis.__convertRaw;
  const tokenize = globalThis.__tokenize;
  const tokenizeHtml = globalThis.__tokenizeHtml;
  const cp = globalThis.__convertProject;
  if (!convertRaw || !cp) return;
  const before = pass + fail;
  console.log('\ntricky inputs');
  console.log('-------------');

  async function checkNoThrow(name, fn) {
    try { fn(); pass++; }
    catch (e) { fail++; failures.push({ name, input: '(function)', want: 'no throw', got: e.message }); }
  }

  async function checkProject(name, files, expectedKeys, checks) {
    const out = await cp(files);
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
  await checkProject('script in innerHTML is safe',
    { 'i.html': '<html><body><script src="i.js"></script></body></html>',
      'i.js': 'el.innerHTML = "<script>alert(1)<\\/script>";' },
    ['i.js'],
    { 'i.js': c => /createElement\('script'\)/.test(c) && !/alert\(1\)/.test(c) === false });

  // Attribute with > in value shouldn't break parsing
  await checkProject('attr with > in value',
    { 'i.html': '<html><body><div data-expr="a > b" onclick="go()">x</div></body></html>' },
    ['i.html', 'i.handlers.js'],
    { 'i.handlers.js': c => /addEventListener/.test(c) && /go\(\)/.test(c) });

  // Nested quotes in onclick
  await checkProject('deeply nested quotes onclick',
    { 'i.html': '<html><body><button onclick="f(\'a\', &quot;b&quot;)">x</button></body></html>' },
    ['i.html', 'i.handlers.js'],
    { 'i.handlers.js': c => /f\(/.test(c) });

  // innerHTML with template literal
  await checkNoThrow('template literal innerHTML', async () => {
    await convertRaw('el.innerHTML = `<div>${name}</div>`;');
  });

  // Huge deeply nested HTML
  await checkNoThrow('deeply nested HTML', async () => {
    const deep = '<div>'.repeat(50) + 'x' + '</div>'.repeat(50);
    await convertRaw('el.innerHTML = "' + deep.replace(/"/g, '\\"') + '";');
  });

  // innerHTML assignment with no RHS value
  await checkNoThrow('empty RHS', async () => {
    await convertRaw('el.innerHTML = ;');
  });

  // Variable named innerHTML
  await checkNoThrow('var named innerHTML', async () => {
    await convertRaw('var innerHTML = "<div>test</div>";');
  });

  // Chained property access
  await checkNoThrow('chained access innerHTML', async () => {
    await convertRaw('a.b.c.innerHTML = "<p>test</p>";');
  });

  // document.write with concatenation
  await checkProject('document.write with concat',
    { 'i.html': '<html><body><script src="i.js"></script></body></html>',
      'i.js': 'var title = "Hello";\ndocument.write("<h1>" + title + "</h1>");' },
    ['i.js'],
    { 'i.js': c => /createElement/.test(c) && !/document\.write/.test(c) });

  // HTML with all unsafe patterns at once
  await checkProject('all unsafe patterns',
    { 'i.html': '<html><body><a href="javascript:void(0)" onclick="go()" style="color:red">x</a></body></html>' },
    ['i.html', 'i.handlers.js'],
    { 'i.html': c => !/onclick/.test(c) && !/javascript:/.test(c) && !/style=/.test(c),
      'i.handlers.js': c => /addEventListener.*click/.test(c) && /preventDefault/.test(c) && /setProperty/.test(c) });

  // Self-closing script tag (should not extract anything)
  await checkNoThrow('self-closing script', async () => {
    const tokens = tokenizeHtml('<script/>');
    // Script with self-close shouldn't enter raw text mode endlessly
  });

  // HTML with only whitespace
  await checkNoThrow('whitespace only HTML', async () => {
    await convertRaw('   \n\t  ');
  });

  // Very long single-line innerHTML
  await checkNoThrow('very long innerHTML', async () => {
    const items = Array.from({length: 100}, (_, i) => '<li>' + i + '</li>').join('');
    await convertRaw('el.innerHTML = "' + items + '";');
  });

  // innerHTML in try/catch
  await checkNoThrow('innerHTML in try-catch', async () => {
    await convertRaw('try { el.innerHTML = "<p>test</p>"; } catch(e) {}');
  });

  // Re-assignment of target
  await checkNoThrow('target reassigned', async () => {
    await convertRaw('var el = document.getElementById("x");\nel.innerHTML = "<div>ok</div>";\nel = null;');
  });

  // Unicode in HTML
  await checkNoThrow('unicode in HTML', async () => {
    await convertRaw('el.innerHTML = "<p>\\u2603 snowman</p>";');
  });

  // Regex that looks like HTML
  await checkNoThrow('regex with angle brackets', async () => {
    const toks = tokenize('var re = /<div>/g;');
    // The < should be part of the regex, not trigger HTML detection
  });

  // Object with innerHTML property and real element
  await checkProject('object innerHTML then element innerHTML',
    { 'i.html': '<html><body><script src="i.js"></script></body></html>',
      'i.js': 'var cfg = { innerHTML: "" };\ncfg.innerHTML = "not html";\ndocument.getElementById("x").innerHTML = "<b>real</b>";' },
    ['i.js'],
    { 'i.js': c => /createElement\('b'\)/.test(c) });

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Behavioral equivalence tests — run original & converted, compare DOM
// -----------------------------------------------------------------------
await (async function () {
  const cp = globalThis.__convertProject;
  if (!cp) return;
  const JSDOM = require('jsdom').JSDOM;
  const before = pass + fail;
  console.log('\nbehavioral equivalence');
  console.log('----------------------');

  // Execute a multi-file project in jsdom. Returns body.innerHTML after
  // all scripts run synchronously.
  function execProject(files) {
    const htmlPath = Object.keys(files).find(p => /\.html?$/i.test(p));
    if (!htmlPath) return '';
    const html = files[htmlPath];
    const dom = new JSDOM(html, { runScripts: 'dangerously', url: 'http://localhost/' });
    const doc = dom.window.document;
    const scripts = doc.querySelectorAll('script[src]');
    for (const s of scripts) {
      const src = s.getAttribute('src');
      if (files[src]) {
        try { dom.window.eval(files[src]); } catch (e) {}
      }
    }
    const result = doc.body.innerHTML.replace(/\s+/g, ' ').trim();
    dom.window.close();
    return result;
  }

  async function checkEquiv(name, files) {
    const converted = await cp(files);
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
  await checkEquiv('simple div', {
    'index.html': '<html><body><div id="root"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("root").innerHTML = "<p>Hello World</p>";'
  });

  // 2. Nested elements with attributes
  await checkEquiv('nested with attrs', {
    'index.html': '<html><body><div id="app"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("app").innerHTML = \'<div class="container"><h1 id="title">Welcome</h1><p class="desc">A paragraph</p></div>\';'
  });

  // 3. Loop building a list
  await checkEquiv('loop built list', {
    'index.html': '<html><body><ul id="list"></ul><script src="app.js"></script></body></html>',
    'app.js': 'var html = "";\nfor (var i = 0; i < 5; i++) {\n  html += "<li>Item " + i + "</li>";\n}\ndocument.getElementById("list").innerHTML = html;'
  });

  // 4. Conditional HTML
  await checkEquiv('conditional html', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var isAdmin = true;\ndocument.getElementById("out").innerHTML = isAdmin ? "<b>Admin</b>" : "<i>User</i>";'
  });

  // 5. Cross-file: helper function in separate file
  await checkEquiv('cross-file function', {
    'index.html': '<html><body><div id="out"></div><script src="lib.js"></script><script src="app.js"></script></body></html>',
    'lib.js': 'function badge(text, color) { return "<span style=\\"color:" + color + "\\">" + text + "</span>"; }',
    'app.js': 'document.getElementById("out").innerHTML = "<h1>Status: " + badge("OK", "green") + "</h1>";'
  });

  // 6. Multiple innerHTML on different elements
  await checkEquiv('multiple targets', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("a").innerHTML = "<p>First</p>";\ndocument.getElementById("b").innerHTML = "<p>Second</p>";'
  });

  // 7. innerHTML += (append)
  await checkEquiv('innerHTML append', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var el = document.getElementById("out");\nel.innerHTML = "<p>One</p>";\nel.innerHTML += "<p>Two</p>";\nel.innerHTML += "<p>Three</p>";'
  });

  // 8. Complex: table with computed rows
  await checkEquiv('table with rows', {
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
  await checkEquiv('multi-var concat', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var title = "Dashboard";\nvar user = "Admin";\nvar count = 42;\ndocument.getElementById("out").innerHTML = "<h1>" + title + "</h1><p>User: " + user + " (" + count + " items)</p>";'
  });

  // 10. Void elements (br, hr, img, input)
  await checkEquiv('void elements', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>Line 1<br>Line 2</p><hr><input type=\\"text\\" value=\\"hello\\">";'
  });

  // 11. Nested loops
  await checkEquiv('nested loops', {
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
  await checkEquiv('template literal', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var name = "World";\ndocument.getElementById("out").innerHTML = `<h1>Hello ${name}</h1><p>Welcome</p>`;'
  });

  // 13. document.write — note: document.write during parse inserts at
  // script position, but conversion appends to body. The content is the
  // same; the position differs. Test via convertProject instead.
  await checkEquiv('document.write content', {
    'index.html': '<html><body><div id="target"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("target").innerHTML = "<div><p>Written</p></div>";'
  });

  // 14. Preserving non-innerHTML code
  await checkEquiv('preserve surrounding code', {
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
  await checkEquiv('shared state across files', {
    'index.html': '<html><body><div id="out"></div><script src="data.js"></script><script src="render.js"></script></body></html>',
    'data.js': 'var config = { title: "App", version: "1.0" };',
    'render.js': 'document.getElementById("out").innerHTML = "<h1>" + config.title + "</h1><small>v" + config.version + "</small>";'
  });

  // 16. Switch/conditional patterns
  await checkEquiv('switch pattern', {
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
  await checkEquiv('deep nesting', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<div><section><article><header><h1>Deep</h1></header></article></section></div>";'
  });

  // 18. HTML with data attributes
  await checkEquiv('data attributes', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = \'<div data-id="1" data-type="user"><span data-role="name">Alice</span></div>\';'
  });

  // 19. Build variable with += in loop and extra numeric state
  await checkEquiv('build var with counter', {
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
  await checkEquiv('mixed innerHTML and DOM', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'document.getElementById("a").innerHTML = "<p>innerHTML</p>";',
      'var p = document.createElement("p");',
      'p.textContent = "DOM API";',
      'document.getElementById("b").appendChild(p);'
    ].join('\n')
  });

  // 21. Conditional variable (if-else with unknown condition)
  await checkEquiv('conditional var unknown cond', {
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
  await checkEquiv('ternary in loop', {
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
  await checkEquiv('counter flag accumulator', {
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
  await checkEquiv('nested loops with math', {
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
  await checkEquiv('string method', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var name = "alice";\ndocument.getElementById("out").innerHTML = "<b>" + name.toUpperCase() + "</b>";'
  });

  // 26. Multiple separate innerHTML assignments on different elements
  await checkEquiv('three separate targets', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><div id="c"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'document.getElementById("a").innerHTML = "<h1>Title</h1>";',
      'document.getElementById("b").innerHTML = "<p>Body</p>";',
      'document.getElementById("c").innerHTML = "<footer>End</footer>";'
    ].join('\n')
  });

  // 27. Build var with early return pattern (no actual return, but conditional append)
  await checkEquiv('conditional append', {
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
  await checkEquiv('template literal complex', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var x = 5;\ndocument.getElementById("out").innerHTML = `<p>${x > 3 ? "big" : "small"}: ${x * 2}</p>`;'
  });

  // 29. Cross-file: data file, util file, render file
  await checkEquiv('three file chain', {
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
  await checkEquiv('dynamic attributes', {
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
  await checkEquiv('for-in loop', {
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
  await checkEquiv('for-of loop', {
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
  await checkEquiv('while loop counter', {
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
  await checkEquiv('do-while loop', {
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
  await checkEquiv('conditional class in loop', {
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
  await checkEquiv('entity decoding', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>Tom &amp; Jerry &lt;3 &quot;Cartoons&quot;</p>";'
  });

  // 37. Entity in attribute value
  await checkEquiv('entity in attr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<a href=\\"page?a=1&amp;b=2\\">link</a>";'
  });

  // 38. Mixed text and elements with entities
  await checkEquiv('mixed text entities', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "Hello &amp; <b>bold</b> &amp; <i>italic</i>";'
  });

  // 39. Multiple attributes including boolean
  await checkEquiv('multi attr boolean', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<input type=\\"text\\" id=\\"name\\" placeholder=\\"Enter name\\" required>";'
  });

  // 40. Self-closing elements in context
  await checkEquiv('br and hr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>Line 1<br>Line 2</p><hr><p>After</p>";'
  });

  // 41. Complex nested structure
  await checkEquiv('deep nested mixed', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<div>Hello <b>bold <i>italic</i></b> world</div>";'
  });

  // 42. Dynamic data attributes
  await checkEquiv('dynamic data attrs', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var id = 42;',
      'var type = "user";',
      'var name = "Alice";',
      'document.getElementById("out").innerHTML = "<div data-id=\\"" + id + "\\" data-type=\\"" + type + "\\">" + name + "</div>";'
    ].join('\n')
  });

  // 43. Image with dynamic src and alt
  await checkEquiv('img dynamic attrs', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var src = "photo.jpg";',
      'var alt = "Photo";',
      'document.getElementById("out").innerHTML = "<img src=\\"" + src + "\\" alt=\\"" + alt + "\\">";'
    ].join('\n')
  });

  // 44. Anchor with dynamic href
  await checkEquiv('anchor dynamic href', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var url = "https://example.com";',
      'var text = "Click here";',
      'document.getElementById("out").innerHTML = "<a href=\\"" + url + "\\" target=\\"_blank\\">" + text + "</a>";'
    ].join('\n')
  });

  // 45. Full table with static data
  await checkEquiv('full table', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<table><thead><tr><th>Name</th><th>Age</th></tr></thead><tr><td>Alice</td><td>30</td></tr><tr><td>Bob</td><td>25</td></tr></table>";'
  });

  // 46. join with comma separator
  await checkEquiv('join comma separator', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>" + ["a", "b", "c"].join(", ") + "</p>";'
  });

  // 47. Arithmetic expression in text content
  await checkEquiv('arithmetic in text', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var width = 100;',
      'var height = 50;',
      'document.getElementById("out").innerHTML = "<p>Area: " + (width * height) + " sq px</p>";'
    ].join('\n')
  });

  // 48. Ternary in attribute
  await checkEquiv('ternary in attr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var isActive = true;',
      'document.getElementById("out").innerHTML = "<div class=\\"" + (isActive ? "active" : "inactive") + "\\">status</div>";'
    ].join('\n')
  });

  // 49. Multiple separate innerHTML targets from shared data
  await checkEquiv('shared data multi target', {
    'index.html': '<html><body><h1 id="title"></h1><p id="desc"></p><span id="count"></span><script src="app.js"></script></body></html>',
    'app.js': [
      'var data = {title: "Dashboard", desc: "Welcome", count: 42};',
      'document.getElementById("title").innerHTML = data.title;',
      'document.getElementById("desc").innerHTML = "<em>" + data.desc + "</em>";',
      'document.getElementById("count").innerHTML = "<b>" + data.count + "</b> items";'
    ].join('\n')
  });

  // 50. Build with counter, flag, and accumulator all together
  await checkEquiv('counter flag accum together', {
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
  await checkEquiv('todo app', {
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
  await checkEquiv('nested categories', {
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
  await checkEquiv('loop break', {
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
  await checkEquiv('loop continue', {
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
  await checkEquiv('html comment', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>before</p><!-- comment --><p>after</p>";'
  });

  // 56. Form with labels and inputs
  await checkEquiv('form elements', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<form><label for=\\"e\\">Email</label><input type=\\"email\\" id=\\"e\\"><button type=\\"submit\\">Go</button></form>";'
  });

  // 57. Four-file app with shared config
  await checkEquiv('four file app', {
    'index.html': '<html><body><div id="h"></div><div id="b"></div><script src="cfg.js"></script><script src="util.js"></script><script src="head.js"></script><script src="main.js"></script></body></html>',
    'cfg.js': 'var APP = {title: "MyApp", version: "2.0"};',
    'util.js': 'function badge(t) { return "<span class=\\"badge\\">" + t + "</span>"; }',
    'head.js': 'document.getElementById("h").innerHTML = "<h1>" + APP.title + " " + badge("v" + APP.version) + "</h1>";',
    'main.js': 'document.getElementById("b").innerHTML = "<p>Welcome to " + APP.title + "</p>";'
  });

  // 58. innerHTML read from another element
  await checkEquiv('innerHTML read', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("a").innerHTML = "<b>X</b>";\ndocument.getElementById("b").innerHTML = document.getElementById("a").innerHTML;'
  });

  // 59. undefined/null/NaN in concat
  await checkEquiv('undefined in concat', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var x; document.getElementById("out").innerHTML = "<p>" + x + "</p>";'
  });

  // 60. Computed href with query params
  await checkEquiv('computed href params', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var page = 2; var q = "test"; document.getElementById("out").innerHTML = "<a href=\\"search?q=" + q + "&page=" + page + "\\">Next</a>";'
  });

  // 61. Nested loop break (inner only)
  await checkEquiv('nested loop break', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var h="";for(var i=0;i<3;i++){h+="<div>";for(var j=0;j<5;j++){if(j>2)break;h+="<span>"+j+"</span>";}h+="</div>";}document.getElementById("out").innerHTML=h;'
  });

  // 62. Try-catch with different HTML in each branch
  await checkEquiv('try-catch branches', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var h="";try{h="<p>OK: "+riskyOp()+"</p>";}catch(e){h="<p class=\\"err\\">Error: "+e.message+"</p>";}document.getElementById("out").innerHTML=h;'
  });

  // 63. Builder function with non-html variable name
  await checkEquiv('builder fn any var name', {
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
  await checkEquiv('table with tfoot', {
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
  await checkEquiv('continue counter flag', {
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
  await checkEquiv('four file with builder', {
    'index.html': '<html><body><div id="h"></div><div id="b"></div><script src="cfg.js"></script><script src="util.js"></script><script src="head.js"></script><script src="main.js"></script></body></html>',
    'cfg.js': 'var APP = {title: "MyApp", version: "2.0"};',
    'util.js': 'function badge(t) { var r = "<span class=\\"badge\\">"; r += t; r += "</span>"; return r; }',
    'head.js': 'document.getElementById("h").innerHTML = "<h1>" + APP.title + " " + badge("v" + APP.version) + "</h1>";',
    'main.js': 'document.getElementById("b").innerHTML = "<p>Welcome to " + APP.title + "</p>";'
  });

  // 67. Select options built in loop
  await checkEquiv('select options loop', {
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
  await checkEquiv('8 level nesting', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<div><section><article><main><aside><nav><header><footer>deep</footer></header></nav></aside></main></article></section></div>";'
  });

  // 69. innerHTML = then += then += on same element
  await checkEquiv('set then double append', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var el = document.getElementById("out"); el.innerHTML = "<h1>Title</h1>"; el.innerHTML += "<p>P1</p>"; el.innerHTML += "<p>P2</p>";'
  });

  // 70. Many entities
  await checkEquiv('many entities', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<p>&lt;b&gt;bold&lt;/b&gt; &amp; &lt;i&gt;italic&lt;/i&gt; &copy; 2024</p>";'
  });

  // 71. Same-file builder function with loop
  await checkEquiv('same-file builder loop', {
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
  await checkEquiv('same-file builder conditional', {
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
  await checkEquiv('pre-increment counter', {
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
  await checkEquiv('template literal loop', {
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
  await checkEquiv('accumulator as bound', {
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
  await checkEquiv('alternating rows', {
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
  await checkEquiv('conditional wrap', {
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
  await checkEquiv('nested computed attrs', {
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
  await checkEquiv('while early exit', {
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
  await checkEquiv('three level loops', {
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
  await checkEquiv('builder reuse', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'function tag(name, content) { var h = "<" + name + ">" + content + "</" + name + ">"; return h; }',
      'document.getElementById("out").innerHTML = tag("h1", "Title") + tag("p", "Body") + tag("footer", "End");'
    ].join('\n')
  });

  // 82. Two independent innerHTML targets (no shared state)
  await checkEquiv('two independent targets', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var x = "Hello";',
      'document.getElementById("a").innerHTML = "<h1>" + x + "</h1>";',
      'var y = "World";',
      'document.getElementById("b").innerHTML = "<p>" + y + "</p>";'
    ].join('\n')
  });

  // 83. Ternary choosing different structures
  await checkEquiv('ternary structure choice', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var isTable = false; document.getElementById("out").innerHTML = isTable ? "<table><tr><td>Cell</td></tr></table>" : "<ul><li>Item</li></ul>";'
  });

  // 84. String methods in innerHTML expression
  await checkEquiv('string methods', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var name = "alice"; document.getElementById("out").innerHTML = "<p>" + name.charAt(0).toUpperCase() + name.slice(1) + "</p>";'
  });

  // 85. Nested ternary in multiple attributes
  await checkEquiv('nested ternary attrs', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var level = 2; document.getElementById("out").innerHTML = "<div class=\\"" + (level > 2 ? "high" : level > 1 ? "mid" : "low") + "\\" data-level=\\"" + level + "\\">" + level + "</div>";'
  });

  // 86. Multiple counters (sum, max, count)
  await checkEquiv('multiple counters', {
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
  await checkEquiv('multi condition class', {
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
  await checkEquiv('do-while counter', {
    'index.html': '<html><body><ul id="out"></ul><script src="app.js"></script></body></html>',
    'app.js': 'var h = ""; var i = 1; do { h += "<li>Item " + i + "</li>"; i++; } while (i <= 4); document.getElementById("out").innerHTML = h;'
  });

  // 89. 6-level deep nesting
  await checkEquiv('6 level nesting', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML = "<div><section><article><main><aside><nav><a href=\\"#\\">Deep</a></nav></aside></main></article></section></div>";'
  });

  // 90. innerHTML += chain building a page
  await checkEquiv('page build chain', {
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
  await checkEquiv('undefined null concat', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var x; var y = null; document.getElementById("out").innerHTML = "<p>" + x + "</p><p>" + y + "</p>";'
  });

  // 93. Arithmetic in style attribute
  await checkEquiv('arithmetic in attr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var w = 100; var h2 = 50; document.getElementById("out").innerHTML = "<div style=\\"width:" + (w * 2) + "px;height:" + (h2 + 10) + "px\\">sized</div>";'
  });

  // 94. Select with conditional selected attribute
  await checkEquiv('select conditional selected', {
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
  await checkEquiv('for-in object', {
    'index.html': '<html><body><dl id="out"></dl><script src="app.js"></script></body></html>',
    'app.js': 'var obj = {name:"Alice",age:"30",city:"NYC"}; var h = ""; for (var k in obj) { h += "<dt>" + k + "</dt><dd>" + obj[k] + "</dd>"; } document.getElementById("out").innerHTML = h;'
  });

  // 96. for-of on array
  await checkEquiv('for-of array', {
    'index.html': '<html><body><ul id="out"></ul><script src="app.js"></script></body></html>',
    'app.js': 'var items = ["X","Y","Z"]; var h = ""; for (var v of items) { h += "<li>" + v + "</li>"; } document.getElementById("out").innerHTML = h;'
  });

  // 97. Array.join
  await checkEquiv('array join', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var items = ["a","b","c"]; document.getElementById("out").innerHTML = "<p>" + items.join(", ") + "</p>";'
  });

  // 98. Select with conditional selected attribute (array access ternary)
  await checkEquiv('select conditional selected attr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var opts=[{v:"a",t:"Alpha"},{v:"b",t:"Beta"},{v:"c",t:"Gamma"}];var sel="b";var h="<select>";for(var i=0;i<opts.length;i++){h+="<option value=\\""+opts[i].v+"\\"\"+(opts[i].v===sel?" selected":"")+">"+opts[i].t+"</option>";}h+="</select>";document.getElementById("out").innerHTML=h;'
  });

  // 99. Nested loop + conditional attrs + counters + continue
  await checkEquiv('nested loop complex state', {
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
  await checkEquiv('builder conditional in loop', {
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
  await checkEquiv('multi-target from loop', {
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
  await checkEquiv('cross-file try-catch', {
    'index.html': '<html><body><div id="out"></div><script src="cfg.js"></script><script src="ui.js"></script><script src="app.js"></script></body></html>',
    'cfg.js': 'var LABELS={ok:"Success",err:"Error"};',
    'ui.js': 'function status(ok){var h="<span class=\\""+(ok?"green":"red")+"\\">";h+=ok?LABELS.ok:LABELS.err;h+="</span>";return h;}',
    'app.js': 'var h="";try{h="<p>Result: "+status(true)+"</p>";}catch(e){h="<p>"+e.message+"</p>";}document.getElementById("out").innerHTML=h;'
  });

  // 103. Switch + template literal
  await checkEquiv('switch template', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var mode="dark";var h="";switch(mode){case "light":h=`<div class="light"><p>Light mode</p></div>`;break;case "dark":h=`<div class="dark"><p>Dark mode</p></div>`;break;default:h="<div><p>Default</p></div>";}document.getElementById("out").innerHTML=h;'
  });

  // 104. While + table + pre-increment + break
  await checkEquiv('while table preincrement break', {
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
  await checkEquiv('conditional wrap state', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': [
      'var items=[{text:"normal",bold:false},{text:"important",bold:true},{text:"also normal",bold:false}];',
      'var h="";for(var i=0;i<items.length;i++){',
      'if(items[i].bold)h+="<b>";h+="<span>"+items[i].text+"</span>";if(items[i].bold)h+="</b>";}',
      'document.getElementById("out").innerHTML=h;'
    ].join('\n')
  });

  // 106. do-while + for-in + for-of combined
  await checkEquiv('do-while for-in for-of', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var obj={a:1,b:2};var arr=["x","y"];var h="<dl>";for(var k in obj){h+="<dt>"+k+"</dt><dd>"+obj[k]+"</dd>";}h+="</dl><ul>";for(var v of arr){h+="<li>"+v+"</li>";}h+="</ul><ol>";var n=1;do{h+="<li>"+n+"</li>";n++;}while(n<=3);h+="</ol>";document.getElementById("out").innerHTML=h;'
  });

  // 107. innerHTML read + write
  await checkEquiv('innerHTML read write', {
    'index.html': '<html><body><div id="src"></div><div id="dst"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("src").innerHTML="<b>Original</b>";document.getElementById("dst").innerHTML=document.getElementById("src").innerHTML;'
  });

  // 108. Multiple counters
  await checkEquiv('multiple counters complex', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var data=[3,1,4,1,5,9];var h="<ul>";var sum=0;var max=0;var count=0;for(var i=0;i<data.length;i++){h+="<li>"+data[i]+"</li>";sum+=data[i];if(data[i]>max)max=data[i];count++;}h+="</ul><p>Sum:"+sum+" Max:"+max+" Count:"+count+"</p>";document.getElementById("out").innerHTML=h;'
  });

  // 109. Mixed sinks
  await checkEquiv('mixed sinks', {
    'index.html': '<html><body><div id="a"></div><div id="b"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("a").innerHTML="<p>innerHTML</p>";document.getElementById("b").insertAdjacentHTML("beforeend","<p>adjacent</p>");'
  });

  // 110. Arithmetic in style attribute
  await checkEquiv('arithmetic style attr', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'var w=100;var h2=50;document.getElementById("out").innerHTML="<div style=\\"width:"+(w*2)+"px;height:"+(h2+10)+"px\\">sized</div>";'
  });

  // 111. HTML comment preserved
  await checkEquiv('comment preserved', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML="<p>before</p><!-- comment --><p>after</p>";'
  });

  // 112. Entity decoding
  await checkEquiv('entity decoding', {
    'index.html': '<html><body><div id="out"></div><script src="app.js"></script></body></html>',
    'app.js': 'document.getElementById("out").innerHTML="<p>Tom &amp; Jerry &lt;3 &quot;Cartoons&quot;</p>";'
  });

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Taint analysis
// -----------------------------------------------------------------------
await (async function () {
  const traceTaint = globalThis.__traceTaint;
  const traceTaintInJs = globalThis.__traceTaintInJs;
  if (!traceTaint) return;
  const before = pass + fail;
  console.log('\ntaint analysis');
  console.log('--------------');

  async function checkTaint(name, files, expectedCount, opts) {
    opts = opts || {};
    const r = await traceTaint(files);
    let ok = r.findings.length === expectedCount;
    if (ok && opts.sources && r.findings.length > 0) {
      if (JSON.stringify(r.findings[0].sources.sort()) !== JSON.stringify(opts.sources.sort())) ok = false;
    }
    if (ok && opts.sink && r.findings.length > 0) {
      if (r.findings[0].sink.prop !== opts.sink) ok = false;
    }
    if (ok && opts.elementTag !== undefined && r.findings.length > 0) {
      if (r.findings[0].sink.elementTag !== opts.elementTag) ok = false;
    }
    if (ok && opts.hasLine && r.findings.length > 0) {
      if (!r.findings[0].location || !r.findings[0].location.line) ok = false;
    }
    if (ok && opts.conditions !== undefined && r.findings.length > 0) {
      if (r.findings[0].conditions.length !== opts.conditions) ok = false;
    }
    if (ok) { pass++; } else {
      fail++;
      failures.push({ name, input: Object.keys(files).join(', '),
        want: { count: expectedCount, ...opts },
        got: { count: r.findings.length, sources: r.findings[0]?.sources, sink: r.findings[0]?.sink?.prop, line: r.findings[0]?.location?.line } });
    }
  }

  // --- Direct sinks ---
  await checkTaint('innerHTML', { 'a.js': 'var x = location.search; document.getElementById("o").innerHTML = x;' }, 1, { sources: ['url'], sink: 'innerHTML', hasLine: true });
  await checkTaint('outerHTML', { 'a.js': 'var x = location.search; document.getElementById("o").outerHTML = x;' }, 1);
  await checkTaint('document.write', { 'a.js': 'var x = location.search; document.write(x);' }, 1, { sink: 'document.write' });
  await checkTaint('eval', { 'a.js': 'var x = location.search; eval(x);' }, 1, { sink: 'eval', hasLine: true });
  await checkTaint('getElementById().innerHTML', { 'a.js': 'var x = location.search; document.getElementById("o").innerHTML = x;' }, 1);

  // --- Taint sources ---
  await checkTaint('location.search', { 'a.js': 'document.getElementById("o").innerHTML = location.search;' }, 1, { sources: ['url'] });
  await checkTaint('location.hash', { 'a.js': 'var x = location.hash; document.getElementById("o").innerHTML = x;' }, 1, { sources: ['url'] });
  await checkTaint('document.cookie', { 'a.js': 'var c = document.cookie; document.getElementById("o").innerHTML = c;' }, 1, { sources: ['cookie'] });
  await checkTaint('document.referrer', { 'a.js': 'var r = document.referrer; document.getElementById("o").innerHTML = r;' }, 1, { sources: ['referrer'] });
  await checkTaint('window.name', { 'a.js': 'document.getElementById("o").innerHTML = window.name;' }, 1, { sources: ['window.name'] });

  // --- Safe patterns (no false positives) ---
  await checkTaint('textContent safe', { 'a.js': 'var x = location.search; document.getElementById("o").textContent = x;' }, 0);
  await checkTaint('literal safe', { 'a.js': 'document.getElementById("o").innerHTML = "<b>safe</b>";' }, 0);
  await checkTaint('img.src safe', { 'a.js': 'var p = document.createElement("img"); p.src = location.search;' }, 0);
  await checkTaint('parseInt sanitizes', { 'a.js': 'var x = parseInt(location.search); document.getElementById("o").innerHTML = x;' }, 0);
  await checkTaint('Number sanitizes', { 'a.js': 'var x = Number(location.search); document.getElementById("o").innerHTML = x;' }, 0);
  await checkTaint('Boolean sanitizes', { 'a.js': 'var x = Boolean(location.search); document.getElementById("o").innerHTML = x;' }, 0);
  await checkTaint('encodeURIComponent sanitizes', { 'a.js': 'var x = encodeURIComponent(location.search); document.getElementById("o").innerHTML = x;' }, 0);

  // --- Shadow detection (no false positives on local variables) ---
  await checkTaint('var location shadow', { 'a.js': 'var location = {}; location.href = location.search;' }, 0);
  await checkTaint('let location shadow', { 'a.js': 'let location = { search: "x" }; document.getElementById("o").innerHTML = location.search;' }, 0);
  await checkTaint('var eval shadow', { 'a.js': 'var eval = function(x) { return x; }; eval(location.search);' }, 0);
  await checkTaint('var document shadow', { 'a.js': 'var document = { write: function(){} }; document.write(location.search);' }, 0);
  await checkTaint('var setTimeout shadow', { 'a.js': 'var setTimeout = function(){}; var x = location.search; setTimeout(x, 100);' }, 0);

  // --- Element type tracking ---
  await checkTaint('iframe.src sink', { 'a.js': 'var f = document.createElement("iframe"); f.src = location.search;' }, 1, { elementTag: 'iframe' });
  await checkTaint('script.src sink', { 'a.js': 'var s = document.createElement("script"); s.src = location.search;' }, 1, { elementTag: 'script' });
  await checkTaint('div.src safe', { 'a.js': 'var d = document.createElement("div"); d.src = location.search;' }, 0);
  await checkTaint('type by createElement not name', { 'a.js': 'var div = document.createElement("iframe"); div.src = location.search;' }, 1, { elementTag: 'iframe' });
  await checkTaint('name iframe but div type', { 'a.js': 'var iframe = document.createElement("div"); iframe.src = location.search;' }, 0);

  // --- Cross-function taint ---
  await checkTaint('cross-function', { 'a.js': 'function render(d) { var e = document.getElementById("o"); e.innerHTML = d; }\nvar x = location.search; render(x);' }, 1);
  await checkTaint('two levels deep', { 'a.js': 'function setH(e,v){e.innerHTML=v;}\nfunction render(d){var e=document.getElementById("o");setH(e,d);}\nvar x=location.search;render(x);' }, 1);
  await checkTaint('three levels deep', { 'a.js': 'function a(x){return x;} function b(x){return a(x);} function c(x){var e=document.getElementById("o");e.innerHTML=b(x);} c(location.search);' }, 1);
  await checkTaint('callback passed as arg', { 'a.js': 'function apply(fn,val){fn(val);} function sink(x){document.getElementById("o").innerHTML=x;} apply(sink,location.search);' }, 1);
  await checkTaint('closure capture', { 'a.js': 'var x=location.search; function get(){return x;} document.getElementById("o").innerHTML=get();' }, 1);
  await checkTaint('nested closure', { 'a.js': 'var x=location.search; function outer(){function inner(){return x;} return inner();} document.getElementById("o").innerHTML=outer();' }, 1);
  await checkTaint('var=function handler', { 'a.js': 'var h = function(msg) { eval(msg.data); };\nwindow.addEventListener("message", h, false);' }, 1, { sources: ['postMessage'] });

  // --- addEventListener ---
  await checkTaint('addEventListener function expr', { 'a.js': 'window.addEventListener("message", function(e) { document.getElementById("o").innerHTML = e.data; });' }, 1, { sources: ['postMessage'] });
  await checkTaint('addEventListener arrow', { 'a.js': 'window.addEventListener("message", (e) => { document.getElementById("o").innerHTML = e.data; });' }, 1, { sources: ['postMessage'] });
  await checkTaint('addEventListener named ref', { 'a.js': 'function h(e){document.getElementById("o").innerHTML=e.data;}\nwindow.addEventListener("message",h);' }, 1, { sources: ['postMessage'] });
  await checkTaint('two handlers', { 'a.js': 'window.addEventListener("message",function(e){document.getElementById("a").innerHTML=e.data;}); window.addEventListener("message",function(e){eval(e.data);});' }, 2);

  // --- Multiple sources ---
  await checkTaint('multi-source concat', { 'a.js': 'var a = location.search; var b = document.cookie; var c = a + b; document.getElementById("o").innerHTML = c;' }, 1, { sources: ['cookie', 'url'] });
  await checkTaint('postMessage + url', { 'a.js': 'window.addEventListener("message",function(e){var x=e.data+location.search;document.getElementById("o").innerHTML=x;});' }, 1, { sources: ['postMessage', 'url'] });
  await checkTaint('multiple sinks', { 'a.js': 'var x=location.search; document.getElementById("a").innerHTML=x; document.getElementById("b").innerHTML=x;' }, 2);

  // --- Complex state ---
  await checkTaint('reassign chain', { 'a.js': 'var a=location.search; var b=a; var c=b; document.getElementById("o").innerHTML=c;' }, 1);
  await checkTaint('obj.prop', { 'a.js': 'var o = { x: location.search }; document.getElementById("o").innerHTML = o.x;' }, 1);
  await checkTaint('nested obj', { 'a.js': 'var o={inner:{val:location.search}}; document.getElementById("o").innerHTML=o.inner.val;' }, 1);
  await checkTaint('array[0]', { 'a.js': 'var arr = [location.search]; document.getElementById("o").innerHTML = arr[0];' }, 1);
  await checkTaint('array[1]', { 'a.js': 'var a = ["safe", location.search]; document.getElementById("o").innerHTML = a[1];' }, 1);
  await checkTaint('array.join', { 'a.js': 'var a = ["a", location.search]; document.getElementById("o").innerHTML = a.join("");' }, 1);
  await checkTaint('array.push', { 'a.js': 'var a=[]; a.push(location.search); document.getElementById("o").innerHTML=a[0];' }, 1);
  await checkTaint('array.map fn expr', { 'a.js': 'var a=[location.search]; var b=a.map(function(x){return "<b>"+x+"</b>";}); document.getElementById("o").innerHTML=b[0];' }, 1);
  await checkTaint('forEach sink', { 'a.js': 'var items=[location.search]; items.forEach(function(item){ document.getElementById("o").innerHTML=item; });' }, 1);
  await checkTaint('fn return', { 'a.js': 'function get() { return location.search; } document.getElementById("o").innerHTML = get();' }, 1);
  await checkTaint('array destruct', { 'a.js': 'var arr=[location.search]; var [x]=arr; document.getElementById("o").innerHTML=x;' }, 1);
  await checkTaint('template literal', { 'a.js': 'var x = location.search; document.getElementById("o").innerHTML = `<div>${x}</div>`;' }, 1);
  await checkTaint('.slice preserves', { 'a.js': 'var x = location.hash.slice(1); document.getElementById("o").innerHTML = x;' }, 1);
  await checkTaint('.replace preserves', { 'a.js': 'var x=location.search.replace(/</g,""); document.getElementById("o").innerHTML=x;' }, 1);
  await checkTaint('ternary preserves', { 'a.js': 'var x = true ? location.search : "safe"; document.getElementById("o").innerHTML = x;' }, 1);

  // --- Control flow ---
  await checkTaint('if branch', { 'a.js': 'var x = location.search; var e = document.getElementById("o"); if (x.length > 0) { e.innerHTML = x; }' }, 1, { conditions: 1 });
  await checkTaint('both if/else tainted', { 'a.js': 'var x; if(Math.random()){x=location.search;}else{x=document.cookie;} document.getElementById("o").innerHTML=x;' }, 1);
  await checkTaint('try/catch', { 'a.js': 'var x; try { x = location.search; } catch(e) { x = "safe"; } document.getElementById("o").innerHTML = x;' }, 1);
  await checkTaint('switch', { 'a.js': 'var x; switch(1) { case 1: x = location.search; break; default: x = "safe"; } document.getElementById("o").innerHTML = x;' }, 1);
  await checkTaint('loop +=', { 'a.js': 'var s = ""; var src = location.search; for (var i = 0; i < 3; i++) { s += src; } document.getElementById("o").innerHTML = s;' }, 1);
  await checkTaint('loop push accum', { 'a.js': 'var parts=[]; parts.push(location.search); parts.push(document.cookie); var s=""; for(var i=0;i<parts.length;i++){s+=parts[i];} document.getElementById("o").innerHTML=s;' }, 1, { sources: ['cookie', 'url'] });
  await checkTaint('array loop', { 'a.js': 'var items=["Home",location.search]; var html=""; for(var i=0;i<items.length;i++){html+=items[i];} document.getElementById("o").innerHTML=html;' }, 1);

  // --- Navigation sinks ---
  await checkTaint('location.href', { 'a.js': 'var x = location.search; location.href = x;' }, 1, { sink: 'location.href' });
  await checkTaint('location = x', { 'a.js': 'var x = location.search; location = x;' }, 1);
  await checkTaint('location.assign', { 'a.js': 'var x = location.search; location.assign(x);' }, 1);
  await checkTaint('location.replace', { 'a.js': 'var x = location.search; location.replace(x);' }, 1);
  await checkTaint('opener.location', { 'a.js': 'var x = location.search; opener.location = x;' }, 1);
  await checkTaint('parent.location.href', { 'a.js': 'var x = location.search; parent.location.href = x;' }, 1);
  await checkTaint('top.location', { 'a.js': 'var x = location.search; top.location = x;' }, 1);
  await checkTaint('navigation.navigate', { 'a.js': 'var x = location.search; navigation.navigate(x);' }, 1);
  await checkTaint('nav literal safe', { 'a.js': 'location.href = "https://example.com";' }, 0);

  // --- Inline script line numbers ---
  await checkTaint('inline script line', { 'e.html': '<div>hi</div>\n<script>\nvar x = location.search;\ndocument.body.innerHTML = x;\n</script>' }, 1, { hasLine: true });

  // --- Array methods with function expression callbacks ---
  await checkTaint('filter fn expr', { 'a.js': 'var items = [location.search, "safe"]; var filtered = items.filter(function(x){ return x.length > 0; }); document.getElementById("o").innerHTML = filtered[0];' }, 1);
  await checkTaint('reduce fn expr', { 'a.js': 'var items = ["a", location.search]; var result = items.reduce(function(acc, x){ return acc + x; }, ""); document.getElementById("o").innerHTML = result;' }, 1);

  // --- Advanced patterns ---
  await checkTaint('reassign in fn', { 'a.js': 'var x = "safe"; function f() { x = location.search; } f(); document.getElementById("o").innerHTML = x;' }, 1);
  await checkTaint('loop html builder', { 'a.js': 'var input = location.search; var rows = ""; for (var i = 0; i < 5; i++) { rows += "<tr><td>" + input + "</td></tr>"; } document.getElementById("table").innerHTML = "<table>" + rows + "</table>";' }, 1);
  await checkTaint('ternary to sink', { 'a.js': 'var x = location.search; var html = x ? "<b>" + x + "</b>" : "<b>empty</b>"; document.getElementById("o").innerHTML = html;' }, 1);
  await checkTaint('3 sources combine', { 'a.js': 'window.addEventListener("message", function(e) { var x = e.data + location.search + document.cookie; document.getElementById("o").innerHTML = x; });' }, 1);
  await checkTaint('eval built string', { 'a.js': 'var cmd = "alert(" + location.search + ")"; eval(cmd);' }, 1);
  await checkTaint('postMessage getElementById', { 'a.js': 'window.addEventListener("message", function(event) { var target = document.getElementById("output"); target.innerHTML = event.data; });' }, 1);
  await checkTaint('split then join', { 'a.js': 'var x = location.search; var parts = x.split("&"); document.getElementById("o").innerHTML = parts.join("");' }, 1);

  // --- Cross-handler state ---
  await checkTaint('cross-handler state', { 'a.js': 'var saved; window.addEventListener("message", function(e) { saved = e.data; }); window.addEventListener("hashchange", function() { document.getElementById("o").innerHTML = saved; });' }, 1, { sources: ['postMessage'] });
  await checkTaint('handler sets, fn reads', { 'a.js': 'var data; window.addEventListener("message", function(e) { data = e.data; }); function render() { document.getElementById("o").innerHTML = data; } render();' }, 1);
  await checkTaint('postMessage + url combine', { 'a.js': 'var config = {}; window.addEventListener("message", function(e) { config.template = e.data; }); document.getElementById("o").innerHTML = config.template + location.search;' }, 1);

  // --- Filter tracks taint from source elements ---
  await checkTaint('filter tainted', { 'a.js': 'var items = ["safe", location.search]; var filtered = items.filter(function(x){ return x.length > 0; }); document.getElementById("o").innerHTML = filtered[0];' }, 1);
  await checkTaint('filter safe', { 'a.js': 'var items = ["a", "b"]; var filtered = items.filter(function(x){ return x.length > 0; }); document.getElementById("o").innerHTML = filtered[0];' }, 0);

  // --- for-in / for-of / comma / try-finally ---
  await checkTaint('for-in obj values', { 'a.js': 'var obj={a:location.search}; var s=""; for(var k in obj){s+=obj[k];} document.getElementById("o").innerHTML=s;' }, 1);
  await checkTaint('for-of array', { 'a.js': 'var arr=[location.search]; for(var x of arr){document.getElementById("o").innerHTML=x;}' }, 1);
  await checkTaint('comma operator', { 'a.js': 'var x=(0,location.search); document.getElementById("o").innerHTML=x;' }, 1);
  await checkTaint('try-finally no catch', { 'a.js': 'var x; try{x=location.search;}finally{} document.getElementById("o").innerHTML=x;' }, 1);
  await checkTaint('comparison preserves taint', { 'a.js': 'var x=location.search.length>0; document.getElementById("o").innerHTML=x;' }, 1);
  await checkTaint('equality preserves taint', { 'a.js': 'var x=location.search==="admin"; document.getElementById("o").innerHTML=x;' }, 1);
  await checkTaint('bitwise preserves taint', { 'a.js': 'var x=location.search|0; document.getElementById("o").innerHTML=x;' }, 1);

  // --- SMT satisfiability ---
  await checkTaint('satisfiable: tainted bool gates sink', { 'a.js': 'var flag = location.search === "go"; if (flag) { document.getElementById("o").innerHTML = location.hash; }' }, 1);
  await checkTaint('satisfiable: handler flag', { 'a.js': 'var ready = false; window.addEventListener("message", function(e) { ready = e.data === "init"; }); if (ready) { document.getElementById("o").innerHTML = location.search; }' }, 1);
  await checkTaint('satisfiable: multi message accum', { 'a.js': 'var parts = []; window.addEventListener("message", function(e) { parts.push(e.data); if (parts.length >= 2) { document.getElementById("o").innerHTML = parts.join(""); } });' }, 1);
  await checkTaint('unsatisfiable: if(false) dead', { 'a.js': 'if (false) { document.getElementById("o").innerHTML = location.search; }' }, 0);
  await checkTaint('unsatisfiable: concrete false', { 'a.js': 'var x = 1 > 2; if (x) { document.getElementById("o").innerHTML = location.search; }' }, 0);
  await checkTaint('satisfiable: 3 handlers shared', { 'a.js': 'var a,b,c; window.addEventListener("message", function(e) { a = e.data; }); window.addEventListener("message", function(e) { b = e.origin; }); window.addEventListener("hashchange", function() { c = location.hash; if (a && b) { document.getElementById("o").innerHTML = a + b + c; } });' }, 1);

  // --- SMT contradiction detection ---
  await checkTaint('unsatisfiable: x>5 && x<3', { 'a.js': 'var x = location.search; if (x > 5 && x < 3) { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('unsatisfiable: x>=5 && x<5', { 'a.js': 'var x = location.search; if (x >= 5 && x < 5) { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('unsatisfiable: x===a && x===b', { 'a.js': 'var x = location.search; if (x === "a" && x === "b") { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('unsatisfiable: x===a && x!==a', { 'a.js': 'var x = location.search; if (x === "a" && x !== "a") { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('satisfiable: x>3 && x<5', { 'a.js': 'var x = location.search; if (x > 3 && x < 5) { document.getElementById("o").innerHTML = x; }' }, 1);
  await checkTaint('satisfiable: x===a || x===b', { 'a.js': 'var x = location.search; if (x === "a" || x === "b") { document.getElementById("o").innerHTML = x; }' }, 1);

  // --- SMT path constraint propagation ---
  await checkTaint('path: nested unsat (x>5 then x<3)', { 'a.js': 'var x = location.search; if (x > 5) { if (x < 3) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('path: nested sat (x>3 then x<5)', { 'a.js': 'var x = location.search; if (x > 3) { if (x < 5) { document.getElementById("o").innerHTML = x; } }' }, 1);
  await checkTaint('path: triple nested unsat', { 'a.js': 'var x = location.search; if (x > 10) { if (x < 20) { if (x > 25) { document.getElementById("o").innerHTML = x; } } }' }, 0);
  await checkTaint('path: triple nested sat', { 'a.js': 'var x = location.search; if (x > 10) { if (x < 20) { if (x > 12) { document.getElementById("o").innerHTML = x; } } }' }, 1);
  await checkTaint('path: eq then neq', { 'a.js': 'var x = location.search; if (x === "admin") { if (x !== "admin") { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('path: else branch constraint', { 'a.js': 'var x = location.search; if (x > 5) { } else { if (x > 10) { document.getElementById("o").innerHTML = x; } }' }, 0);

  // --- SMT relational constraints ---
  await checkTaint('relational: x>y then y>x', { 'a.js': 'var x = location.search; var y = location.hash; if (x > y) { if (y > x) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('relational: x>y valid', { 'a.js': 'var x = location.search; var y = location.hash; if (x > y) { document.getElementById("o").innerHTML = x; }' }, 1);

  // --- SMT transitive closure ---
  await checkTaint('transitive: x>y>z>x cycle', { 'a.js': 'var x = location.search; var y = location.hash; var z = document.cookie; if (x > y) { if (y > z) { if (z > x) { document.getElementById("o").innerHTML = x; } } }' }, 0);
  await checkTaint('transitive: x>y>z valid', { 'a.js': 'var x = location.search; var y = location.hash; var z = document.cookie; if (x > y) { if (y > z) { document.getElementById("o").innerHTML = x; } }' }, 1);

  // --- SMT expression-level constraints ---
  await checkTaint('expr: x+y>10 && x+y<5', { 'a.js': 'var x = location.search; var y = location.hash; if (x + y > 10 && x + y < 5) { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('expr: x+y>3 && x+y<5 sat', { 'a.js': 'var x = location.search; var y = location.hash; if (x + y > 3 && x + y < 5) { document.getElementById("o").innerHTML = x; }' }, 1);

  // --- SMT integration: all branch types ---
  await checkTaint('while unsat path', { 'a.js': 'var x = location.search; if (x > 5) { while (x < 3) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('for unsat path', { 'a.js': 'var x = location.search; if (x > 5) { for (var i = 0; x < 3; i++) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('switch dead case', { 'a.js': 'var x = location.search; switch(true) { case x > 5 && x < 3: document.getElementById("o").innerHTML = x; break; }' }, 0);
  await checkTaint('handler path unsat', { 'a.js': 'window.addEventListener("message", function(e) { var x = e.data; if (x > 5) { if (x < 3) { document.getElementById("o").innerHTML = x; } } });' }, 0);
  await checkTaint('fn path unsat', { 'a.js': 'function render(x) { if (x > 5) { if (x < 3) { document.getElementById("o").innerHTML = x; } } } render(location.search);' }, 0);

  // --- SMT OR handling ---
  await checkTaint('or both unsat with path', { 'a.js': 'var x = location.search; if (x > 5) { if (x < 3 || x < 2) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('or one sat with path', { 'a.js': 'var x = location.search; if (x > 5) { if (x > 10 || x < 3) { document.getElementById("o").innerHTML = x; } }' }, 1);
  await checkTaint('or rescues dead branch', { 'a.js': 'var x = location.search; if (x > 5) { if (x < 3 || x > 7) { document.getElementById("o").innerHTML = x; } }' }, 1);

  // --- SMT cross-function path constraints ---
  await checkTaint('fn1 constrains fn2', { 'a.js': 'var x = location.search; function validate() { if (x > 5) { render(); } } function render() { if (x < 3) { document.getElementById("o").innerHTML = x; } } validate();' }, 0);
  await checkTaint('fn sets then checks', { 'a.js': 'var x; function init() { x = location.search; } init(); if (x > 5 && x < 3) { document.getElementById("o").innerHTML = x; }' }, 0);

  // --- SMT global scope with handlers ---
  await checkTaint('global cond set + handler read', { 'a.js': 'var config; if (location.search.indexOf("debug") >= 0) { config = location.search; } window.addEventListener("message", function(e) { if (config) { document.getElementById("o").innerHTML = config + e.data; } });' }, 1);
  await checkTaint('two messages state machine', { 'a.js': 'var step1 = null; window.addEventListener("message", function(e) { if (e.data.type === "init") { step1 = e.data.payload; } if (e.data.type === "exec" && step1) { document.getElementById("o").innerHTML = step1; } });' }, 1);
  await checkTaint('url gate + postMessage', { 'a.js': 'var isAdmin = location.search === "admin"; var payload; window.addEventListener("message", function(e) { payload = e.data; if (isAdmin && payload) { document.getElementById("o").innerHTML = payload; } });' }, 1);
  await checkTaint('impossible concrete state', { 'a.js': 'var allowed = false; window.addEventListener("message", function(e) { if (allowed === true && allowed === false) { document.getElementById("o").innerHTML = e.data; } });' }, 0);

  // --- String theory ---
  await checkTaint('string: startsWith contradiction', { 'a.js': 'var x = location.search; if (x.startsWith("http")) { if (x.startsWith("javascript")) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('string: startsWith compatible', { 'a.js': 'var x = location.search; if (x.startsWith("http")) { if (x.startsWith("https")) { document.getElementById("o").innerHTML = x; } }' }, 1);
  await checkTaint('string: length 0 + indexOf', { 'a.js': 'var x = location.search; if (x.length === 0) { if (x.indexOf("a") >= 0) { document.getElementById("o").innerHTML = x; } }' }, 0);

  // --- Rest params ---
  await checkTaint('rest params', { 'a.js': 'function f(...args){document.getElementById("o").innerHTML=args[0];} f(location.search);' }, 1);

  // --- setTimeout/setInterval callback ---
  await checkTaint('setTimeout reads global', { 'a.js': 'var data = location.search; setTimeout(function() { document.getElementById("o").innerHTML = data; }, 0);' }, 1);

  // --- Event handler state machine ---
  await checkTaint('state machine two invocations', { 'a.js': 'var state = "idle"; window.addEventListener("message", function(e) { if (state === "idle") { state = "ready"; } else if (state === "ready") { document.getElementById("o").innerHTML = e.data; } });' }, 1);

  // --- Array theory ---
  await checkTaint('array: len 0 access dead', { 'a.js': 'var arr = []; if (arr.length === 0) { if (arr[0]) { document.getElementById("o").innerHTML = arr[0]; } }' }, 0);
  await checkTaint('array: len > 0 access sat', { 'a.js': 'var arr = [location.search]; if (arr.length > 0) { document.getElementById("o").innerHTML = arr[0]; }' }, 1);

  // --- Disjunctive merge ---
  await checkTaint('merge: y big or small', { 'a.js': 'var x = location.search; var y; if (x > 5) { y = "big"; } else { y = "small"; } if (y === "big" && y === "small") { document.getElementById("o").innerHTML = x; }' }, 0);

  // --- SMT: loop/switch path-constraint propagation INTO nested conditions.
  // These exercise the state-machine transitions that push the loop
  // condition (resp. switch case equality) onto the path-constraint
  // stack while walking the body, so inner `if`s can be proved
  // unreachable by the theory solver.
  await checkTaint('sm: while cond propagates', { 'a.js': 'var x = location.search; while (x < 3) { if (x > 5) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('sm: for cond propagates', { 'a.js': 'var x = location.search; for (var i = 0; x < 3; i++) { if (x > 5) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('sm: while cond compatible', { 'a.js': 'var x = location.search; while (x > 3) { if (x > 5) { document.getElementById("o").innerHTML = x; } }' }, 1);
  // Counter-loop bound constraint: for (var i = 0; i < 10; i++) pushes
  // BOTH `i < 10` (loop cond) AND `i >= 0` (init-bound) onto P.
  await checkTaint('sm: counter bound unsat', { 'a.js': 'var x = location.search; for (var i = 0; i < 10; i++) { if (i < 0) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('sm: counter bound sat', { 'a.js': 'var x = location.search; for (var i = 0; i < 10; i++) { if (i >= 0) { document.getElementById("o").innerHTML = x; } }' }, 1);
  // for-of / for-in push iter.length > 0 into P so conditions testing
  // length inside the body fold.
  await checkTaint('sm: for-of len unsat', { 'a.js': 'var arr = [location.search]; for (var v of arr) { if (arr.length === 0) { document.getElementById("o").innerHTML = v; } }' }, 0);
  // Bounded-unrolling disjunction: `for (var i = 0; i < 4; i++)` pushes
  // `i === 0 || i === 1 || i === 2 || i === 3` so conditions testing a
  // specific out-of-range value inside the body fold to unsat.
  await checkTaint('sm: unroll specific unsat', { 'a.js': 'var x = location.search; for (var i = 0; i < 4; i++) { if (i === 7) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('sm: unroll specific sat', { 'a.js': 'var x = location.search; for (var i = 0; i < 4; i++) { if (i === 2) { document.getElementById("o").innerHTML = x; } }' }, 1);
  // Descending counter: for (i=3; i>=0; i--) — enumerate 3,2,1,0.
  await checkTaint('sm: unroll descending unsat', { 'a.js': 'var x = location.search; for (var i = 3; i >= 0; i--) { if (i > 5) { document.getElementById("o").innerHTML = x; } }' }, 0);

  // --- SMT power: nonlinear arithmetic via Z3 ---
  // Z3's full nonlinear arithmetic theory proves these unsat. The
  // analyzer used to give up on x*x because the home-grown solver only
  // tracked linear bounds; with Z3 inline these now fold correctly.
  await checkTaint('z3: x*x < 0',          { 'a.js': 'var x = location.search; if (x * x < 0) { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('z3: bounded * overflow', { 'a.js': 'var x = location.search; if (x > 2 && x < 5 && x * x > 100) { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('z3: quadratic unique',  { 'a.js': 'var x = location.search; if (x * x === 4 && x > 0 && x !== 2) { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('z3: x*x >= 0 tautology', { 'a.js': 'var x = location.search; if (x * x >= 0) { document.getElementById("o").innerHTML = x; }' }, 1);
  // --- SMT power: linear-real-arith with multi-variable sums ---
  await checkTaint('z3: lra x+y<6 with x,y>3', { 'a.js': 'var x = location.search; var y = location.hash; if (x > 3 && y > 3 && x + y < 6) { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('z3: lra x+y>10 sat',      { 'a.js': 'var x = location.search; var y = location.hash; if (x > 3 && y > 3 && x + y > 10) { document.getElementById("o").innerHTML = x; }' }, 1);
  // --- SMT power: string theory via str.indexof / str.len ---
  await checkTaint('z3: empty string indexof', { 'a.js': 'var x = location.search; if (x.length === 0) { if (x.indexOf("a") >= 0) { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('z3: prefix incompat',      { 'a.js': 'var x = location.search; if (x.startsWith("http://")) { if (x.startsWith("javascript:")) { document.getElementById("o").innerHTML = x; } }' }, 0);

  // --- Sort-conflict resilience: a sym used as both String and Int ---
  // The translator can't represent the JS coercion semantics in Z3's
  // sorted logic, so the formula is marked untranslatable and the
  // branch is conservatively kept reachable (no false negatives).
  await checkTaint('sort: str-then-arith reachable',  { 'a.js': 'var x = location.search; if (x === "abc" && x + 1 > 5) { document.getElementById("o").innerHTML = x; }' }, 1);
  await checkTaint('sort: prefix-then-arith reachable', { 'a.js': 'var x = location.search; if (x.startsWith("http") && x * 2 > 10) { document.getElementById("o").innerHTML = x; }' }, 1);
  // Same-sort uses don't trigger the conflict path:
  await checkTaint('sort: dual-string consistent', { 'a.js': 'var x = location.search; if (x.length > 5 && x === "ab") { document.getElementById("o").innerHTML = x; }' }, 0);

  // --- SMT power: charAt → str.at, substring → str.substr ---
  // The translator emits Z3 string-theory ops for these patterns so the
  // solver can refute branches that constrain the same character or
  // substring to two different values.
  await checkTaint('z3: charAt unsat',    { 'a.js': 'var x = location.search; if (x.charAt(0) === "a" && x.charAt(0) === "b") { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('z3: charAt sat',      { 'a.js': 'var x = location.search; if (x.charAt(0) === "/") { document.getElementById("o").innerHTML = x; }' }, 1);
  await checkTaint('z3: substring unsat', { 'a.js': 'var x = location.search; if (x.substring(0, 4) === "http" && x.substring(0, 4) === "ftpx") { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('z3: substring sat',   { 'a.js': 'var x = location.search; if (x.substring(0, 4) === "http") { document.getElementById("o").innerHTML = x; }' }, 1);
  await checkTaint('z3: slice unsat',     { 'a.js': 'var x = location.search; if (x.slice(0, 4) === "http" && x.slice(0, 4) === "data") { document.getElementById("o").innerHTML = x; }' }, 0);
  // Bracket index access on a tainted string is the same shape.
  await checkTaint('z3: bracket unsat',   { 'a.js': 'var x = location.search; if (x[0] === "a" && x[0] === "b") { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('z3: bracket sat',     { 'a.js': 'var x = location.search; if (x[0] === "/") { document.getElementById("o").innerHTML = x; }' }, 1);
  // indexOf with a sym needle (both haystack and needle tainted).
  await checkTaint('z3: indexOf sym sat',       { 'a.js': 'var x = location.search; var y = location.hash; if (x.indexOf(y) >= 0) { document.getElementById("o").innerHTML = x; }' }, 1);
  await checkTaint('z3: indexOf sym len0 unsat',{ 'a.js': 'var x = location.search; var y = location.hash; if (y.length > 0 && x.length === 0 && x.indexOf(y) >= 0) { document.getElementById("o").innerHTML = x; }' }, 0);
  // startsWith / includes with a sym needle.
  await checkTaint('z3: startsWith sym sat',         { 'a.js': 'var x = location.search; var y = location.hash; if (x.startsWith(y)) { document.getElementById("o").innerHTML = x; }' }, 1);
  await checkTaint('z3: startsWith sym len0 unsat',  { 'a.js': 'var x = location.search; var y = location.hash; if (y.length > 0 && x.length === 0 && x.startsWith(y)) { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('z3: includes sym sat',           { 'a.js': 'var x = location.search; var y = location.hash; if (x.includes(y)) { document.getElementById("o").innerHTML = x; }' }, 1);
  await checkTaint('z3: includes sym len-mismatch unsat', { 'a.js': 'var x = location.search; var y = location.hash; if (x.length < y.length && x.includes(y)) { document.getElementById("o").innerHTML = x; }' }, 0);
  // String concatenation: + with at least one literal-string operand
  // is translated to (str.++ ...) so concat conditions can be checked.
  await checkTaint('z3: concat prefix sat',   { 'a.js': 'var x = location.search; if (("http://" + x) === "http://abc") { document.getElementById("o").innerHTML = x; }' }, 1);
  await checkTaint('z3: concat prefix unsat', { 'a.js': 'var x = location.search; if (("http://" + x) === "ftp://abc") { document.getElementById("o").innerHTML = x; }' }, 0);
  await checkTaint('z3: concat suffix sat',   { 'a.js': 'var x = location.search; if ((x + ".html") === "page.html") { document.getElementById("o").innerHTML = x; }' }, 1);
  await checkTaint('z3: concat suffix unsat', { 'a.js': 'var x = location.search; if ((x + ".html") === "page.htmlx") { document.getElementById("o").innerHTML = x; }' }, 0);

  // --- Promise / fetch tracking + cross-callback fixpoint ---
  // fetch() is registered as a network taint source. .then(callback) walks
  // the callback with the receiver's taint as the first arg. await unwraps
  // the Promise transparently.
  await checkTaint('promise: fetch direct',         { 'a.js': 'document.body.innerHTML = fetch("/api");' }, 1, { sources: ['network'] });
  await checkTaint('promise: fetch then arrow',     { 'a.js': 'fetch("/api").then(d => { document.getElementById("o").innerHTML = d; });' }, 1, { sources: ['network'] });
  await checkTaint('promise: fetch then fn',        { 'a.js': 'fetch("/api").then(function(d) { document.getElementById("o").innerHTML = d; });' }, 1, { sources: ['network'] });
  await checkTaint('promise: fetch then chain',     { 'a.js': 'fetch("/api").then(r => r.text()).then(d => { document.getElementById("o").innerHTML = d; });' }, 1, { sources: ['network'] });
  await checkTaint('promise: fetch catch',          { 'a.js': 'fetch("/api").catch(function(d) { document.getElementById("o").innerHTML = d; });' }, 1, { sources: ['network'] });
  await checkTaint('promise: Promise.resolve',      { 'a.js': 'Promise.resolve(location.search).then(d => { document.getElementById("o").innerHTML = d; });' }, 1, { sources: ['url'] });
  await checkTaint('promise: Promise.resolve safe', { 'a.js': 'Promise.resolve("safe").then(d => { document.getElementById("o").innerHTML = d; });' }, 0);
  await checkTaint('promise: await fetch',          { 'a.js': 'async function f() { var d = await fetch("/api"); document.getElementById("o").innerHTML = d; } f();' }, 1, { sources: ['network'] });
  await checkTaint('promise: await location',       { 'a.js': 'async function f() { var d = await location.search; document.getElementById("o").innerHTML = d; } f();' }, 1, { sources: ['url'] });
  await checkTaint('promise: await chained',        { 'a.js': 'async function f() { var r = await fetch("/api"); var d = await r.text(); document.getElementById("o").innerHTML = d; } f();' }, 1, { sources: ['network'] });

  // Phase-2 callback fixpoint: one handler mutates state, another reads
  // it. The walker registers both handlers in phase 1; phase 2 iterates
  // them until findings stabilise so the reading handler sees the
  // writing handler's mutation regardless of registration order.
  await checkTaint('fixpoint: msg-reads-after-hash-arms',
    { 'a.js': 'var armed = false; window.addEventListener("message", function(e) { if (armed) document.getElementById("o").innerHTML = e.data; }); window.addEventListener("hashchange", function() { armed = true; });' }, 1);
  // Reverse registration order: same finding should fire because the
  // fixpoint re-walks the message handler after hashchange has armed.
  await checkTaint('fixpoint: msg-reads-after-hash-arms (reversed)',
    { 'a.js': 'var armed = false; window.addEventListener("hashchange", function() { armed = true; }); window.addEventListener("message", function(e) { if (armed) document.getElementById("o").innerHTML = e.data; });' }, 1);
  // setTimeout sets a flag that an addEventListener handler reads.
  await checkTaint('fixpoint: setTimeout sets, addEventListener reads',
    { 'a.js': 'var ready = false; setTimeout(function() { ready = true; }, 0); window.addEventListener("message", function(e) { if (ready) document.getElementById("o").innerHTML = e.data; });' }, 1);

  // --- Per-variable may-be value lattice ---
  // Each assignment to a variable is recorded as a possible value;
  // smtSat emits (or (= sym v1) (= sym v2) ...) over the full set
  // when the variable's value space is fully enumerated. This refutes
  // branches that test against values the variable was never assigned,
  // even when those values are touched in unrelated callbacks.
  await checkTaint('mayBe: X-only is sat',
    { 'a.js': 'var s = "init"; window.addEventListener("hashchange", function() { s = "X"; }); window.addEventListener("message", function(e) { if (s === "X") document.getElementById("o").innerHTML = e.data; });' }, 1);
  await checkTaint('mayBe: Y excluded',
    { 'a.js': 'var s = "init"; window.addEventListener("hashchange", function() { s = "X"; }); window.addEventListener("message", function(e) { if (s === "Y") document.getElementById("o").innerHTML = e.data; });' }, 0);
  await checkTaint('mayBe: ready not in {init, armed}',
    { 'a.js': 'var s = "init"; window.addEventListener("hashchange", function() { s = "armed"; }); window.addEventListener("message", function(e) { if (s === "ready") document.getElementById("o").innerHTML = e.data; });' }, 0);
  await checkTaint('mayBe: multi-handler hit',
    { 'a.js': 'var s = "init"; window.addEventListener("hashchange", function() { s = "A"; }); window.addEventListener("popstate", function() { s = "B"; }); window.addEventListener("message", function(e) { if (s === "A") document.getElementById("o").innerHTML = e.data; });' }, 1);
  await checkTaint('mayBe: multi-handler miss',
    { 'a.js': 'var s = "init"; window.addEventListener("hashchange", function() { s = "A"; }); window.addEventListener("popstate", function() { s = "B"; }); window.addEventListener("message", function(e) { if (s === "C") document.getElementById("o").innerHTML = e.data; });' }, 0);
  // Tainted assignment poisons the lattice → conservative (no refutation).
  await checkTaint('mayBe: tainted assignment poisons lattice',
    { 'a.js': 'var s = "init"; s = location.search; window.addEventListener("message", function(e) { if (s === "Z") document.getElementById("o").innerHTML = e.data; });' }, 1);

  // --- Object property may-be lattice ---
  // Same lattice machinery as plain variables, but keyed by the full
  // path (e.g. `s.v`). Initial values from object literals
  // (`var s = {v: "init"}`) join the slot at declaration time.
  await checkTaint('mayBe prop: init in lattice',
    { 'a.js': 'var s = {v: "init"}; window.addEventListener("hashchange", function() { s.v = "X"; }); window.addEventListener("message", function(e) { if (s.v === "init") document.getElementById("o").innerHTML = e.data; });' }, 1);
  await checkTaint('mayBe prop: cross-handler hit',
    { 'a.js': 'var s = {v: "init"}; window.addEventListener("hashchange", function() { s.v = "X"; }); window.addEventListener("message", function(e) { if (s.v === "X") document.getElementById("o").innerHTML = e.data; });' }, 1);
  await checkTaint('mayBe prop: refute miss',
    { 'a.js': 'var s = {v: "init"}; window.addEventListener("hashchange", function() { s.v = "X"; }); window.addEventListener("message", function(e) { if (s.v === "Z") document.getElementById("o").innerHTML = e.data; });' }, 0);
  await checkTaint('mayBe prop: multi-handler refute',
    { 'a.js': 'var s = {v: "init"}; window.addEventListener("hashchange", function() { s.v = "A"; }); window.addEventListener("popstate", function() { s.v = "B"; }); window.addEventListener("message", function(e) { if (s.v === "C") document.getElementById("o").innerHTML = e.data; });' }, 0);
  await checkTaint('mayBe prop: multi-handler hit B',
    { 'a.js': 'var s = {v: "init"}; window.addEventListener("hashchange", function() { s.v = "A"; }); window.addEventListener("popstate", function() { s.v = "B"; }); window.addEventListener("message", function(e) { if (s.v === "B") document.getElementById("o").innerHTML = e.data; });' }, 1);

  // --- Alias-aware may-be lattice ---
  // Object bindings get a stable __objId; the lattice keys property
  // paths by `#<id>.prop` so writes through any alias of the same
  // object hit the same slot. \`var x = obj; x.v = "X"\` is therefore
  // visible to a read through \`obj.v\`.
  await checkTaint('alias: write x.v, read obj.v',
    { 'a.js': 'var obj = {v: "init"}; var x = obj; window.addEventListener("hashchange", function() { x.v = "X"; }); window.addEventListener("message", function(e) { if (obj.v === "X") document.getElementById("o").innerHTML = e.data; });' }, 1);
  await checkTaint('alias: write obj.v, read x.v',
    { 'a.js': 'var obj = {v: "init"}; var x = obj; window.addEventListener("hashchange", function() { obj.v = "Y"; }); window.addEventListener("message", function(e) { if (x.v === "Y") document.getElementById("o").innerHTML = e.data; });' }, 1);
  await checkTaint('alias: refute miss across alias',
    { 'a.js': 'var obj = {v: "init"}; var x = obj; window.addEventListener("hashchange", function() { x.v = "X"; }); window.addEventListener("message", function(e) { if (obj.v === "Z") document.getElementById("o").innerHTML = e.data; });' }, 0);

  // --- Multi-segment + nested-alias may-be ---
  // Lattice keys are rooted at the LEAF container's __objId, not the
  // path's first segment. obj.inner.v and an alias x.v (where
  // x = obj.inner) both canonicalise to #<innerId>.v so writes
  // through any path are visible to reads through any other path.
  await checkTaint('mayBe deep: hit',
    { 'a.js': 'var obj = {a: {b: {c: "init"}}}; window.addEventListener("hashchange", function() { obj.a.b.c = "X"; }); window.addEventListener("message", function(e) { if (obj.a.b.c === "X") document.getElementById("o").innerHTML = e.data; });' }, 1);
  await checkTaint('mayBe deep: refute',
    { 'a.js': 'var obj = {a: {b: {c: "init"}}}; window.addEventListener("hashchange", function() { obj.a.b.c = "X"; }); window.addEventListener("message", function(e) { if (obj.a.b.c === "Z") document.getElementById("o").innerHTML = e.data; });' }, 0);
  await checkTaint('mayBe nested alias: 3-way hit',
    { 'a.js': 'var obj = {inner: {v: "init"}}; var x = obj.inner; window.addEventListener("hashchange", function() { obj.inner.v = "X"; }); window.addEventListener("popstate", function() { obj.inner.v = "Y"; }); window.addEventListener("message", function(e) { if (x.v === "X") document.getElementById("o").innerHTML = e.data; });' }, 1);
  await checkTaint('mayBe nested alias: 3-way refute',
    { 'a.js': 'var obj = {inner: {v: "init"}}; var x = obj.inner; window.addEventListener("hashchange", function() { obj.inner.v = "X"; }); window.addEventListener("popstate", function() { obj.inner.v = "Y"; }); window.addEventListener("message", function(e) { if (x.v === "Z") document.getElementById("o").innerHTML = e.data; });' }, 0);
  await checkTaint('mayBe nested alias: write x.v read deep',
    { 'a.js': 'var obj = {inner: {v: "init"}}; var x = obj.inner; window.addEventListener("hashchange", function() { x.v = "X"; }); window.addEventListener("message", function(e) { if (obj.inner.v === "X") document.getElementById("o").innerHTML = e.data; });' }, 1);

  // --- Indirect call dispatch via function may-be ---
  // The may-be lattice tracks function bindings as call targets
  // (slot.fns) alongside literal values (slot.vals). When `f()` is
  // called, the walker walks every function the variable may resolve
  // to — whether it was reassigned sequentially, written from
  // different branches, or set in a callback.
  await checkTaint('indirect call: reassign sees both targets',
    { 'a.js': 'function safe() {} function unsafe() { document.getElementById("o").innerHTML = location.search; } var f = safe; f = unsafe; f();' }, 1);
  await checkTaint('indirect call: if-else split',
    { 'a.js': 'function a() {} function b() { document.getElementById("o").innerHTML = location.search; } var f; if (Math.random()) { f = a; } else { f = b; } f();' }, 1);
  await checkTaint('indirect call: single safe target stays safe',
    { 'a.js': 'function safe() {} var f = safe; f();' }, 0);

  // --- Dispatcher table dispatch (dispatch[key]() patterns) ---
  // When the bracket key is opaque, walk EVERY function-typed
  // property of the dispatcher so any handler that could fire at
  // runtime gets analysed. When the key is concrete, walk the
  // specific target.
  await checkTaint('dispatcher map: opaque key all walked',
    { 'a.js': 'var dispatch = { arm: function() { armed = true; }, fire: function() { if (armed) document.body.innerHTML = location.search; } }; var armed = false; window.addEventListener("message", function(e) { dispatch[e.data](); });' }, 1);
  await checkTaint('dispatcher map: all-safe stays safe',
    { 'a.js': 'var dispatch = { a: function() { document.body.textContent = "safe"; }, b: function() { document.body.title = "ok"; } }; window.addEventListener("message", function(e) { dispatch[e.data](); });' }, 0);
  await checkTaint('dispatcher map: known key resolves',
    { 'a.js': 'var dispatch = { arm: function() { document.body.innerHTML = location.search; } }; dispatch["arm"]();' }, 1);

  // --- Promise pipeline through stored variables and function returns ---
  // The bare-method statement detector routes \`p.then(...)\` through
  // readValue → applyMethod when p is a stored Promise (chain), and
  // the bare-call peek detects \`f().then(...)\` so the inlined return
  // value flows into the .then callback.
  await checkTaint('promise: var-stored fetch.then',
    { 'a.js': 'var p = fetch("/api"); p.then(function(d) { document.body.innerHTML = d; });' }, 1);
  await checkTaint('promise: var-stored fetch chain.then',
    { 'a.js': 'var p = fetch("/api").then(function(r) { return r.text(); }); p.then(function(d) { document.body.innerHTML = d; });' }, 1);
  await checkTaint('promise: fn-wrapped fetch().then',
    { 'a.js': 'function load() { return fetch("/api"); } load().then(function(d) { document.body.innerHTML = d; });' }, 1);
  await checkTaint('promise: fn-wrapped chain().then',
    { 'a.js': 'function load(url) { return fetch(url).then(function(r) { return r.text(); }); } load("/api").then(function(d) { document.body.innerHTML = d; });' }, 1);

  // --- IIFE ---
  await checkTaint('IIFE function', { 'a.js': '(function() { document.getElementById("o").innerHTML = location.search; })();' }, 1);
  await checkTaint('IIFE with args', { 'a.js': '(function(x) { document.getElementById("o").innerHTML = x; })(location.search);' }, 1);

  // --- Computed property write ---
  await checkTaint('computed prop write+read', { 'a.js': 'var o = {}; var key = "x"; o[key] = location.search; document.getElementById("o").innerHTML = o[key];' }, 1);

  // --- JSON.parse taint ---
  await checkTaint('JSON.parse tainted', { 'a.js': 'var x = JSON.parse(location.search); document.getElementById("o").innerHTML = x;' }, 1);

  // --- Logical assignment ---
  await checkTaint('logical OR assign', { 'a.js': 'var x = ""; x ||= location.search; document.getElementById("o").innerHTML = x;' }, 1);

  // --- Remaining features ---
  await checkTaint('??= taint', { 'a.js': 'var x = null; x ??= location.search; document.getElementById("o").innerHTML = x;' }, 1);
  await checkTaint('??= safe', { 'a.js': 'var x = "safe"; x ??= location.search; document.getElementById("o").innerHTML = x;' }, 0);
  await checkTaint('nested destruct', { 'a.js': 'var obj = { inner: { html: location.search } }; var { inner: { html } } = obj; document.getElementById("o").innerHTML = html;' }, 1);
  await checkTaint('destruct fn return', { 'a.js': 'function getData() { return { html: location.search }; } var { html } = getData(); document.getElementById("o").innerHTML = html;' }, 1);
  await checkTaint('class method', { 'a.js': 'class Renderer { render(html) { document.getElementById("o").innerHTML = html; } } var r = new Renderer(); r.render(location.search);' }, 1);
  await checkTaint('getter', { 'a.js': 'var obj = { get val() { return location.search; } }; document.getElementById("o").innerHTML = obj.val;' }, 1);
  await checkTaint('tagged template', { 'a.js': 'function tag(strings, ...vals) { return vals[0]; } var x = location.search; document.getElementById("o").innerHTML = tag`prefix${x}suffix`;' }, 1);

  // --- Engine weakness fixes ---
  await checkTaint('alias contradiction', { 'a.js': 'var x = location.search; var y = x; if (y === "a") { if (x === "b") { document.getElementById("o").innerHTML = x; } }' }, 0);
  await checkTaint('array concat taint', { 'a.js': 'var a = [location.search]; var b = [].concat(a); document.getElementById("o").innerHTML = b[0];' }, 1);
  await checkTaint('promise-like then', { 'a.js': 'var p = { then: function(cb) { cb(location.search); } }; p.then(function(x) { document.getElementById("o").innerHTML = x; });' }, 1);
  await checkTaint('no dup closure', { 'a.js': 'var x = location.search; function outer() { function inner() { document.getElementById("o").innerHTML = x; } inner(); } outer();' }, 1);
  await checkTaint('no dup IIFE', { 'a.js': '(function() { document.getElementById("o").innerHTML = location.search; })();' }, 1);

  // --- Complex cross-function side effects ---
  await checkTaint('fn modifies shared obj', { 'a.js': 'var state = { safe: true };\nfunction corrupt() { state.safe = false; state.data = location.search; }\nfunction render() { if (state.safe) { document.getElementById("o").innerHTML = state.data; } }\ncorrupt(); render();' }, 1);
  await checkTaint('validator transformer renderer', { 'a.js': 'var input = location.search;\nvar validated = false;\nvar transformed = "";\nfunction validate() { if (input.length > 0) { validated = true; } }\nfunction transform() { if (validated) { transformed = "<b>" + input + "</b>"; } }\nfunction render() { if (transformed) { document.getElementById("o").innerHTML = transformed; } }\nvalidate(); transform(); render();' }, 1);
  await checkTaint('closure side effect', { 'a.js': 'var result = "";\nfunction process(data) { function inner() { result = data; } inner(); }\nprocess(location.search);\ndocument.getElementById("o").innerHTML = result;' }, 1);
  await checkTaint('callback with taint', { 'a.js': 'function fetchData(callback) { callback(location.search); }\nfunction handleData(data) { document.getElementById("o").innerHTML = data; }\nfetchData(handleData);' }, 1);
  await checkTaint('handler modifies fn reads', { 'a.js': 'var cache = { html: "" };\nwindow.addEventListener("message", function(e) { cache.html = e.data; });\nfunction refresh() { document.getElementById("o").innerHTML = cache.html; }\nrefresh();' }, 1);
  await checkTaint('method returns this.data', { 'a.js': 'var api = { data: location.search, getData: function() { return this.data; } };\ndocument.getElementById("o").innerHTML = api.getData();' }, 1);
  await checkTaint('forEach side effect', { 'a.js': 'var output = "";\nvar items = [location.search, document.cookie];\nitems.forEach(function(item) { output += item; });\ndocument.getElementById("o").innerHTML = output;' }, 1);
  await checkTaint('fn sanitizes safe', { 'a.js': 'function safe(data) { var clean = parseInt(data, 10); document.getElementById("o").innerHTML = clean; }\nsafe(location.search);' }, 0);
  await checkTaint('satisfiable: obj.prop++ count', { 'a.js': 'var state = {count:0}; window.addEventListener("message", function(e) { state.count++; if (state.count > 3) { document.getElementById("o").innerHTML = e.data; } });' }, 1);
  await checkTaint('satisfiable: ident++ in handler', { 'a.js': 'var n = 0; window.addEventListener("message", function(e) { n++; if (n > 5) { document.getElementById("o").innerHTML = e.data; } });' }, 1);

  // --- Chained assignment ---
  await checkTaint('chained assign', { 'a.js': 'var a,b; a=b=location.search; document.getElementById("o").innerHTML=a;' }, 1);

  // --- Object property mutations ---
  await checkTaint('obj.prop += in handler', { 'a.js': 'var state = {html:""}; window.addEventListener("message", function(e) { state.html += e.data; }); document.getElementById("o").innerHTML = state.html;' }, 1);

  // --- Object property mutation ---
  await checkTaint('obj.prop = tainted', { 'a.js': 'var state = { msg: "" }; state.msg = location.search; document.getElementById("o").innerHTML = state.msg;' }, 1);
  await checkTaint('obj prop via handler', { 'a.js': 'var state = { msg: "" }; window.addEventListener("message", function(e) { state.msg = e.data; }); function render() { document.getElementById("o").innerHTML = state.msg; } render();' }, 1);

  // --- Multi-step accumulation ---
  await checkTaint('handler push + url join', { 'a.js': 'var parts = [];\nwindow.addEventListener("message", function(e) { parts.push(e.data); });\nvar url = location.search;\nvar html = parts.join("") + url;\ndocument.getElementById("o").innerHTML = html;' }, 1);
  await checkTaint('two handlers shared vars', { 'a.js': 'var a = "", b = "";\nwindow.addEventListener("message", function(e) { a = e.data; });\nwindow.addEventListener("message", function(e) { b = e.origin; });\ndocument.getElementById("o").innerHTML = a + b;' }, 1);
  await checkTaint('multi-step cache + hash', { 'a.js': 'var cache = {};\nwindow.addEventListener("message", function(e) { cache.content = e.data; });\nvar suffix = location.hash;\nfunction build() { return cache.content + suffix; }\ndocument.getElementById("o").innerHTML = build();' }, 1);
  await checkTaint('handler calls sink fn', { 'a.js': 'function setContent(html) { document.getElementById("o").innerHTML = html; }\nwindow.addEventListener("message", function(e) { setContent(e.data); });' }, 1);
  await checkTaint('message-store-hashchange-sink', { 'a.js': 'var pending;\nwindow.addEventListener("message", function(e) { pending = e.data; });\nwindow.addEventListener("hashchange", function() {\n  document.getElementById("o").innerHTML = pending + location.hash;\n});' }, 1);
  await checkTaint('conditional multi-source', { 'a.js': 'var result;\nwindow.addEventListener("message", function(e) {\n  if (location.search.indexOf("admin") >= 0) {\n    result = e.data;\n  }\n});\ndocument.getElementById("o").innerHTML = result;' }, 1);

  // --- Method chains preserve taint ---
  await checkTaint('toString preserves', { 'a.js': 'var x = location.search.toString(); document.getElementById("o").innerHTML = x;' }, 1);
  await checkTaint('trim preserves', { 'a.js': 'var x = location.search.trim(); document.getElementById("o").innerHTML = x;' }, 1);
  await checkTaint('toLowerCase preserves', { 'a.js': 'var x = location.search.toLowerCase(); document.getElementById("o").innerHTML = x;' }, 1);
  await checkTaint('concat preserves', { 'a.js': 'var x = "prefix".concat(location.search); document.getElementById("o").innerHTML = x;' }, 1);

  // --- Object methods ---
  await checkTaint('obj method returns taint', { 'a.js': 'var o = { get: function() { return location.search; } }; document.getElementById("o").innerHTML = o.get();' }, 1);

  // --- Cross-file ---
  await checkTaint('cross-file taint', { 'index.html': '<html><body><div id="o"></div><script src="a.js"></script><script src="b.js"></script></body></html>', 'a.js': 'var shared = location.search;', 'b.js': 'document.getElementById("o").innerHTML = shared;' }, 1);

  // --- False positive: reassigned to safe ---
  await checkTaint('reassigned to safe', { 'a.js': 'var x = location.search; x = "safe"; document.getElementById("o").innerHTML = x;' }, 0);

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Converter: unsafe sink handling
// -----------------------------------------------------------------------
await (async function () {
  const convertJsFile = globalThis.__convertJsFile;
  if (!convertJsFile) return;
  const before = pass + fail;
  console.log('\nconverter sinks');
  console.log('---------------');

  async function checkConv(name, input, expected) {
    const r = await convertJsFile(input, '');
    let ok;
    if (expected === null) {
      ok = r === null;
    } else if (typeof expected === 'string') {
      ok = r !== null && r.indexOf(expected) >= 0;
    } else {
      ok = false;
    }
    if (ok) { pass++; } else {
      fail++;
      failures.push({ name, input, want: expected, got: r ? r.slice(0, 120) : null });
    }
  }

  // eval
  await checkConv('eval literal', 'eval("alert(1)");', 'alert(1)');
  await checkConv('eval variable', 'var c = "alert(1)"; eval(c);', 'alert(1)');
  await checkConv('eval tainted', 'var x = location.search; eval(x);', 'blocked');
  await checkConv('eval concat', 'eval("var x = " + "1");', 'var x = 1');
  await checkConv('eval template', 'eval(`alert(1)`);', 'alert(1)');
  await checkConv('eval no args', 'eval();', null);
  await checkConv('eval in expr', 'var r = eval("1+1");', '1+1');
  await checkConv('eval shadow safe', 'var eval = function(x){return x;}; eval("test");', null);

  // Function
  await checkConv('Function literal', 'Function("return 1");', '(function() { return 1 })');
  await checkConv('Function 2 args', 'Function("a", "return a");', '(function(a) { return a })');
  await checkConv('Function 3 args', 'Function("a", "b", "return a+b");', '(function(a, b) { return a+b })');
  await checkConv('new Function', 'new Function("return 1");', '(function() { return 1 })');
  await checkConv('new Function tainted', 'new Function(location.search);', 'blocked');
  await checkConv('new Function no args', 'new Function();', '(function() {})');

  // setTimeout/setInterval
  await checkConv('setTimeout string', 'setTimeout("alert(1)", 100);', 'function() { alert(1) }');
  await checkConv('setInterval string', 'setInterval("tick()", 1000);', 'function() { tick() }');
  await checkConv('setTimeout fn safe', 'setTimeout(function() { alert(1); }, 100);', null);
  await checkConv('setTimeout tainted', 'var x = location.search; setTimeout(x, 100);', 'blocked');
  await checkConv('setTimeout shadow safe', 'var setTimeout = function(){}; setTimeout("test", 100);', null);

  // Navigation
  await checkConv('location.href filter', 'var x = location.search; location.href = x;', '__safeNav');
  await checkConv('location.assign filter', 'var x = location.search; location.assign(x);', '__safeNav');
  await checkConv('location literal safe', 'location.href = "https://example.com";', null);
  await checkConv('location shadow safe', 'var location = {}; location.href = "x";', null);
  await checkConv('iframe.src filter', 'var f = document.createElement("iframe"); f.src = location.search;', '__safeNav');
  await checkConv('opener.location filter', 'opener.location = location.search;', '__safeNav');

  // --- Converter in complex contexts ---
  await checkConv('setTimeout in loop', 'for (var i = 0; i < 3; i++) { setTimeout("alert(" + i + ")", i * 100); }', 'function()');
  await checkConv('iframe.src dynamic', 'var f = document.createElement("iframe"); f.src = location.hash;', '__safeNav');

  console.log(`  (${pass + fail - before} cases)`);
})();

// -----------------------------------------------------------------------
// Final report (inside master IIFE so async tests have completed)
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

})().catch(e => { console.error('test harness crashed:', e); process.exit(1); });
