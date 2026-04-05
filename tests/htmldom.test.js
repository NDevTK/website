// Advanced tests for htmldom.js's extractHTML resolver.
//
// Run with: node tests/htmldom.test.js
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
// splicing an export line into the source before eval.
const src = fs.readFileSync(path.join(__dirname, '..', 'htmldom.js'), 'utf8');
const patched = src.replace(
  'function extractHTML(input) {',
  'globalThis.__extractHTML = extractHTML;\n  function extractHTML(input) {'
);
// eslint-disable-next-line no-eval
eval(patched);
const extractHTML = globalThis.__extractHTML;

// Test harness.
let pass = 0;
let fail = 0;
const failures = [];

function check(name, input, expected) {
  const out = extractHTML(input);
  const got = {
    html: out.html,
    target: out.target || null,
    assignProp: out.assignProp || null,
    assignOp: out.assignOp || null,
    autoSubs: out.autoSubs || [],
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
  check('unknown identifier', `document.body.innerHTML=y;`, '');
});

// -----------------------------------------------------------------------
// Scoping: block vs function
// -----------------------------------------------------------------------
group('scoping', () => {
  check('let in block doesn\'t leak',
    `{ let x='<a>'; } document.body.innerHTML=x;`, '');
  check('const in block doesn\'t leak',
    `{ const x='<a>'; } document.body.innerHTML=x;`, '');
  check('var leaks out of block (function-scoped)',
    `{ var x='<a>'; } document.body.innerHTML=x;`, '<a>');
  check('let shadowing',
    `let x='<a>'; { let x='<b>'; } document.body.innerHTML=x;`, '<a>');
  check('let shadowing (inner site)',
    `let x='<a>'; { let x='<b>'; document.body.innerHTML=x; }`, '<b>');
  check('var in function does not leak',
    `function f(){ var x='<a>'; } document.body.innerHTML=x;`, '');
  check('let in function does not leak',
    `function f(){ let x='<a>'; } document.body.innerHTML=x;`, '');
  check('outer var visible past function',
    `var x='<a>'; function f(){} document.body.innerHTML=x;`, '<a>');
  check('arrow expression body (no scope opened)',
    `var f = x => x+1; var y='<a>'; document.body.innerHTML=y;`, '<a>');
  check('arrow block body (scope opened)',
    `var f = () => { var x='<bad>'; }; var y='<a>'; document.body.innerHTML=y;`, '<a>');
  check('nested blocks',
    `{ { let x='<a>'; } } document.body.innerHTML=x;`, '');
  check('nested function scopes',
    `function a(){ function b(){ var x='<a>'; } } document.body.innerHTML=x;`, '');
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
  check('unknown ident breaks chain',
    `var x='<a>'+unknownVar; document.body.innerHTML=x;`, '');
  check('non-literal breaks chain (call)',
    `var x='<a>'+foo(); document.body.innerHTML=x;`, '');
  check('unresolved ident becomes a placeholder expression',
    `var x = 'a' + foo(); document.body.innerHTML = '<a>'+x+'</a>';`,
    { html: '<a>__HDX0__</a>', autoSubs: [['__HDX0__', 'x']] });
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
  check('non-HTML concat returns empty',
    `var x = 'a' + 'b'; document.body.innerHTML=x;`, '');
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
    `var obj = { html: '<a>' }; document.body.innerHTML = obj.missing;`, '');
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
  check('out-of-bounds returns empty',
    `var arr=['<a>']; document.body.innerHTML=arr[5];`, '');
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
    `var obj={html:'<a>'}; document.body.innerHTML=obj['missing'];`, '');
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
    `{ let o = {html:'<a>'}; } document.body.innerHTML = o.html;`, '');
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
  check('function with unknown arg (unsupported, returns empty)',
    `const f = x => '<a>' + x + '</a>';
     document.body.innerHTML = f(unknown);`, '');
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
  check('function called with missing arg (unsupported)',
    `function f(x) { return '<a>'+x+'</a>'; } document.body.innerHTML = f();`, '');
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
