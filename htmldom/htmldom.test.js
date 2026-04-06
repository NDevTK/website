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

function check(name, input, expected) {
  const out = extractHTML(input);
  const got = {
    html: out.html,
    target: out.target || null,
    assignProp: out.assignProp || null,
    assignOp: out.assignOp || null,
    autoSubs: out.autoSubs || [],
    loops: out.loops || undefined,
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
    `var obj = { html: '<a>' }; document.body.innerHTML = obj.missing;`, 'undefined');
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
// typeof folding
// -----------------------------------------------------------------------
group('typeof folding', () => {
  check('typeof string',
    `var a = 'hi'; document.body.innerHTML = typeof a;`, 'string');
  check('typeof number',
    `var a = 5; document.body.innerHTML = typeof a;`, 'number');
  check('typeof boolean',
    `var a = true; document.body.innerHTML = typeof a;`, 'boolean');
  check('typeof array/object/function',
    `var a = [1]; var o = {x:1}; var f = () => 1; document.body.innerHTML = typeof a + '-' + typeof o + '-' + typeof f;`,
    'object-object-function');
  check('typeof + equality',
    `var a = 5; document.body.innerHTML = (typeof a === 'number') ? 'Y' : 'N';`, 'Y');
  check('void is undefined',
    `document.body.innerHTML = 'v:' + (void 0);`, 'v:undefined');
  check('typeof null',
    `document.body.innerHTML = typeof null;`, 'object');
  check('typeof undefined',
    `document.body.innerHTML = typeof undefined;`, 'undefined');
  check('typeof computed boolean',
    `var x = 3 > 2; document.body.innerHTML = typeof x;`, 'boolean');
  check('typeof void',
    `document.body.innerHTML = typeof (void 0);`, 'undefined');
});

// -----------------------------------------------------------------------
// Boolean / null / undefined type tracking
// -----------------------------------------------------------------------
group('primitive type tracking', () => {
  check('true + 1 = 2 (boolean coerces to number)',
    `document.body.innerHTML = true + 1;`, '2');
  check('false + 1 = 1',
    `document.body.innerHTML = false + 1;`, '1');
  check('comparison result in arithmetic',
    `document.body.innerHTML = (3>2) + 1;`, '2');
  check('ternary with boolean condition',
    `document.body.innerHTML = (3>2) ? 'yes' : 'no';`, 'yes');
  check('ternary with false condition',
    `document.body.innerHTML = (1>2) ? 'yes' : 'no';`, 'no');
  check('null ?? default',
    `var x = null; document.body.innerHTML = x ?? 'default';`, 'default');
  check('undefined ?? default',
    `var x = undefined; document.body.innerHTML = x ?? 'default';`, 'default');
  check('value ?? default',
    `var x = 'value'; document.body.innerHTML = x ?? 'default';`, 'value');
});

// -----------------------------------------------------------------------
// String equality folding
// -----------------------------------------------------------------------
group('string comparison', () => {
  check('=== on strings',
    `document.body.innerHTML = ('abc' === 'abc' ? 'A' : 'B');`, 'A');
  check('!== on strings',
    `document.body.innerHTML = ('a' !== 'b' ? 'A' : 'B');`, 'A');
  check('< on strings',
    `document.body.innerHTML = ('a' < 'b' ? 'lt' : 'ge');`, 'lt');
});

// -----------------------------------------------------------------------
// Mutation tracking on bindings
// -----------------------------------------------------------------------
group('mutations', () => {
  check('arr.push appends',
    `var a = ['x']; a.push('y','z'); document.body.innerHTML = a.join(',');`, 'x,y,z');
  check('arr.pop removes last',
    `var a = ['x','y','z']; a.pop(); document.body.innerHTML = a.join(',');`, 'x,y');
  check('arr.shift removes first',
    `var a = ['x','y','z']; a.shift(); document.body.innerHTML = a.join(',');`, 'y,z');
  check('arr.unshift prepends',
    `var a = ['b','c']; a.unshift('a'); document.body.innerHTML = a.join(',');`, 'a,b,c');
  check('indexed write arr[i]=v',
    `var a = [1,2,3]; a[0] = 9; document.body.innerHTML = a.join(',');`, '9,2,3');
  check('member write obj.x=v',
    `var o = {a:1}; o.b = 2; document.body.innerHTML = o.a + ',' + o.b;`, '1,2');
  check('keyed write obj[k]=v',
    `var o = {a:1}; o['c'] = 3; document.body.innerHTML = o.c;`, '3');
  check('nested member write',
    `var o = {n:{x:1}}; o.n.x = 5; document.body.innerHTML = o.n.x;`, '5');
});

// -----------------------------------------------------------------------
// for-of / for-in static unrolling
// -----------------------------------------------------------------------
group('for-of unrolling', () => {
  check('accumulator over static array',
    `var a=''; for (var x of ['a','b','c']) { a += '<li>'+x+'</li>'; } document.body.innerHTML=a;`,
    '<li>a</li><li>b</li><li>c</li>');
  check('accumulator with prefix',
    `var a='X:'; for (var x of ['a','b','c']) { a += '<li>'+x+'</li>'; } document.body.innerHTML=a;`,
    'X:<li>a</li><li>b</li><li>c</li>');
  check('for-in over static object iterates keys',
    `var o={a:1,b:2,c:3}; var s=''; for (var k in o) { s += k; } document.body.innerHTML=s;`, 'abc');
  check('empty iterable leaves baseline',
    `var a='pre:'; for (var x of []) { a += x; } document.body.innerHTML=a;`, 'pre:');
  check('single-statement body',
    `var a=''; for (var x of ['a','b']) a += x; document.body.innerHTML=a;`, 'ab');
  check('loop var used twice',
    `var a=''; for (var x of ['a','b']) a += x+':'+x+','; document.body.innerHTML=a;`, 'a:a,b:b,');
  check('nested for-of unrolls both',
    `var a=''; for (var x of ['a','b']) for (var y of ['1','2']) a += x+y+'/'; document.body.innerHTML=a;`,
    'a1/a2/b1/b2/');
  check('for-of over precomputed array',
    `var items=['one','two']; var a=''; for (var x of items) a += '['+x+']'; document.body.innerHTML=a;`,
    '[one][two]');
  check('method call on loop var (toUpperCase)',
    `var a=''; for (var x of ['a','b']) a += x.toUpperCase(); document.body.innerHTML = a;`, 'AB');
  check('arithmetic on loop var',
    `var a=''; for (var x of [1,2,3]) a += (x*10)+','; document.body.innerHTML = a;`, '10,20,30,');
  check('arr.push inside for-of',
    `var out=[]; for (var x of ['a','b','c']) out.push('<li>'+x+'</li>'); document.body.innerHTML = out.join('');`,
    '<li>a</li><li>b</li><li>c</li>');
  check('template literal in for-of body',
    "var a=''; for (var x of ['a','b']) a += `<li>${x}</li>`; document.body.innerHTML=a;",
    '<li>a</li><li>b</li>');
});

// -----------------------------------------------------------------------
// Bounded for/while loop simulation
// -----------------------------------------------------------------------
group('bounded loop simulation', () => {
  check('for i<5 i++',
    `var s=''; for(var i=0; i<5; i++) s += i; document.body.innerHTML = s;`, '01234');
  check('for with array indexing',
    `var a=['a','b','c']; var s=''; for(var i=0; i<a.length; i++) s += a[i]; document.body.innerHTML = s;`, 'abc');
  check('for decrement',
    `var s=''; for(var i=3; i>0; i--) s += i; document.body.innerHTML = s;`, '321');
  check('for step +=2',
    `var s=''; for(var i=0; i<10; i+=2) s += i+','; document.body.innerHTML = s;`, '0,2,4,6,8,');
  check('while with counter',
    `var s=''; var i=0; while(i<3) { s+=i; i++; } document.body.innerHTML = s;`, '012');
  check('nested for loops',
    `var s=''; for(var i=0;i<2;i++) for(var j=0;j<3;j++) s+=i+''+j+' '; document.body.innerHTML=s;`, '00 01 02 10 11 12 ');
  check('for building HTML from array',
    `var items=['a','b','c']; var html=''; for(var i=0;i<items.length;i++) html+='<li>'+items[i]+'</li>'; document.body.innerHTML=html;`,
    '<li>a</li><li>b</li><li>c</li>');
  check('while building from array',
    `var parts=['head','body','foot']; var i=0; var h=''; while(i<parts.length) { h+='<'+parts[i]+'>'; i++; } document.body.innerHTML=h;`,
    '<head><body><foot>');
  check('for zero iterations',
    `var s='init'; for(var i=0; i<0; i++) s='never'; document.body.innerHTML = s;`, 'init');
  check('for with opaque bound falls to markers',
    `var s=''; for(var i=0;i<n;i++) s+='x'; document.body.innerHTML=s;`,
    { html: '__HDLOOP0S__x__HDLOOP0E__' });
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
// String methods: replace/replaceAll/at
// -----------------------------------------------------------------------
group('string methods extended', () => {
  check('replace literal',
    `document.body.innerHTML = 'hello world'.replace('world', 'js');`, 'hello js');
  check('replaceAll literal',
    `document.body.innerHTML = 'aXbXc'.replaceAll('X', '-');`, 'a-b-c');
  check('at negative index',
    `document.body.innerHTML = 'abc'.at(-1);`, 'c');
  check('charCodeAt',
    `document.body.innerHTML = 'A'.charCodeAt(0);`, '65');
});

// -----------------------------------------------------------------------
// Array methods extended
// -----------------------------------------------------------------------
group('array methods extended', () => {
  check('find with predicate',
    `var a=[1,2,3]; document.body.innerHTML = a.find(x => x > 1);`, '2');
  check('findIndex with predicate',
    `var a=[1,2,3]; document.body.innerHTML = a.findIndex(x => x > 1);`, '1');
  check('some true',
    `var a=[1,2,3]; document.body.innerHTML = a.some(x => x > 2);`, 'true');
  check('some false',
    `var a=[1,2,3]; document.body.innerHTML = a.some(x => x > 5);`, 'false');
  check('every true',
    `var a=[1,2,3]; document.body.innerHTML = a.every(x => x > 0);`, 'true');
  check('every false',
    `var a=[1,2,3]; document.body.innerHTML = a.every(x => x > 1);`, 'false');
  check('concat arrays',
    `var a=[1,2]; var b=[3,4]; document.body.innerHTML = a.concat(b).join(',');`, '1,2,3,4');
  check('concat inline arrays',
    `document.body.innerHTML = [1,2].concat([3],[4,5]).join(',');`, '1,2,3,4,5');
  check('flat nested',
    `var a=[[1,2],[3,4]]; document.body.innerHTML = a.flat().join(',');`, '1,2,3,4');
  check('fill range',
    `var a=[1,2,3]; document.body.innerHTML = a.fill(0,1,2).join(',');`, '1,0,3');
  check('splice at statement level',
    `var a=[1,2,3]; a.splice(1,1,'x'); document.body.innerHTML = a.join(',');`, '1,x,3');
  check('at negative',
    `var a=['a','b','c']; document.body.innerHTML = a.at(-1);`, 'c');
  check('flatMap',
    `var a=[1,2,3]; document.body.innerHTML = a.flatMap(x => [x, x*2]).join(',');`, '1,2,2,4,3,6');
  check('sort at statement level',
    `var a=['c','a','b']; a.sort(); document.body.innerHTML = a.join(',');`, 'a,b,c');
  check('reverse at statement level',
    `var a=[1,2,3]; a.reverse(); document.body.innerHTML = a.join(',');`, '3,2,1');
});

// -----------------------------------------------------------------------
// Object builtins
// -----------------------------------------------------------------------
group('Object builtins', () => {
  check('Object.assign via expression',
    `var a={x:1}; var c = Object.assign(a,{y:2}); document.body.innerHTML = c.x + ',' + c.y;`, '1,2');
  check('Object.fromEntries',
    `var o = Object.fromEntries([['a','1'],['b','2']]); document.body.innerHTML = o.a + o.b;`, '12');
});

// -----------------------------------------------------------------------
// switch / try-catch
// -----------------------------------------------------------------------
group('control flow', () => {
  check('switch concrete match',
    `var x = 'b'; var r = ''; switch(x) { case 'a': r = 'A'; break; case 'b': r = 'B'; break; } document.body.innerHTML = r;`, 'B');
  check('switch default',
    `var x = 'z'; var r = ''; switch(x) { case 'a': r = 'A'; break; default: r = 'D'; } document.body.innerHTML = r;`, 'D');
  check('try-catch walks try body',
    `var a = 'init'; try { a = 'tried'; } catch(e) {} document.body.innerHTML = a;`, 'tried');
  check('if true takes if-branch',
    `var r=''; if(true){r='yes';}else{r='no';} document.body.innerHTML=r;`, 'yes');
  check('if false takes else-branch',
    `var r=''; if(false){r='yes';}else{r='no';} document.body.innerHTML=r;`, 'no');
  check('if concrete equality',
    `var x='a'; var r=''; if(x==='a'){r='A';}else{r='B';} document.body.innerHTML=r;`, 'A');
  check('if null is falsy',
    `var r=''; if(null){r='yes';}else{r='no';} document.body.innerHTML=r;`, 'no');
  check('if 0 is falsy',
    `var r=''; if(0){r='yes';}else{r='no';} document.body.innerHTML=r;`, 'no');
  check('if object is truthy',
    `var o={x:1}; var r=''; if(o){r='yes';} document.body.innerHTML=r;`, 'yes');
  check('if false without else skips body',
    `var r='init'; if(false){r='changed';} document.body.innerHTML=r;`, 'init');
  check('else-if chain',
    `var x=2; var r=''; if(x===1){r='one';}else if(x===2){r='two';}else{r='other';} document.body.innerHTML=r;`, 'two');
  check('single-statement if body',
    `var r='init'; if(true) r='yes'; document.body.innerHTML=r;`, 'yes');
  check('do-while loop body is walked',
    `var a='init'; do { a = 'done'; } while(false); document.body.innerHTML=a;`, 'done');
});

// -----------------------------------------------------------------------
// Number methods
// -----------------------------------------------------------------------
group('number methods', () => {
  check('toFixed',
    `document.body.innerHTML = (3.14159).toFixed(2);`, '3.14');
  check('toString with radix',
    `document.body.innerHTML = (255).toString(16);`, 'ff');
  check('toPrecision',
    `document.body.innerHTML = (123.456).toPrecision(5);`, '123.46');
});

// -----------------------------------------------------------------------
// Infinity / NaN literals
// -----------------------------------------------------------------------
group('Infinity and NaN', () => {
  check('typeof Infinity',
    `document.body.innerHTML = typeof Infinity;`, 'number');
  check('typeof NaN',
    `document.body.innerHTML = typeof NaN;`, 'number');
  check('isFinite(Infinity)',
    `document.body.innerHTML = isFinite(Infinity);`, 'false');
  check('isNaN(NaN)',
    `document.body.innerHTML = isNaN(NaN);`, 'true');
  check('Infinity comparison',
    `document.body.innerHTML = (Infinity > 999) ? 'yes' : 'no';`, 'yes');
});

// -----------------------------------------------------------------------
// Number vs string + operator
// -----------------------------------------------------------------------
group('number/string distinction', () => {
  check('number + number = numeric add',
    `document.body.innerHTML = 1 + 2;`, '3');
  check('string + string = concat',
    `var x = '1'; var y = '2'; document.body.innerHTML = x + y;`, '12');
  check('string + number = concat',
    `document.body.innerHTML = 'a' + 1;`, 'a1');
});

// -----------------------------------------------------------------------
// Shadowed builtins respected
// -----------------------------------------------------------------------
group('builtin shadowing', () => {
  check('unshadowed Math.floor works',
    `document.body.innerHTML = Math.floor(3.7);`, '3');
  check('shadowed Math uses user object',
    `var Math = {floor:99}; document.body.innerHTML = Math.floor;`, '99');
  check('shadowed parseInt uses user function',
    `function parseInt(x){return x+'!';} document.body.innerHTML = parseInt('5');`, '5!');
  check('unshadowed parseInt folds string arg',
    `document.body.innerHTML = parseInt('42');`, '42');
  check('unshadowed parseFloat folds string arg',
    `document.body.innerHTML = parseFloat('3.14');`, '3.14');
  check('unshadowed Number coerces string',
    `document.body.innerHTML = Number('99');`, '99');
  check('unshadowed Boolean coerces number',
    `document.body.innerHTML = Boolean(1);`, 'true');
  check('shadowed Object.keys uses user function',
    `var Object = {keys:()=>'fake'}; document.body.innerHTML = Object.keys();`, 'fake');
  check('user method on object via property lookup',
    `var obj = {greet:()=>'hello'}; document.body.innerHTML = obj.greet();`, 'hello');
  check('.length on plain object uses property',
    `var obj = {length:'custom'}; document.body.innerHTML = obj.length;`, 'custom');
  check('.length on array gives count',
    `var a=[1,2,3]; document.body.innerHTML = a.length;`, '3');
  check('String.fromCharCode folds',
    `document.body.innerHTML = String.fromCharCode(65,66,67);`, 'ABC');
});

// -----------------------------------------------------------------------
// Compound assignment operators
// -----------------------------------------------------------------------
group('compound assignments', () => {
  check('-= subtracts',
    `var a=10; a -= 3; document.body.innerHTML = a;`, '7');
  check('*= multiplies',
    `var a=5; a *= 4; document.body.innerHTML = a;`, '20');
  check('/= divides',
    `var a=20; a /= 4; document.body.innerHTML = a;`, '5');
  check('||= assigns on falsy',
    `var a=''; a ||= 'default'; document.body.innerHTML = a;`, 'default');
  check('||= no-op on truthy',
    `var a='existing'; a ||= 'default'; document.body.innerHTML = a;`, 'existing');
  check('&&= assigns on truthy',
    `var a='old'; a &&= 'new'; document.body.innerHTML = a;`, 'new');
  check('??= assigns on null',
    `var a=null; a ??= 'fallback'; document.body.innerHTML = a;`, 'fallback');
  check('??= assigns on undefined',
    `var a=undefined; a ??= 'fb'; document.body.innerHTML = a;`, 'fb');
  check('??= no-op on value',
    `var a='val'; a ??= 'fb'; document.body.innerHTML = a;`, 'val');
});

// -----------------------------------------------------------------------
// Destructuring in for-of
// -----------------------------------------------------------------------
group('for-of destructuring', () => {
  check('array destructuring in for-of',
    `var r=''; for(var [k,v] of [['a',1],['b',2]]) r+=k+v; document.body.innerHTML=r;`, 'a1b2');
  check('object destructuring in for-of',
    `var r=''; for(var {name,age} of [{name:'A',age:1},{name:'B',age:2}]) r+=name+age; document.body.innerHTML=r;`, 'A1B2');
});

// -----------------------------------------------------------------------
// Function return typed bindings (array/object)
// -----------------------------------------------------------------------
group('typed function returns', () => {
  check('destructure array from function',
    `function f(){return ['a','b'];} var [x,y]=f(); document.body.innerHTML=x+y;`, 'ab');
  check('destructure object from function',
    `function f(){return {a:'x',b:'y'};} var {a,b}=f(); document.body.innerHTML=a+b;`, 'xy');
  check('member access on function return',
    `function f(){return {html:'<p>hi</p>'};} document.body.innerHTML=f().html;`, '<p>hi</p>');
  check('index access on function return',
    `function f(){return ['a','b'];} document.body.innerHTML=f()[0];`, 'a');
  check('method on function return',
    `function wrap(x){return [x];} document.body.innerHTML=wrap('hi').join(',');`, 'hi');
});

// -----------------------------------------------------------------------
// Spread in function calls
// -----------------------------------------------------------------------
group('spread args', () => {
  check('spread array into function',
    `function f(a,b,c){return a+b+c;} var args=['x','y','z']; document.body.innerHTML = f(...args);`, 'xyz');
  check('mixed spread with regular args',
    `function f(a,b,c,d){return a+b+c+d;} var r=['b','c']; document.body.innerHTML = f('a',...r,'d');`, 'abcd');
});

// -----------------------------------------------------------------------
// Array.from on strings
// -----------------------------------------------------------------------
group('Array.from string', () => {
  check('Array.from iterates characters',
    `document.body.innerHTML = Array.from('abc').join(',');`, 'a,b,c');
  check('Array.from string with mapFn',
    `document.body.innerHTML = Array.from('abc', c => c.toUpperCase()).join('');`, 'ABC');
});

// -----------------------------------------------------------------------
// Comma operator
// -----------------------------------------------------------------------
group('comma operator', () => {
  check('returns last expression',
    `document.body.innerHTML = (1, 2, 'three');`, 'three');
  check('single expression in parens unchanged',
    `document.body.innerHTML = ('hello');`, 'hello');
});

// -----------------------------------------------------------------------
// Regex-based string methods
// -----------------------------------------------------------------------
group('regex methods', () => {
  check('replace with regex',
    `var s='hello world'; document.body.innerHTML = s.replace(/o/g,'0');`, 'hell0 w0rld');
  check('match with regex returns array',
    `document.body.innerHTML = 'a1b2c3'.match(/[0-9]+/g).join(',');`, '1,2,3');
  check('search with regex returns index',
    `document.body.innerHTML = 'hello'.search(/ll/);`, '2');
  check('regex.test on string true',
    `document.body.innerHTML = /^[a-z]+$/.test('hello');`, 'true');
  check('regex.test on string false',
    `document.body.innerHTML = /^[0-9]+$/.test('hello');`, 'false');
  check('split with regex',
    `document.body.innerHTML = 'a-b-c'.split(/-/).join(',');`, 'a,b,c');
  check('match returns null for no match',
    `document.body.innerHTML = 'abc'.match(/xyz/);`, 'null');
});

// -----------------------------------------------------------------------
// Edge-case hardening
// -----------------------------------------------------------------------
group('edge cases', () => {
  check('bitwise |= compound assignment',
    `var a=5; a |= 3; document.body.innerHTML = a;`, '7');
  check('bitwise &= compound assignment',
    `var a=7; a &= 5; document.body.innerHTML = a;`, '5');
  check('bitwise ^= compound assignment',
    `var a=7; a ^= 3; document.body.innerHTML = a;`, '4');
  check('<<= shift assignment',
    `var a=1; a <<= 3; document.body.innerHTML = a;`, '8');
  check('with statement skipped',
    `var r='ok'; with(obj) { r='bad'; } document.body.innerHTML = r;`, 'ok');
  check('debugger skipped',
    `debugger; var a='ok'; document.body.innerHTML = a;`, 'ok');
});

// -----------------------------------------------------------------------
// Class support
// -----------------------------------------------------------------------
group('classes', () => {
  check('class constructor sets properties',
    `class Foo { constructor(x) { this.x = x; } } var f = new Foo('hi'); document.body.innerHTML = f.x;`, 'hi');
  check('class method with this',
    `class Foo { constructor(x) { this.x = x; } greet() { return 'hello ' + this.x; } } var f = new Foo('world'); document.body.innerHTML = f.greet();`,
    'hello world');
  check('class method numeric',
    `class P { constructor(a,b) { this.a=a; this.b=b; } sum() { return this.a + this.b; } } var p = new P(3,4); document.body.innerHTML = p.sum();`, '7');
  check('class method returns HTML',
    `class Item { constructor(name) { this.name=name; } render() { return '<li>'+this.name+'</li>'; } } var it = new Item('test'); document.body.innerHTML = it.render();`,
    '<li>test</li>');
  check('new inline property access',
    `class C { constructor() { this.val='ok'; } } document.body.innerHTML = new C().val;`, 'ok');
  check('class with multiple methods',
    `class C { constructor(n) { this.n=n; } double() { return this.n*2; } label() { return 'n='+this.double(); } } document.body.innerHTML = new C(5).label();`, 'n=10');
  check('super() in subclass constructor',
    `class A{constructor(){this.x='a';}} class B extends A{constructor(){super();this.y='b';}} var b=new B(); document.body.innerHTML=b.x+b.y;`, 'ab');
  check('super.method() call',
    `class A{val(){return 'a';}} class B extends A{val(){return super.val()+'b';}} document.body.innerHTML=new B().val();`, 'ab');
  check('class expression',
    `var C=class{constructor(x){this.x=x;}}; document.body.innerHTML=new C('hi').x;`, 'hi');
  check('named class expression',
    `var C=class Foo{constructor(x){this.x=x;}}; document.body.innerHTML=new C('v').x;`, 'v');
  check('inherited method',
    `class A{greet(){return 'hi';}} class B extends A{} document.body.innerHTML=new B().greet();`, 'hi');
});

// -----------------------------------------------------------------------
// Getters
// -----------------------------------------------------------------------
group('getters', () => {
  check('simple getter',
    `var o={get x(){return 'val';}}; document.body.innerHTML=o.x;`, 'val');
  check('getter with this',
    `var o={a:3,b:4,get sum(){return this.a+this.b;}}; document.body.innerHTML=o.sum;`, '7');
});

// -----------------------------------------------------------------------
// Real-world patterns (from GitHub search)
// -----------------------------------------------------------------------
group('real-world patterns', () => {
  check('SparrowCI autocomplete: substr in if inside for',
    `var arr=['alpha','beta','gamma']; var val='al'; var html='';
     for(var i=0;i<arr.length;i++){
       if(arr[i].substr(0,val.length).toUpperCase()==val.toUpperCase()){
         html+='<strong>'+arr[i].substr(0,val.length)+'</strong>';
         html+=arr[i].substr(val.length);
       }
     } document.body.innerHTML=html;`,
    "<strong>al</strong>pha");
  check('wikidata-osm: concat link from variables',
    `var type='way'; var id=12345; var link='<li><a href="https://osm.org/'+type+'/'+id+'">OSM</a></li>'; document.body.innerHTML=link;`,
    '<li><a href="https://osm.org/way/12345">OSM</a></li>');
  check('nn.js: iteration status in for loop',
    `var iterations=3; var html=''; for(var iter=0;iter<iterations;iter++) html+='Iter '+(iter+1)+' of '+iterations+'<br>'; document.body.innerHTML=html;`,
    'Iter 1 of 3<br>Iter 2 of 3<br>Iter 3 of 3<br>');
  check('table builder from object array',
    `var data=[{name:'Alice',age:30},{name:'Bob',age:25}]; var html='<table>';
     for(var i=0;i<data.length;i++) html+='<tr><td>'+data[i].name+'</td><td>'+data[i].age+'</td></tr>';
     html+='</table>'; document.body.innerHTML=html;`,
    '<table><tr><td>Alice</td><td>30</td></tr><tr><td>Bob</td><td>25</td></tr></table>');
  check('map with function keyword',
    `var items=['Home','About']; document.body.innerHTML='<ul>'+items.map(function(item){return '<li>'+item+'</li>';}).join('')+'</ul>';`,
    '<ul><li>Home</li><li>About</li></ul>');
  check('forEach with function keyword (side effects)',
    `var colors=['red','green','blue']; var html=''; colors.forEach(function(color,i){html+='<div>'+(i+1)+'. '+color+'</div>';}); document.body.innerHTML=html;`,
    '<div>1. red</div><div>2. green</div><div>3. blue</div>');
  check('forEach with arrow (side effects)',
    `var a=['x','y','z']; var h=''; a.forEach(c=>{h+=c;}); document.body.innerHTML=h;`, 'xyz');
  check('conditional HTML building with if',
    `var isAdmin=true; var name='Alice'; var html='<div>'; html+='<span>'+name+'</span>';
     if(isAdmin) html+='<span class="badge">Admin</span>';
     html+='</div>'; document.body.innerHTML=html;`,
    '<div><span>Alice</span><span class="badge">Admin</span></div>');
});

// -----------------------------------------------------------------------
// General JS patterns
// -----------------------------------------------------------------------
group('general JS', () => {
  check('hex literal',
    `document.body.innerHTML = 0xFF;`, '255');
  check('binary literal',
    `document.body.innerHTML = 0b1010;`, '10');
  check('octal literal',
    `document.body.innerHTML = 0o77;`, '63');
  check('IIFE',
    `var r = (function(){ return 'iife'; })(); document.body.innerHTML = r;`, 'iife');
  check('arrow IIFE',
    `var r = (() => 'val')(); document.body.innerHTML = r;`, 'val');
  check('closure',
    `function make(x){ return function(){ return x; }; } var f = make('hi'); document.body.innerHTML = f();`, 'hi');
  check('nested function with closure',
    `function outer(){ var x = 'o'; function inner(){ return x; } return inner(); } document.body.innerHTML = outer();`, 'o');
  check('curried arrow',
    `var add = x => y => x + y; document.body.innerHTML = add('a')('b');`, 'ab');
  check('rest parameters',
    `function f(...args){ return args.join(','); } document.body.innerHTML = f('a','b','c');`, 'a,b,c');
  check('rest with leading params',
    `function f(a, b, ...rest){ return rest.join(','); } document.body.innerHTML = f(1,2,3,4,5);`, '3,4,5');
  check('nested destructuring',
    `var {a:{b}} = {a:{b:'deep'}}; document.body.innerHTML = b;`, 'deep');
  check('deeply nested destructuring',
    `var {a:{b:{c}}} = {a:{b:{c:'v'}}}; document.body.innerHTML = c;`, 'v');
  check('object method shorthand callable',
    `var o = { greet(){ return 'hi'; } }; document.body.innerHTML = o.greet();`, 'hi');
  check('missing property is undefined',
    `var o = {}; document.body.innerHTML = o.x ?? 'fb';`, 'fb');
  check('double negation',
    `document.body.innerHTML = !!1 ? 't' : 'f';`, 't');
  check('string method chaining',
    `document.body.innerHTML = '  Hello World  '.trim().toLowerCase().replace(' ','-');`, 'hello-world');
  check('default parameter',
    `function f(x='def'){ return x; } document.body.innerHTML = f();`, 'def');
  check('logical OR default',
    `var x = null; var y = x || 'default'; document.body.innerHTML = y;`, 'default');
  check('delete removes property',
    `var o={a:1,b:2}; delete o.a; document.body.innerHTML=JSON.stringify(o);`, '{"b":2}');
  check('destructuring assignment swap',
    `var a=1,b=2; [a,b]=[b,a]; document.body.innerHTML=a+','+b;`, '2,1');
  check('break exits loop',
    `var s=''; for(var i=0;i<10;i++){if(i===3)break; s+=i;} document.body.innerHTML=s;`, '012');
  check('continue skips iteration',
    `var s=''; for(var i=0;i<5;i++){if(i===2)continue; s+=i;} document.body.innerHTML=s;`, '0134');
  check('labeled continue outer',
    `var r=''; outer: for(var i=0;i<3;i++){for(var j=0;j<3;j++){if(j===1)continue outer; r+=j;}} document.body.innerHTML=r;`, '000');
  check('setter invoked on assignment',
    `var o={_v:0,set v(x){this._v=x;}}; o.v=5; document.body.innerHTML=o._v;`, '5');
  check('numeric separator',
    `document.body.innerHTML = 1_000_000;`, '1000000');
  check('hex with separator',
    `document.body.innerHTML = 0xFF_FF;`, '65535');
  check('chained assignment',
    `var a,b; a=b='val'; document.body.innerHTML=a+b;`, 'valval');
  check('tagged template',
    `function tag(s,...v){return s[0]+v[0]+s[1];} document.body.innerHTML=tag\`a\${'B'}c\`;`, 'aBc');
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
  check('while loop with known bound resolves fully',
    `var s=''; while (s.length < 10) s += 'x'; document.body.innerHTML=s;`,
    'xxxxxxxxxx');
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
  if (all[0] && all[0].target === 'out' && /<a>__HDX0__<\/a>/.test(all[0].html)) pass++;
  else { fail++; failures.push({ name: 'all[0]', got: all[0] }); }
  if (all[1] && all[1].target === 'table' && all[1].html === '<tr><th>Hi</th></tr>') pass++;
  else { fail++; failures.push({ name: 'all[1]', got: all[1] }); }
  if (all[2] && all[2].target === `document.getElementById('nums')` && all[2].assignOp === '+=' && /<br>__HDX0__/.test(all[2].html)) pass++;
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
    `var s='abc'; document.body.innerHTML = s.replace(/b/g,'X');`, 'aXc');
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
