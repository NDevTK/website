// DOM XSS Benchmark Corpus
// ========================
// Each test case is a self-contained JavaScript snippet representing
// a known DOM XSS vulnerability pattern. The corpus covers the OWASP
// DOM-based XSS categories plus real-world patterns from browser
// security research.
//
// Format: { id, category, description, code, expected }
// where expected = { findings: N, sources: [...], sinks: [...] }
//
// Categories follow the OWASP DOM XSS taxonomy:
//   S1 — document.write / document.writeln
//   S2 — innerHTML / outerHTML
//   S3 — eval / Function / setTimeout-string
//   S4 — location.href / location.assign / location.replace
//   S5 — setAttribute on event handlers
//   S6 — CSS injection (style.cssText, etc.)
//   S7 — postMessage handler
//   S8 — Fetch/XHR response to DOM
//   S9 — Storage to DOM
//   S10 — Complex data flow (multi-step, cross-function, async)

module.exports = [
  // ============================================================
  // S1: document.write / document.writeln
  // ============================================================
  {
    id: 'S1-01',
    category: 'S1',
    description: 'document.write with location.hash',
    code: 'document.write(location.hash);',
    expected: { findings: 1, sources: ['url'], sinks: ['html'] },
  },
  {
    id: 'S1-02',
    category: 'S1',
    description: 'document.write with concatenated URL param',
    code: 'document.write("<img src=\'" + location.search + "\'>");',
    expected: { findings: 1, sources: ['url'], sinks: ['html'] },
  },
  {
    id: 'S1-03',
    category: 'S1',
    description: 'document.writeln with template literal',
    code: 'document.writeln(`<div>${location.hash}</div>`);',
    expected: { findings: 1, sources: ['url'], sinks: ['html'] },
  },

  // ============================================================
  // S2: innerHTML / outerHTML
  // ============================================================
  {
    id: 'S2-01',
    category: 'S2',
    description: 'Direct innerHTML from location.hash',
    code: 'document.getElementById("x").innerHTML = location.hash;',
    expected: { findings: 1, sources: ['url'], sinks: ['html'] },
  },
  {
    id: 'S2-02',
    category: 'S2',
    description: 'innerHTML via intermediate variable',
    code: 'var x = location.hash; document.getElementById("o").innerHTML = x;',
    expected: { findings: 1, sources: ['url'], sinks: ['html'] },
  },
  {
    id: 'S2-03',
    category: 'S2',
    description: 'innerHTML via function return',
    code: 'function getData() { return location.hash; } document.getElementById("o").innerHTML = getData();',
    expected: { findings: 1, sources: ['url'], sinks: ['html'] },
  },
  {
    id: 'S2-04',
    category: 'S2',
    description: 'innerHTML safe (textContent)',
    code: 'document.getElementById("o").textContent = location.hash;',
    expected: { findings: 0 },
  },
  {
    id: 'S2-05',
    category: 'S2',
    description: 'innerHTML safe (constant string)',
    code: 'document.getElementById("o").innerHTML = "<b>safe</b>";',
    expected: { findings: 0 },
  },
  {
    id: 'S2-06',
    category: 'S2',
    description: 'innerHTML safe (parseInt sanitizer)',
    code: 'var x = parseInt(location.search); document.getElementById("o").innerHTML = x;',
    expected: { findings: 0 },
  },
  {
    id: 'S2-07',
    category: 'S2',
    description: 'innerHTML via document.cookie',
    code: 'document.getElementById("o").innerHTML = document.cookie;',
    expected: { findings: 1, sources: ['cookie'], sinks: ['html'] },
  },
  {
    id: 'S2-08',
    category: 'S2',
    description: 'innerHTML via document.referrer',
    code: 'document.getElementById("o").innerHTML = document.referrer;',
    expected: { findings: 1, sources: ['referrer'], sinks: ['html'] },
  },
  {
    id: 'S2-09',
    category: 'S2',
    description: 'innerHTML via window.name',
    code: 'document.getElementById("o").innerHTML = window.name;',
    expected: { findings: 1, sources: ['window.name'], sinks: ['html'] },
  },
  {
    id: 'S2-10',
    category: 'S2',
    description: 'outerHTML from URL',
    code: 'document.getElementById("o").outerHTML = location.hash;',
    expected: { findings: 1, sources: ['url'], sinks: ['html'] },
  },

  // ============================================================
  // S3: eval / Function / setTimeout-string
  // ============================================================
  {
    id: 'S3-01',
    category: 'S3',
    description: 'eval with URL source',
    code: 'eval(location.hash);',
    expected: { findings: 1, sources: ['url'], sinks: ['code'] },
  },
  {
    id: 'S3-02',
    category: 'S3',
    description: 'new Function with URL source',
    code: 'new Function(location.hash)();',
    expected: { findings: 1, sources: ['url'], sinks: ['code'] },
  },
  {
    id: 'S3-03',
    category: 'S3',
    description: 'setTimeout with string first arg',
    code: 'setTimeout(location.hash, 100);',
    expected: { findings: 1, sources: ['url'], sinks: ['code'] },
  },
  {
    id: 'S3-04',
    category: 'S3',
    description: 'setTimeout with function (safe)',
    code: 'setTimeout(function() { console.log("safe"); }, 100);',
    expected: { findings: 0 },
  },

  // ============================================================
  // S4: Navigation sinks
  // ============================================================
  {
    id: 'S4-01',
    category: 'S4',
    description: 'location.href assignment',
    code: 'location.href = location.hash;',
    expected: { findings: 1, sources: ['url'], sinks: ['navigation'] },
  },
  {
    id: 'S4-02',
    category: 'S4',
    description: 'document.location.href assignment',
    code: 'document.location.href = location.hash;',
    expected: { findings: 1, sources: ['url'], sinks: ['navigation'] },
  },
  {
    id: 'S4-03',
    category: 'S4',
    description: 'window.open with tainted URL',
    code: 'window.open(location.hash);',
    expected: { findings: 1, sources: ['url'] },
  },

  // ============================================================
  // S5: setAttribute on event handlers
  // ============================================================
  {
    id: 'S5-01',
    category: 'S5',
    description: 'setAttribute onclick',
    code: 'document.createElement("div").setAttribute("onclick", location.hash);',
    expected: { findings: 1, sources: ['url'] },
  },

  // ============================================================
  // S6: CSS injection
  // ============================================================
  {
    id: 'S6-01',
    category: 'S6',
    description: 'style.cssText from URL',
    code: 'document.body.style.cssText = location.hash;',
    expected: { findings: 1, sources: ['url'], sinks: ['css'] },
  },
  {
    id: 'S6-02',
    category: 'S6',
    description: 'style.background from URL',
    code: 'document.body.style.background = location.hash;',
    expected: { findings: 1, sources: ['url'], sinks: ['css'] },
  },
  {
    id: 'S6-03',
    category: 'S6',
    description: 'element.style.cssText via getElementById',
    code: 'var el = document.getElementById("x"); el.style.cssText = location.hash;',
    expected: { findings: 1, sources: ['url'], sinks: ['css'] },
  },

  // ============================================================
  // S7: postMessage handler
  // ============================================================
  {
    id: 'S7-01',
    category: 'S7',
    description: 'message event data to innerHTML',
    code: 'window.addEventListener("message", function(e) { document.getElementById("o").innerHTML = e.data; });',
    expected: { findings: 1, sources: ['postMessage'], sinks: ['html'] },
  },
  {
    id: 'S7-02',
    category: 'S7',
    description: 'postMessage data via destructuring',
    code: 'window.addEventListener("message", function(e) { var d = e.data; document.getElementById("o").innerHTML = d; });',
    expected: { findings: 1, sources: ['postMessage'], sinks: ['html'] },
  },

  // ============================================================
  // S8: Fetch/XHR response to DOM
  // ============================================================
  {
    id: 'S8-01',
    category: 'S8',
    description: 'fetch().then(r => r.text()).then(t => innerHTML)',
    code: 'fetch("/api").then(r => r.text()).then(t => document.getElementById("o").innerHTML = t);',
    expected: { findings: 1, sources: ['network'], sinks: ['html'] },
  },
  {
    id: 'S8-02',
    category: 'S8',
    description: 'fetch + destructure',
    code: 'fetch("/api").then(r => r.json()).then(({data}) => document.getElementById("o").innerHTML = data);',
    expected: { findings: 1, sources: ['network'] },
  },
  {
    id: 'S8-03',
    category: 'S8',
    description: 'async function fetch flow',
    code: 'async function load() { var r = await fetch("/api"); var d = await r.json(); document.getElementById("o").innerHTML = d.html; } load();',
    expected: { findings: 1, sources: ['network'] },
  },
  {
    id: 'S8-04',
    category: 'S8',
    description: 'XHR response to innerHTML',
    code: 'var x = new XMLHttpRequest(); x.open("GET", "/api"); x.onload = function() { document.getElementById("o").innerHTML = x.response; }; x.send();',
    expected: { findings: 1, sources: ['network'] },
  },

  // ============================================================
  // S9: Storage to DOM
  // ============================================================
  {
    id: 'S9-01',
    category: 'S9',
    description: 'localStorage.getItem to innerHTML',
    code: 'document.getElementById("o").innerHTML = localStorage.getItem("key");',
    expected: { findings: 1, sources: ['storage'], sinks: ['html'] },
  },
  {
    id: 'S9-02',
    category: 'S9',
    description: 'sessionStorage.getItem to innerHTML',
    code: 'document.getElementById("o").innerHTML = sessionStorage.getItem("key");',
    expected: { findings: 1, sources: ['storage'], sinks: ['html'] },
  },

  // ============================================================
  // S10: Complex data flow (multi-step, cross-function, async)
  // ============================================================
  {
    id: 'S10-01',
    category: 'S10',
    description: 'Cross-function taint propagation',
    code: 'function process(x) { return x; } document.getElementById("o").innerHTML = process(location.hash);',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-02',
    category: 'S10',
    description: 'Dispatch table lookup',
    code: 'var routes = { home: function(x) { document.getElementById("o").innerHTML = x; } }; routes.home(location.hash);',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-03',
    category: 'S10',
    description: 'jQuery-style wrapper',
    code: 'var $ = document.querySelector.bind(document); $("#o").innerHTML = location.hash;',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-04',
    category: 'S10',
    description: 'Object.assign taint merge',
    code: 'var o = Object.assign({}, { u: location.hash }); document.getElementById("o").innerHTML = o.u;',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-05',
    category: 'S10',
    description: 'Early return pattern',
    code: 'function f() { if (a) return "safe"; return location.hash; } document.getElementById("o").innerHTML = f();',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-06',
    category: 'S10',
    description: 'Promise rejection flow',
    code: 'async function f() { throw location.hash; } f().catch(e => document.getElementById("o").innerHTML = e);',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-07',
    category: 'S10',
    description: 'Generator yield flow',
    code: 'function* gen() { yield location.hash; } for (var v of gen()) { document.getElementById("o").innerHTML = v; }',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-08',
    category: 'S10',
    description: 'Proxy get trap',
    code: 'var p = new Proxy({}, { get: function(t, k) { return location.hash; } }); document.getElementById("o").innerHTML = p.anything;',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-09',
    category: 'S10',
    description: 'Bind partial application',
    code: 'function f(x) { document.getElementById("o").innerHTML = x; } var g = f.bind(null, location.hash); g();',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-10',
    category: 'S10',
    description: 'ES5 prototype method',
    code: 'function F(x) { this.x = x; } F.prototype.getX = function() { return this.x; }; var f = new F(location.hash); document.getElementById("o").innerHTML = f.getX();',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-11',
    category: 'S10',
    description: 'Map iteration with destructuring',
    code: 'var m = new Map(); m.set("k", location.hash); for (var [k, v] of m.entries()) { document.getElementById("o").innerHTML = v; }',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-12',
    category: 'S10',
    description: 'Symbol.iterator protocol',
    code: 'var it = { [Symbol.iterator]: function*() { yield location.hash; } }; for (var v of it) { document.getElementById("o").innerHTML = v; }',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-13',
    category: 'S10',
    description: 'Nested container mutation via alias',
    code: 'var o = {}; var a = [o]; a[0].x = location.hash; document.getElementById("o").innerHTML = o.x;',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-14',
    category: 'S10',
    description: 'Constructor function with this binding',
    code: 'function Foo(x) { this.x = x; } var f = new Foo(location.hash); document.getElementById("o").innerHTML = f.x;',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-15',
    category: 'S10',
    description: 'Class getter/setter round-trip',
    code: 'class C { get v() { return this._v; } set v(x) { this._v = x; } } var c = new C(); c.v = location.hash; document.getElementById("o").innerHTML = c.v;',
    expected: { findings: 1, sources: ['url'] },
  },
  {
    id: 'S10-16',
    category: 'S10',
    description: 'Call-site cond refutation (safe concrete arg)',
    code: 'function f(a) { if (a > 5) return "safe"; return location.hash; } document.getElementById("o").innerHTML = f(10);',
    expected: { findings: 0 },
  },
  {
    id: 'S10-17',
    category: 'S10',
    description: 'SMT path refutation (x === 99 on constant 0)',
    code: 'function f(n){if(n<=0)return 0; return f(n-1)+1;} var x=f(3); if(x===99) document.getElementById("o").innerHTML=location.hash;',
    expected: { findings: 0 },
  },
  {
    id: 'S10-18',
    category: 'S10',
    description: 'DOMPurify sanitizer removes taint',
    code: 'var clean = DOMPurify.sanitize(location.hash); document.getElementById("o").innerHTML = clean;',
    expected: { findings: 0 },
  },
  {
    id: 'S10-19',
    category: 'S10',
    description: 'Nested try-catch swallows throw (no false positive)',
    code: 'function f(){ try { throw location.hash; } catch(e) { } } try { f(); } catch(e) { document.getElementById("o").innerHTML = e; }',
    expected: { findings: 0 },
  },
  {
    id: 'S10-20',
    category: 'S10',
    description: 'for-await async iterator',
    code: 'async function f(){ for await (var r of fetch("/api")) { document.getElementById("o").innerHTML = r; } } f();',
    expected: { findings: 1, sources: ['network'] },
  },
];
