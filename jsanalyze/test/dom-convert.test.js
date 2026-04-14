// dom-convert.test.js — consumers/dom-convert.js regression coverage.
//
// These tests port the legacy htmldom convertProject cases
// (htmldom/htmldom.test.js §convertProject) plus fixtures
// from the user-supplied example input, so the new consumer
// is held to the same contract the legacy engine satisfied.
//
// HTML-side coverage (this file):
//   * Inline <script> extraction
//   * Inline <style> extraction
//   * Inline event handlers → addEventListener
//   * Inline style attributes → style.setProperty
//   * javascript: hrefs → click handlers
//   * Multi-page non-collision
//   * Handlers script insertion point
//
// JS-side coverage (innerHTML → createElement,
// __safeNav, eval blocking, document.write lowering)
// is added by the next commit's tests.

'use strict';

const dc = require('../consumers/dom-convert.js');
const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

// Helper: run analyze() on a JS snippet and pass the trace
// into convertJsFile. Returns the rewritten source.
async function convertJs(src, filename) {
  filename = filename || '<input>.js';
  const trace = await analyze({ [filename]: src }, { typeDB: TDB });
  return dc.convertJsFile(src, trace, filename);
}

async function expectProject(files, expectedKeys, checks) {
  const out = await dc.convertProject(files);
  const gotKeys = Object.keys(out).sort();
  const wantKeys = expectedKeys.slice().sort();
  if (JSON.stringify(gotKeys) !== JSON.stringify(wantKeys)) {
    throw new Error('expected output files ' + JSON.stringify(wantKeys) +
      ' but got ' + JSON.stringify(gotKeys));
  }
  if (checks) {
    for (const [key, check] of Object.entries(checks)) {
      if (!check(out[key] || '')) {
        throw new Error('file `' + key + '` failed its check: ' +
          (out[key] || '').slice(0, 200));
      }
    }
  }
}

const tests = [
  // --- Inline <script> extraction ---
  {
    name: 'dom-convert: inline <script> extracted to <page>.js',
    fn: async () => {
      await expectProject(
        { 'app.html': '<html><body><script>var x = 1;</script></body></html>' },
        ['app.html', 'app.js'],
        {
          'app.html': c => /<script src="app\.js">/.test(c) && !/var x/.test(c),
          'app.js': c => /var x = 1/.test(c),
        });
    },
  },
  {
    name: 'dom-convert: multiple inline <script> blocks get numbered names',
    fn: async () => {
      await expectProject(
        { 'app.html':
          '<html><body><script>var a=1;</script><script>var b=2;</script></body></html>' },
        ['app.html', 'app.js', 'app.1.js'],
        {
          'app.js': c => /var a=1/.test(c),
          'app.1.js': c => /var b=2/.test(c),
        });
    },
  },
  {
    name: 'dom-convert: <script src=…> left alone',
    fn: async () => {
      await expectProject(
        { 'app.html':
          '<html><body><script src="lib.js"></script></body></html>' },
        [],
        {});
    },
  },

  // --- Inline <style> extraction ---
  {
    name: 'dom-convert: inline <style> extracted to <page>.css',
    fn: async () => {
      await expectProject(
        { 'page.html': '<html><head><style>body { color: red; }</style></head><body></body></html>' },
        ['page.html', 'page.css'],
        {
          'page.html': c => /link[^>]*href="page\.css"/.test(c) && !/<style>/.test(c),
          'page.css': c => /body\s*{\s*color:\s*red/.test(c),
        });
    },
  },

  // --- Inline event handlers ---
  {
    name: 'dom-convert: onclick → addEventListener in handlers file',
    fn: async () => {
      await expectProject(
        { 'page.html': '<html><body><button onclick="go()">Go</button></body></html>' },
        ['page.html', 'page.handlers.js'],
        {
          'page.html': c => !/onclick/.test(c) && /data-handler="0"/.test(c),
          'page.handlers.js': c =>
            /addEventListener\('click'/.test(c) &&
            /go\(\)/.test(c) &&
            /data-handler="0"/.test(c),
        });
    },
  },
  {
    name: 'dom-convert: inline style attribute → setProperty calls',
    fn: async () => {
      await expectProject(
        { 'page.html':
          '<html><body><div style="color: red; background: blue">x</div></body></html>' },
        ['page.html', 'page.handlers.js'],
        {
          'page.html': c => !/style=/.test(c) && /data-handler="0"/.test(c),
          'page.handlers.js': c =>
            /setProperty\('color',\s*'red'/.test(c) &&
            /setProperty\('background',\s*'blue'/.test(c),
        });
    },
  },
  {
    name: 'dom-convert: important flag preserved',
    fn: async () => {
      await expectProject(
        { 'page.html':
          '<html><body><div style="color: red !important">x</div></body></html>' },
        ['page.html', 'page.handlers.js'],
        {
          'page.handlers.js': c => /setProperty\('color',\s*'red',\s*'important'\)/.test(c),
        });
    },
  },
  {
    name: 'dom-convert: javascript: href → click handler with preventDefault',
    fn: async () => {
      await expectProject(
        { 'page.html': '<html><body><a href="javascript:go()">go</a></body></html>' },
        ['page.html', 'page.handlers.js'],
        {
          'page.html': c => !/javascript:/.test(c),
          'page.handlers.js': c =>
            /addEventListener\('click'/.test(c) &&
            /preventDefault/.test(c) &&
            /go\(\)/.test(c),
        });
    },
  },
  {
    name: 'dom-convert: element with id reused as selector',
    fn: async () => {
      await expectProject(
        { 'page.html':
          '<html><body><button id="go" onclick="alert(1)">x</button></body></html>' },
        ['page.html', 'page.handlers.js'],
        {
          'page.html': c => /id="go"/.test(c) && !/onclick/.test(c),
          'page.handlers.js': c =>
            /getElementById\('go'\)/.test(c) &&
            /alert\(1\)/.test(c),
        });
    },
  },
  {
    name: 'dom-convert: multiple inline events on one element share a scope',
    fn: async () => {
      await expectProject(
        { 'page.html':
          '<html><body><button onclick="a()" onmouseover="b()">x</button></body></html>' },
        ['page.html', 'page.handlers.js'],
        {
          'page.handlers.js': c =>
            /\(function\(\)/.test(c) &&     // wrapped in IIFE (>1 op)
            /var el =/.test(c) &&
            /addEventListener\('click'/.test(c) &&
            /addEventListener\('mouseover'/.test(c),
        });
    },
  },
  {
    name: 'dom-convert: handler returning false wraps in preventDefault check',
    fn: async () => {
      await expectProject(
        { 'page.html': '<html><body><a href="#" onclick="return false">x</a></body></html>' },
        ['page.html', 'page.handlers.js'],
        {
          'page.handlers.js': c =>
            /__r === false/.test(c) && /preventDefault/.test(c),
        });
    },
  },

  // --- Multi-page ---
  {
    name: 'dom-convert: two pages produce non-colliding handler files',
    fn: async () => {
      await expectProject(
        {
          'a.html': '<html><body><button onclick="x()">A</button></body></html>',
          'b.html': '<html><body><button onclick="y()">B</button></body></html>',
        },
        ['a.html', 'a.handlers.js', 'b.html', 'b.handlers.js'],
        {
          'a.handlers.js': c => /x\(\)/.test(c) && !/y\(\)/.test(c),
          'b.handlers.js': c => /y\(\)/.test(c) && !/x\(\)/.test(c),
        });
    },
  },

  // --- Handlers script insertion point ---
  {
    name: 'dom-convert: handlers script inserted before </body>',
    fn: async () => {
      await expectProject(
        { 'page.html': '<html><body><button onclick="go()">Go</button></body></html>' },
        ['page.html', 'page.handlers.js'],
        {
          'page.html': c => {
            const scriptIdx = c.indexOf('<script src="page.handlers.js"');
            const bodyClose = c.indexOf('</body>');
            return scriptIdx >= 0 && bodyClose >= 0 && scriptIdx < bodyClose;
          },
        });
    },
  },

  // --- Clean HTML untouched ---
  {
    name: 'dom-convert: clean HTML not in output',
    fn: async () => {
      await expectProject(
        { 'clean.html': '<html><body><p>Hello</p></body></html>' },
        [],
        {});
    },
  },

  // --- User-supplied example fragment ---
  {
    name: 'dom-convert: user example (inline style + inline handlers + inline script)',
    fn: async () => {
      const input =
        '<div style="position: fixed; z-index: -99; width: 100%; height: 100%">\n' +
        '  <iframe credentialless loading="lazy" id="background" sandbox="allow-scripts" ' +
        'frameborder="0" height="100%" width="100%" src="https://random.ndev.tk/"></iframe>\n' +
        '</div>\n' +
        '<button onclick="alert(\'hello\')">Greet</button>';
      const files = { 'page.html': input };
      const out = await dc.convertProject(files);
      const handlers = out['page.handlers.js'] || '';
      // The outer div's 4 style declarations → 4 setProperty calls.
      assert(/setProperty\('position',\s*'fixed'/.test(handlers),
        'position: fixed extracted: ' + handlers.slice(0, 200));
      assert(/setProperty\('z-index',\s*'-99'/.test(handlers),
        'z-index: -99 extracted');
      assert(/setProperty\('width',\s*'100%'/.test(handlers),
        'width: 100% extracted');
      assert(/setProperty\('height',\s*'100%'/.test(handlers),
        'height: 100% extracted');
      // The button's onclick → addEventListener.
      assert(/addEventListener\('click'.*alert\('hello'\)/.test(handlers),
        'button click handler extracted');
      // Rewritten HTML has no inline style= or onclick=.
      const pageHtml = out['page.html'];
      assert(!/style="/.test(pageHtml), 'style attr removed');
      assert(!/onclick=/.test(pageHtml), 'onclick attr removed');
      // iframe's `id="background"` is reused as the selector
      // for its own… wait, iframe has no inline events in this
      // fragment, so it's not rewritten. Just check it's intact.
      assert(/iframe/.test(pageHtml), 'iframe preserved');
      assert(/credentialless/.test(pageHtml), 'credentialless attr preserved');
    },
  },

  // --- parseStyleDecls edge cases ---
  {
    name: 'dom-convert: parseStyleDecls handles url(...) with semicolons',
    fn: () => {
      const decls = dc.parseStyleDecls('background: url("a;b.png"); color: red');
      assertEqual(decls.length, 2);
      assertEqual(decls[0].prop, 'background');
      assertEqual(decls[0].value, 'url("a;b.png")');
      assertEqual(decls[1].prop, 'color');
      assertEqual(decls[1].value, 'red');
    },
  },
  {
    name: 'dom-convert: parseStyleDecls strips !important',
    fn: () => {
      const decls = dc.parseStyleDecls('margin: 0 !important');
      assertEqual(decls.length, 1);
      assertEqual(decls[0].prop, 'margin');
      assertEqual(decls[0].value, '0');
      assertEqual(decls[0].important, true);
    },
  },

  // --- JS-side: concrete innerHTML → createElement tree ---
  {
    name: 'dom-convert js: concrete innerHTML becomes createElement + appendChild',
    fn: async () => {
      const out = await convertJs(
        'document.body.innerHTML = "<p>Hello</p>";');
      assert(!/innerHTML/.test(out), 'innerHTML removed');
      assert(/replaceChildren\(\)/.test(out), 'replaceChildren before DOM calls');
      assert(/createElement\("p"\)/.test(out), 'createElement("p")');
      assert(/createTextNode\("Hello"\)/.test(out), 'createTextNode for "Hello"');
    },
  },
  {
    name: 'dom-convert js: nested concrete innerHTML emits nested createElement',
    fn: async () => {
      const out = await convertJs(
        'document.body.innerHTML = "<div class=\\"x\\"><span>hi</span></div>";');
      assert(/createElement\("div"\)/.test(out), 'creates div');
      assert(/setAttribute\("class", "x"\)/.test(out), 'sets class attr');
      assert(/createElement\("span"\)/.test(out), 'creates span');
      assert(/createTextNode\("hi"\)/.test(out), 'creates text "hi"');
      assert(/appendChild/.test(out), 'appendChild present');
    },
  },
  {
    name: 'dom-convert js: non-concrete innerHTML is left alone',
    fn: async () => {
      const src = 'var x = location.hash; document.body.innerHTML = x;';
      const out = await convertJs(src);
      // innerHTML is still present — the MVP JS-side doesn't
      // synthesize runtime sanitizers for tainted values.
      assert(/innerHTML/.test(out), 'innerHTML preserved for non-concrete');
    },
  },

  // --- JS-side: tainted navigation → __safeNav ---
  {
    name: 'dom-convert js: tainted location.href wrapped in __safeNav',
    fn: async () => {
      const out = await convertJs(
        'var r = location.hash.slice(1); location.href = r;');
      assert(/__safeNav/.test(out), '__safeNav helper injected');
      assert(/function __safeNav\(url\)/.test(out), 'helper defined');
      // The assignment should be wrapped in the IIFE form.
      assert(/var __u=__safeNav\(r\)/.test(out),
        'assignment wrapped: ' + out.slice(0, 200));
    },
  },
  {
    name: 'dom-convert js: string-literal location.href NOT wrapped',
    fn: async () => {
      const out = await convertJs('location.href = "https://x.com/";');
      // String literals are safe at compile time — no wrapper.
      assert(!/__safeNav/.test(out), 'no __safeNav for literal');
    },
  },

  // --- JS-side: eval blocking ---
  {
    name: 'dom-convert js: eval(dynamic) → blocked placeholder',
    fn: async () => {
      const out = await convertJs(
        'var data = location.hash; eval(data);');
      assert(/\[blocked: eval with dynamic argument\]/.test(out),
        'eval blocked: ' + out);
      assert(!/eval\(data\)/.test(out), 'original eval removed');
    },
  },
  {
    name: 'dom-convert js: eval(constant) is NOT blocked',
    fn: async () => {
      const out = await convertJs('eval("var x = 1;");');
      assert(!/\[blocked/.test(out), 'constant eval not blocked');
    },
  },

  // --- JS-side: document.write lowering ---
  {
    name: 'dom-convert js: document.write(literal) → appendChild createTextNode',
    fn: async () => {
      const out = await convertJs('document.write("Hello");');
      assert(/createTextNode\("Hello"\)/.test(out), 'createTextNode emitted');
      assert(/appendChild/.test(out), 'appendChild emitted');
      assert(!/document\.write\("Hello"\)/.test(out), 'original call removed');
    },
  },

  // --- JS-side: loop-built innerHTML pattern ---
  {
    name: 'dom-convert js: loop-built nav → createElement + for loop',
    fn: async () => {
      // User-supplied navigation-builder example: the innerHTML
      // value is constructed at runtime via a for loop that
      // accumulates into an `html` variable. The pattern
      // matcher detects this shape and rewrites to an
      // iterative createElement loop.
      const src = [
        'var items = ["Home", "About", "Contact"];',
        'var html = "<nav>";',
        'for (var i = 0; i < items.length; i++) {',
        '  html += "<a href=\\"/" + items[i].toLowerCase() + "\\"" + ">" + items[i] + "</a>";',
        '}',
        'html += "</nav>";',
        'document.body.innerHTML = html;',
      ].join('\n');
      const out = await convertJs(src);
      // The rewritten source has replaceChildren + createElement
      // for nav + a for loop that creates anchors.
      assert(/replaceChildren\(\)/.test(out), 'replaceChildren emitted');
      assert(/createElement\("nav"\)/.test(out), 'nav created');
      assert(/for \(var i = 0; i < items\.length; i\+\+\)/.test(out),
        'loop preserved');
      assert(/createElement\("a"\)/.test(out), 'anchor created inside loop');
      assert(/setAttribute\("href"/.test(out), 'href attribute set');
      assert(/createTextNode/.test(out), 'createTextNode for the label');
      // The original string-concat assignment is gone.
      assert(!/document\.body\.innerHTML = html/.test(out),
        'original innerHTML assignment replaced');
    },
  },
  {
    name: 'dom-convert js: loop pattern with tainted text content still converts',
    fn: async () => {
      // The third item is location.search which taints `items`.
      // The loop pattern matches regardless — the tainted
      // value flows through createTextNode which is the safe
      // DOM sink, so no separate sanitizer is needed.
      const src = [
        'var items = ["Home", "About", location.search];',
        'var html = "<nav>";',
        'for (var i = 0; i < items.length; i++) {',
        '  html += "<a>" + items[i] + "</a>";',
        '}',
        'html += "</nav>";',
        'document.body.innerHTML = html;',
      ].join('\n');
      const out = await convertJs(src);
      assert(/createElement\("nav"\)/.test(out), 'nav created');
      assert(/createElement\("a"\)/.test(out), 'anchors created');
      assert(/createTextNode\(items\[i\]\)/.test(out),
        'tainted value flows through createTextNode: ' + out.slice(0, 300));
    },
  },

  // --- Wave 12d5: while / do-while / for-of loop templates ---
  {
    name: 'dom-convert js: while-loop accumulator → createElement + while',
    fn: async () => {
      const src = [
        'var items = ["a", "b", "c"];',
        'var html = "<ul>";',
        'var i = 0;',
        'while (i < items.length) {',
        '  html += "<li>" + items[i] + "</li>";',
        '  i++;',
        '}',
        'html += "</ul>";',
        'document.body.innerHTML = html;',
      ].join('\n');
      const out = await convertJs(src);
      assert(/createElement\("ul"\)/.test(out), 'ul created');
      assert(/while \(i < items\.length\)/.test(out),
        'while header preserved');
      assert(/i\+\+;/.test(out), 'bookkeeping i++ preserved');
      assert(/var i = 0/.test(out), 'var i = 0 preserved above loop');
      assert(/createElement\("li"\)/.test(out), 'li created');
      assert(/createTextNode\(items\[i\]\)/.test(out),
        'text content flows through createTextNode');
    },
  },
  {
    name: 'dom-convert js: do-while loop accumulator',
    fn: async () => {
      const src = [
        'var items = ["a", "b"];',
        'var html = "<ul>";',
        'var i = 0;',
        'do {',
        '  html += "<li>" + items[i] + "</li>";',
        '  i++;',
        '} while (i < items.length);',
        'html += "</ul>";',
        'document.body.innerHTML = html;',
      ].join('\n');
      const out = await convertJs(src);
      assert(/do \{/.test(out), 'do-while header preserved');
      assert(/\} while \(i < items\.length\)/.test(out),
        'do-while tail preserved');
      assert(/createElement\("li"\)/.test(out));
    },
  },
  {
    name: 'dom-convert js: for-of loop accumulator',
    fn: async () => {
      const src = [
        'var items = ["a", "b"];',
        'var html = "";',
        'for (var item of items) {',
        '  html += "<li>" + item + "</li>";',
        '}',
        'document.body.innerHTML = html;',
      ].join('\n');
      const out = await convertJs(src);
      assert(/for \(var item of items\)/.test(out),
        'for-of header preserved');
      assert(/createElement\("li"\)/.test(out));
      assert(/createTextNode\(item\)/.test(out),
        'per-item text node');
    },
  },

  // --- Wave 12d7: branch nested inside a loop body ---
  {
    name: 'dom-convert js: if/else inside loop body → one child splice per branch',
    fn: async () => {
      // The loop body's accumulator-append is guarded by an
      // if/else that picks one of two different child shapes
      // per iteration. The library collects both accum-sites
      // and the consumer splices each site's child block in
      // place, preserving the enclosing if/else control flow.
      const src = [
        'var items = ["short", "longer one"];',
        'var html = "<ul>";',
        'for (var i = 0; i < items.length; i++) {',
        '  if (items[i].length > 5) {',
        '    html += "<li class=\\"long\\">" + items[i] + "</li>";',
        '  } else {',
        '    html += "<li>" + items[i] + "</li>";',
        '  }',
        '}',
        'html += "</ul>";',
        'document.body.innerHTML = html;',
      ].join('\n');
      const out = await convertJs(src);
      assert(/createElement\("ul"\)/.test(out), 'ul wrapper created');
      assert(/for \(var i = 0; i < items\.length; i\+\+\)/.test(out),
        'for header preserved');
      assert(/if \(items\[i\]\.length > 5\) \{/.test(out),
        'if guard preserved: ' + out);
      assert(/\} else \{/.test(out), 'else branch preserved');
      // Two createElement("li") calls — one per branch — and
      // only the long branch sets the class attribute.
      const liMatches = out.match(/createElement\("li"\)/g) || [];
      assert(liMatches.length === 2,
        'two li createElement calls, got ' + liMatches.length + ': ' + out);
      assert(/setAttribute\("class", "long"\)/.test(out),
        'long-branch class attr emitted: ' + out);
      assert(/createTextNode\(items\[i\]\)/.test(out),
        'text expression emitted');
      assert(!/innerHTML =/.test(out),
        'original innerHTML assignment removed');
    },
  },

  // --- Wave 12d: if/else accumulator branch template ---
  {
    name: 'dom-convert js: if/else accumulator → branch template',
    fn: async () => {
      const src = [
        'var cond = location.hash === "admin";',
        'var html;',
        'if (cond) {',
        '  html = "<p>Welcome, admin</p>";',
        '} else {',
        '  html = "<p>Welcome, guest</p>";',
        '}',
        'document.body.innerHTML = html;',
      ].join('\n');
      const out = await convertJs(src);
      assert(/document\.body\.replaceChildren/.test(out),
        'replaceChildren emitted');
      assert(/if \(cond\) \{/.test(out), 'if branch preserved');
      assert(/\} else \{/.test(out), 'else branch preserved');
      assert(/createTextNode\("Welcome, admin"\)/.test(out),
        'admin branch emits admin text');
      assert(/createTextNode\("Welcome, guest"\)/.test(out),
        'guest branch emits guest text');
      assert(!/innerHTML =/.test(out), 'original innerHTML assignment removed');
    },
  },
  {
    name: 'dom-convert js: ternary in var decl → branch template',
    fn: async () => {
      const src = [
        'var cond = location.hash === "admin";',
        'var html = cond ? "<p>admin</p>" : "<p>guest</p>";',
        'document.body.innerHTML = html;',
      ].join('\n');
      const out = await convertJs(src);
      assert(/if \(cond\)/.test(out), 'ternary lowered to if/else');
      assert(/createTextNode\("admin"\)/.test(out), 'admin emitted');
      assert(/createTextNode\("guest"\)/.test(out), 'guest emitted');
    },
  },
  {
    name: 'dom-convert js: if/else without block braces → branch template',
    fn: async () => {
      const src = [
        'var cond = 1;',
        'var html;',
        'if (cond) html = "<b>yes</b>";',
        'else html = "<i>no</i>";',
        'document.body.innerHTML = html;',
      ].join('\n');
      const out = await convertJs(src);
      assert(/if \(cond\)/.test(out), 'if/else preserved');
      assert(/createElement\("b"\)/.test(out), 'b element in consequent');
      assert(/createElement\("i"\)/.test(out), 'i element in alternate');
    },
  },

  // --- Wave 12d6: switch accumulator template ---
  {
    name: 'dom-convert js: switch accumulator → switch template',
    fn: async () => {
      const src = [
        'var kind = location.hash;',
        'var html;',
        'switch (kind) {',
        '  case "a": html = "<p>A</p>"; break;',
        '  case "b": html = "<p>B</p>"; break;',
        '  default: html = "<p>?</p>";',
        '}',
        'document.body.innerHTML = html;',
      ].join('\n');
      const out = await convertJs(src);
      assert(/switch \(kind\)/.test(out), 'switch header preserved');
      assert(/case "a":/.test(out), 'case "a" present');
      assert(/case "b":/.test(out), 'case "b" present');
      assert(/default:/.test(out), 'default present');
      assert(/createTextNode\("A"\)/.test(out), 'A branch emitted');
      assert(/createTextNode\("B"\)/.test(out), 'B branch emitted');
      assert(/createTextNode\("\?"\)/.test(out), 'default emitted');
      assert(!/innerHTML =/.test(out), 'original innerHTML removed');
    },
  },

  // --- Wave 12c7: callback walking through addEventListener ---
  {
    name: 'dom-convert js: eval inside addEventListener handler is blocked',
    fn: async () => {
      // The handler is never directly called — it only gets
      // registered as a message listener. Without callback
      // walking the engine wouldn\'t observe the eval inside
      // it and the rewriter would leave the call alone.
      // With callback walking the eval surfaces in trace.calls
      // and convertJsFile replaces it with the blocked
      // placeholder.
      const src = [
        'var h = function(msg) {',
        '  var data = msg.data;',
        '  eval(data);',
        '};',
        "window.addEventListener('message', h, false);",
      ].join('\n');
      const out = await convertJs(src);
      assert(/\[blocked: eval with dynamic argument\]/.test(out),
        'eval inside handler is blocked: ' + out);
    },
  },
  {
    name: 'dom-convert js: document.write(literal) inside handler is lowered',
    fn: async () => {
      const src = [
        'var h = function() {',
        '  document.write("Hello");',
        '};',
        "window.addEventListener('click', h, false);",
      ].join('\n');
      const out = await convertJs(src);
      assert(/createTextNode\("Hello"\)/.test(out),
        'document.write literal inside handler lowered: ' + out);
    },
  },
  {
    name: 'dom-convert js: tainted navigation inside setTimeout callback is wrapped',
    fn: async () => {
      // setTimeout's first arg is a callback; the body's
      // `location.href = dirty` assignment should be wrapped
      // in __safeNav despite living inside a deferred handler.
      const src = [
        'var dirty = location.hash.slice(1);',
        'setTimeout(function() {',
        '  location.href = dirty;',
        '}, 100);',
      ].join('\n');
      const out = await convertJs(src);
      assert(/__safeNav/.test(out), '__safeNav helper inserted: ' + out);
      assert(/var __u=__safeNav\(dirty\)/.test(out),
        'tainted assignment wrapped: ' + out);
    },
  },

  // --- Wave 12d8: legacy adversarial convertProject cases ---
  //
  // These port the adversarial cases from
  // htmldom/htmldom.test.js §adversarial into the new engine
  // via convertJsFile. The negatives check that the engine
  // doesn't mis-recognise innerHTML strings / plain objects
  // as real DOM sinks; the positives check that the
  // additional sink forms (writeln, outerHTML,
  // insertAdjacentHTML, innerHTML +=) are all rewritten.
  {
    name: 'dom-convert js: var named innerHTML is NOT rewritten',
    fn: async () => {
      // A local `var innerHTML = …` declaration is not a DOM
      // sink — the engine's sink classifier gates on the
      // receiver's typeName. Since `innerHTML` is a plain
      // binding with no DOM-chain type, no innerHtmlAssignment
      // record is produced and convertJsFile leaves the source
      // untouched.
      const src = 'var innerHTML = "<p>safe</p>";\nconsole.log(innerHTML);';
      const out = await convertJs(src);
      assert(out === src,
        'var innerHTML must not be rewritten. Got:\n' + out);
    },
  },
  {
    name: 'dom-convert js: innerHTML inside a comment is NOT rewritten',
    fn: async () => {
      const src = '// el.innerHTML = "<b>xss</b>";\nconsole.log("safe");';
      const out = await convertJs(src);
      assert(out === src, 'comment-only innerHTML rewritten: ' + out);
    },
  },
  {
    name: 'dom-convert js: innerHTML inside a string literal is NOT rewritten',
    fn: async () => {
      const src = 'var s = "el.innerHTML = bad";\nconsole.log(s);';
      const out = await convertJs(src);
      assert(out === src, 'string-literal innerHTML rewritten: ' + out);
    },
  },
  {
    name: 'dom-convert js: obj.innerHTML on plain object is NOT rewritten',
    fn: async () => {
      const src = [
        'var obj = { innerHTML: "" };',
        'obj.innerHTML = "<div>test</div>";',
      ].join('\n');
      const out = await convertJs(src);
      assert(out === src,
        'plain-object innerHTML rewritten: ' + out);
    },
  },
  {
    name: 'dom-convert js: empty innerHTML → replaceChildren only',
    fn: async () => {
      const src = 'document.body.innerHTML = "";';
      const out = await convertJs(src);
      assert(/document\.body\.replaceChildren\(\);/.test(out),
        'empty innerHTML emits replaceChildren: ' + out);
      assert(!/innerHTML =/.test(out),
        'original assignment removed: ' + out);
    },
  },
  {
    name: 'dom-convert js: double innerHTML → two independent rewrites',
    fn: async () => {
      const src = [
        'var x = 1, y = 2;',
        'document.body.innerHTML = "<a>" + x + "</a>";',
        'document.body.innerHTML = "<b>" + y + "</b>";',
      ].join('\n');
      const out = await convertJs(src);
      assert(/createElement\("a"\)/.test(out), 'a element: ' + out);
      assert(/createElement\("b"\)/.test(out), 'b element: ' + out);
      assert(!/innerHTML =/.test(out),
        'both original assignments removed: ' + out);
    },
  },
  {
    name: 'dom-convert js: script tag in split concat → createElement',
    fn: async () => {
      // "<scr" + "ipt>alert(1)</" + "script>" — the concat
      // folds to "<script>alert(1)</script>". The engine's
      // concrete-value path emits createElement("script")
      // etc., which the consumer treats structurally.
      const src = 'document.body.innerHTML = "<scr" + "ipt>alert(1)</" + "script>";';
      const out = await convertJs(src);
      assert(!/innerHTML =/.test(out),
        'original innerHTML removed: ' + out);
    },
  },
  {
    name: 'dom-convert js: outerHTML = literal → parentNode.replaceChild',
    fn: async () => {
      const src = [
        'var el = document.getElementById("x");',
        'el.outerHTML = "<div id=\\"new\\">hello</div>";',
      ].join('\n');
      const out = await convertJs(src);
      assert(/createDocumentFragment|createElement\("div"\)/.test(out),
        'fragment or div emitted: ' + out);
      assert(/parentNode\.replaceChild/.test(out),
        'parentNode.replaceChild emitted: ' + out);
      assert(!/outerHTML =/.test(out),
        'original outerHTML removed: ' + out);
    },
  },
  {
    name: 'dom-convert js: insertAdjacentHTML(beforeend, literal) → appendChild',
    fn: async () => {
      const src = [
        'var el = document.getElementById("x");',
        'el.insertAdjacentHTML("beforeend", "<li>item</li>");',
      ].join('\n');
      const out = await convertJs(src);
      assert(/createElement\("li"\)/.test(out),
        'li created: ' + out);
      assert(/el\.appendChild/.test(out),
        'appendChild on receiver: ' + out);
      assert(!/insertAdjacentHTML/.test(out),
        'original call removed: ' + out);
    },
  },
  {
    name: 'dom-convert js: insertAdjacentHTML(beforebegin, literal) → parentNode.insertBefore',
    fn: async () => {
      const src = [
        'var ref = document.getElementById("r");',
        'ref.insertAdjacentHTML("beforebegin", "<hr>");',
      ].join('\n');
      const out = await convertJs(src);
      assert(/createElement\("hr"\)/.test(out),
        'hr created: ' + out);
      assert(/parentNode\.insertBefore/.test(out),
        'parentNode.insertBefore emitted: ' + out);
      assert(!/insertAdjacentHTML/.test(out),
        'original call removed: ' + out);
    },
  },
  {
    name: 'dom-convert js: document.writeln(literal) → appendChild createTextNode',
    fn: async () => {
      const src = 'document.writeln("Hello");';
      const out = await convertJs(src);
      assert(/createTextNode\("Hello"\)/.test(out),
        'createTextNode emitted: ' + out);
      assert(!/document\.writeln\(/.test(out),
        'original writeln removed: ' + out);
    },
  },
];

module.exports = { tests };
