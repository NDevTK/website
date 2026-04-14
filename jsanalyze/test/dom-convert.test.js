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
const { assert, assertEqual } = require('./run.js');

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
];

module.exports = { tests };
