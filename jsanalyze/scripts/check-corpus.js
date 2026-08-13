// check-corpus.js — run the parser over real production bundles.
//
//   node jsanalyze/scripts/check-corpus.js [--depth]
//
// The unit tests analyse snippets. Snippets are written by hand,
// and hand-written code is not what this analyser is pointed at:
// its input is minified, bundled, machine-generated JavaScript.
// Those two dialects diverge sharply — a minifier folds branches
// into nested ternaries, folds statements into comma sequences,
// and names object keys with reserved words — and every one of
// those shapes was a parse error here while the whole unit suite
// stayed green.
//
// A parse error is not a local failure. `analyze()` abandons the
// file, so one unsupported construct erases every finding in it,
// and the result is indistinguishable from a clean scan. That is
// the failure mode this script exists to catch.
//
// The bundles are fetched rather than vendored (they are tens of
// megabytes) and cached under jsanalyze/.corpus/. With no
// network the script skips, and says so, rather than passing
// silently.

'use strict';

const fs   = require('fs');
const path = require('path');
const https = require('https');

const { parseModule } = require('../src/parse.js');

const CACHE = path.join(__dirname, '..', '.corpus');

// Chosen for dialect coverage rather than popularity: an old
// UMD library (jQuery, Angular), modern framework output (React,
// Vue), a compiler bundle (TypeScript, Babel), an app-scale
// bundle (Monaco), and heavy numeric code (three.js).
const CORPUS = [
  ['react-dom.min.js',  'https://cdnjs.cloudflare.com/ajax/libs/react-dom/18.2.0/umd/react-dom.production.min.js'],
  ['vue.prod.min.js',   'https://cdnjs.cloudflare.com/ajax/libs/vue/3.4.21/vue.global.prod.min.js'],
  ['jquery.min.js',     'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js'],
  ['angular.min.js',    'https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js'],
  ['lodash.min.js',     'https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js'],
  ['d3.min.js',         'https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js'],
  ['moment.min.js',     'https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.4/moment.min.js'],
  ['three.min.js',      'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js'],
  ['babel.min.js',      'https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/7.23.6/babel.min.js'],
  ['typescript.min.js', 'https://cdnjs.cloudflare.com/ajax/libs/typescript/5.3.3/typescript.min.js'],
  ['monaco.editor.js',  'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs/editor/editor.main.js'],
];

function fetch(url, dest) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 120000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error('HTTP ' + res.statusCode));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        fs.writeFileSync(dest, Buffer.concat(chunks));
        resolve();
      });
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', reject);
  });
}

// Deepest AST path, walked with an explicit stack so measuring a
// bundle can't overflow while parsing it didn't.
function astDepth(node) {
  let max = 0;
  const stack = [[node, 1]];
  while (stack.length > 0) {
    const [n, d] = stack.pop();
    if (d > max) max = d;
    for (const k in n) {
      if (k === 'loc') continue;
      const v = n[k];
      if (v && typeof v === 'object' && v.type) stack.push([v, d + 1]);
      else if (Array.isArray(v)) {
        for (const c of v) if (c && typeof c === 'object' && c.type) stack.push([c, d + 1]);
      }
    }
  }
  return max;
}

async function main() {
  const wantDepth = process.argv.includes('--depth');
  if (!fs.existsSync(CACHE)) fs.mkdirSync(CACHE, { recursive: true });

  let ok = 0, failed = 0, skipped = 0;
  const failures = [];

  for (const [name, url] of CORPUS) {
    const dest = path.join(CACHE, name);
    if (!fs.existsSync(dest)) {
      try {
        await fetch(url, dest);
      } catch (e) {
        console.log('SKIP  ' + name.padEnd(20) + ' (fetch failed: ' + e.message + ')');
        skipped++;
        continue;
      }
    }
    const src = fs.readFileSync(dest, 'utf8');
    const t0 = Date.now();
    let ast = null;
    try {
      ast = parseModule(src, name, { sourceType: 'script' });
    } catch (e) {
      failed++;
      failures.push({ name, message: e.message });
      console.log('FAIL  ' + name.padEnd(20) + ' ' +
        e.message.replace(/^.*parse error: /, '').slice(0, 60));
      continue;
    }
    ok++;
    const ms = Date.now() - t0;
    const extra = wantDepth ? '  depth=' + astDepth(ast) : '';
    console.log('ok    ' + name.padEnd(20) +
      String(Math.round(src.length / 1024)).padStart(6) + ' KB  ' +
      String(ms).padStart(5) + ' ms' + extra);
  }

  console.log('');
  console.log('parsed ' + ok + '/' + (ok + failed) +
    (skipped ? '  (' + skipped + ' skipped — no network)' : ''));
  if (failed > 0) {
    console.log('');
    console.log('A parse failure here means every finding in that bundle is');
    console.log('silently absent. Reduce the failure to a minimal case and add');
    console.log('it to test/construct-coverage.test.js before fixing it.');
    process.exitCode = 1;
  }
}

main();
