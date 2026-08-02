// ast-snapshot.js — differential safety net for parser changes.
//
//   node jsanalyze/scripts/ast-snapshot.js save before.json
//   …change the parser…
//   node jsanalyze/scripts/ast-snapshot.js save after.json
//   node jsanalyze/scripts/ast-snapshot.js diff before.json after.json
//
// The unit suite proves the parser still finds the flows it used
// to find. It does NOT prove the parser builds the same tree: a
// refactor can shift a node type, drop an operand, or reassociate
// an operator and still pass every test, because most tests only
// assert on the taint result at the end of a long pipeline.
//
// This captures the actual ASTs — every construct-coverage
// snippet, every .js file in the repo, and every cached
// production bundle — with positions stripped and keys sorted,
// so a rewrite can be shown to be structurally identical rather
// than merely test-passing.
//
// `diff` exits non-zero on any change except a source that
// previously failed to parse and now succeeds, which is an
// improvement rather than a regression.

'use strict';

const fs   = require('fs');
const path = require('path');

const ROOT   = path.join(__dirname, '..', '..');
const CORPUS = path.join(__dirname, '..', '.corpus');
const SKIP   = new Set(['node_modules', '.git', 'vendor', '.corpus', 'browser-bundle.js']);

// Structural view of a node: positions dropped (a rewrite may
// legitimately report different spans), key order normalised,
// child order preserved.
function normalise(node) {
  if (Array.isArray(node)) return node.map(normalise);
  if (!node || typeof node !== 'object') return node;
  const out = {};
  for (const k of Object.keys(node).sort()) {
    if (k === 'loc' || k === 'start' || k === 'end' || k === 'range') continue;
    out[k] = normalise(node[k]);
  }
  return out;
}

function collectSources() {
  const { parseModule } = require('../src/parse.js');
  const sources = [];

  // Construct-coverage snippets: the shapes we care about most.
  const covPath = path.join(__dirname, '..', 'test', 'construct-coverage.test.js');
  if (fs.existsSync(covPath)) {
    const cov = fs.readFileSync(covPath, 'utf8');
    let i = 0;
    for (const m of cov.matchAll(/^\s*'[^']*':\s*(.+?),?$/gm)) {
      const literal = m[1].trim().replace(/,$/, '');
      let code;
      try {
        // The table builds snippets from a SINK constant.
        code = new Function('SINK', 'return ' + literal)(
          'document.body.innerHTML = h;');
      } catch (e) { continue; }
      if (typeof code === 'string') sources.push({ name: 'snippet:' + (i++), code });
    }
  }

  // Every JS file in the repo.
  (function walk(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (SKIP.has(e.name)) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.js')) {
        sources.push({ name: path.relative(ROOT, p), code: fs.readFileSync(p, 'utf8') });
      }
    }
  })(ROOT);

  // Production bundles, if check-corpus.js has cached them.
  if (fs.existsSync(CORPUS)) {
    for (const f of fs.readdirSync(CORPUS)) {
      sources.push({ name: 'corpus:' + f, code: fs.readFileSync(path.join(CORPUS, f), 'utf8') });
    }
  }
  return { sources, parseModule };
}

function save(outFile) {
  const { sources, parseModule } = collectSources();
  const out = Object.create(null);
  let ok = 0, failed = 0;
  for (const { name, code } of sources) {
    try {
      out[name] = JSON.stringify(normalise(parseModule(code, name, { sourceType: 'script' })));
      ok++;
    } catch (e) {
      out[name] = 'ERROR: ' + e.message;
      failed++;
    }
  }
  fs.writeFileSync(outFile, JSON.stringify(out));
  console.log('saved ' + sources.length + ' sources (' + ok + ' parsed, ' +
    failed + ' failed) to ' + outFile);
}

function diff(beforeFile, afterFile) {
  const before = JSON.parse(fs.readFileSync(beforeFile, 'utf8'));
  const after  = JSON.parse(fs.readFileSync(afterFile, 'utf8'));
  let identical = 0;
  const changes = [];
  for (const key of Object.keys(before)) {
    if (!(key in after)) { changes.push({ key, kind: 'MISSING' }); continue; }
    if (before[key] === after[key]) { identical++; continue; }
    const wasError = before[key].startsWith('ERROR:');
    const isError  = after[key].startsWith('ERROR:');
    changes.push({
      key,
      kind: wasError && !isError ? 'now-parses'
        : !wasError && isError ? 'REGRESSED'
        : 'AST-CHANGED',
      detail: isError ? after[key].slice(0, 100) : '',
    });
  }
  console.log('identical ' + identical + ', changed ' + changes.length);
  for (const c of changes.slice(0, 40)) {
    console.log('  ' + c.kind.padEnd(12) + ' ' + c.key + (c.detail ? '  ' + c.detail : ''));
  }
  const bad = changes.filter((c) => c.kind !== 'now-parses');
  if (bad.length > 0) {
    console.log('');
    console.log(bad.length + ' source(s) changed shape or stopped parsing.');
    process.exitCode = 1;
  }
}

const [cmd, a, b] = process.argv.slice(2);
if (cmd === 'save' && a) save(a);
else if (cmd === 'diff' && a && b) diff(a, b);
else {
  console.log('usage: ast-snapshot.js save <file> | diff <before> <after>');
  process.exitCode = 2;
}
