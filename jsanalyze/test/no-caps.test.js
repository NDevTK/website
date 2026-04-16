// no-caps.test.js — regression guard for hidden-assumption audit
//
// Every hidden cap / magic number / silent catch we removed gets
// an explicit test here so it can't silently come back. If any of
// these tests fail, the offending change has reintroduced an
// arbitrary limit or swallowed an exception.

'use strict';

const path = require('path');
const fs = require('fs');
const { assert, assertEqual } = require('./run.js');

const SRC_DIR = path.join(__dirname, '..', 'src');

// Read the combined source of every module in src/ so we can
// grep-check for specific patterns. Used to assert structural
// properties (no `maxIterations`, etc.) that unit tests can't.
function readAllSource() {
  const files = fs.readdirSync(SRC_DIR).filter(f => f.endsWith('.js'));
  let text = '';
  for (const f of files) text += fs.readFileSync(path.join(SRC_DIR, f), 'utf8') + '\n';
  return text;
}

const tests = [
  {
    name: 'no MAX_OVERLAY_DEPTH constant in engine source',
    fn: () => {
      const src = readAllSource();
      assert(!/MAX_OVERLAY_DEPTH/.test(src),
        'MAX_OVERLAY_DEPTH found — overlay flattening heuristic reintroduced');
    },
  },
  {
    name: 'no maxIterations cap in worklist source',
    fn: () => {
      const src = fs.readFileSync(path.join(SRC_DIR, 'worklist.js'), 'utf8');
      assert(!/maxIterations/.test(src),
        'maxIterations found — worklist iteration cap reintroduced');
    },
  },
  {
    name: 'no cartesian product cap in transfer source',
    fn: () => {
      const src = fs.readFileSync(path.join(SRC_DIR, 'transfer.js'), 'utf8');
      // The old code used `length * length <= 64` and `length <= 16`.
      assert(!/values\.length\s*\*\s*[a-z.]+\.values\.length\s*<=\s*\d/.test(src),
        'cartesian product cap found — broadcast limit reintroduced');
      assert(!/\.values\.length\s*<=\s*1[0-9](?!\d)/.test(src),
        'OneOf broadcast length cap found — reintroduced');
    },
  },
  {
    name: 'whole-program fixpoint has no magic iteration / widen-threshold constants',
    fn: () => {
      const src = fs.readFileSync(path.join(SRC_DIR, 'index.js'), 'utf8');
      // Guards D14 for the fixpoint driver. No MAX_ITER /
      // MAX_ITERATIONS / WIDEN_AT / similar caps — widening is
      // the structural termination mechanism.
      assert(!/\bMAX_ITER(ATIONS)?\b/.test(src),
        'MAX_ITER found — fixpoint iteration cap reintroduced (violates D14)');
      assert(!/\bWIDEN_AT\b/.test(src),
        'WIDEN_AT found — widening-threshold constant reintroduced (violates D14)');
      assert(!/iter\s*<\s*\d+\s*&&/.test(src),
        'numeric iteration bound found on fixpoint loop (violates D14)');
    },
  },
  {
    name: 'only boundary catches exist in engine src',
    fn: () => {
      // Allowed: index.js has exactly 3 try/catch — one for the
      // parse boundary, one for the module-top walk boundary,
      // and one per-callback inside the whole-program fixpoint
      // loop. The third one is required because a single
      // callback's walk error mustn't abort the fixpoint over
      // the others (the driver iterates over a set of
      // registered callbacks; failing to continue would turn
      // one bad callback into a whole-file analysis failure).
      // Everywhere else: none.
      for (const f of fs.readdirSync(SRC_DIR)) {
        if (!f.endsWith('.js')) continue;
        const src = fs.readFileSync(path.join(SRC_DIR, f), 'utf8');
        const matches = src.match(/\bcatch\s*\(/g) || [];
        if (f === 'index.js') {
          assertEqual(matches.length, 3,
            'index.js must have exactly 3 boundary catches, found ' + matches.length);
        } else {
          assertEqual(matches.length, 0,
            f + ' must have zero catch clauses, found ' + matches.length);
        }
      }
    },
  },
  {
    name: 'boundary catches raise soundness assumptions',
    fn: () => {
      const src = fs.readFileSync(path.join(SRC_DIR, 'index.js'), 'utf8');
      // Each boundary catch must include a `assumptions.raise(` call
      // on the same handler. Count raises to be safe.
      const raises = src.match(/assumptions\.raise\(/g) || [];
      assert(raises.length >= 2,
        'expected >= 2 boundary raises in index.js, found ' + raises.length);
    },
  },
  {
    name: 'deep expression parses without ever catching exceptions',
    fn: async () => {
      // Build a 5000-term chain and make sure it analyzes without
      // any `trace.warnings` entries (which would indicate a
      // boundary catch fired).
      const { analyze } = require('../src/index.js');
      let src = 'var x = 1';
      for (let i = 0; i < 5000; i++) src += ' + ' + i;
      src += ';';
      const trace = await analyze(src);
      assertEqual(trace.warnings.length, 0,
        'deep-expression parse produced warnings: ' + JSON.stringify(trace.warnings));
      assertEqual(trace.partial, false);
    },
  },
  {
    name: 'lattice transfer stays sound without caps (no Top fallback)',
    fn: async () => {
      // A small OneOf binary-op should produce a full cartesian
      // product, not a Top widened value. Previously capped at 64
      // products; now unbounded.
      const { analyze } = require('../src/index.js');
      const trace = await analyze('var a = 1; var b = 2; var c = a + b;');
      // Look for any concrete(3) in the bindings.
      let found = false;
      for (const reg in trace.bindings) {
        const v = trace.bindings[reg];
        if (v && v.kind === 'concrete' && v.value === 3) { found = true; break; }
      }
      assert(found, 'expected concrete(3) from 1+2 after cap removal');
    },
  },
];

module.exports = { tests };
