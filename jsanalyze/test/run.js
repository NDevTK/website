// test/run.js — minimal test harness for jsanalyze
//
// Run with: node jsanalyze/test/run.js
//
// Each test file exports an array of { name, fn } entries. This
// runner executes them and prints pass/fail counts. No external
// dependencies.

'use strict';

const path = require('path');
const fs = require('fs');

const testFiles = [
  'parse.test.js',
  'assumptions.test.js',
  'ir.test.js',
  'domain.test.js',
  'transfer.test.js',
  'worklist.test.js',
  'analyze.test.js',
  'no-caps.test.js',
  'typedb.test.js',
  'source-classification.test.js',
  'sink-classification.test.js',
  'smt.test.js',
  'formula.test.js',
  'path-cond.test.js',
  'refine.test.js',
  'interproc.test.js',
  'per-path-type.test.js',
  'type-narrow.test.js',
  'scope.test.js',
  'loop.test.js',
  'try.test.js',
  'arrow.test.js',
  'destructure.test.js',
  'modern-js.test.js',
];

async function main() {
  let total = 0, passed = 0, failed = 0;
  const failures = [];
  for (const tf of testFiles) {
    const full = path.join(__dirname, tf);
    if (!fs.existsSync(full)) continue;
    const mod = require(full);
    if (!mod.tests || !Array.isArray(mod.tests)) {
      console.log('SKIP', tf, '(no tests exported)');
      continue;
    }
    console.log('\n' + tf);
    console.log('-'.repeat(tf.length));
    for (const t of mod.tests) {
      total++;
      try {
        await t.fn();
        passed++;
        process.stdout.write('.');
      } catch (e) {
        failed++;
        process.stdout.write('F');
        failures.push({ file: tf, name: t.name, error: e });
      }
    }
    console.log('');
  }
  console.log('\n' + '='.repeat(60));
  console.log('Total: ' + total + '  Passed: ' + passed + '  Failed: ' + failed);
  if (failures.length > 0) {
    console.log('');
    for (const f of failures) {
      console.log('FAIL ' + f.file + ' :: ' + f.name);
      console.log('  ' + (f.error.message || f.error));
      if (f.error.stack) {
        console.log('  ' + f.error.stack.split('\n').slice(1, 4).join('\n  '));
      }
    }
    process.exit(1);
  }
  process.exit(0);
}

// Simple assertion helpers used by test files.
function assert(cond, msg) {
  if (!cond) throw new Error('assertion failed: ' + (msg || ''));
}
function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error((msg || 'values differ') + '\n  expected: ' + JSON.stringify(expected) + '\n  actual:   ' + JSON.stringify(actual));
  }
}
function assertDeepEqual(actual, expected, msg) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    throw new Error((msg || 'values differ') + '\n  expected: ' + e + '\n  actual:   ' + a);
  }
}
function assertThrows(fn, msg) {
  let threw = false;
  try { fn(); } catch (_) { threw = true; }
  if (!threw) throw new Error('expected to throw: ' + (msg || ''));
}

module.exports = { assert, assertEqual, assertDeepEqual, assertThrows };

if (require.main === module) main();
