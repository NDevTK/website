#!/usr/bin/env node
// DOM XSS Benchmark Runner
// ========================
// Runs every test case in dom-xss-corpus.js through the analyser
// and reports precision / recall / F1 per category and overall.
//
// Precision = TP / (TP + FP)   — "of the findings we reported, how many are real?"
// Recall    = TP / (TP + FN)   — "of the real vulnerabilities, how many did we find?"
// F1        = 2 * P * R / (P + R)
//
// A test case is:
//   TP if expected.findings > 0 AND actual findings > 0
//   FN if expected.findings > 0 AND actual findings === 0
//   TN if expected.findings === 0 AND actual findings === 0
//   FP if expected.findings === 0 AND actual findings > 0
//
// Source/sink matching: when expected.sources / expected.sinks are
// specified, we additionally verify that the actual finding's sources
// include every expected source and the actual finding's sink type
// matches. A mismatch is a "wrong finding" and counts as FP + FN.

global.document = { getElementById: () => ({ addEventListener: () => {}, value: "" }) };
global.DOMParser = class { parseFromString() { return { body: { childNodes: [] } }; } };

const corpus = require('./dom-xss-corpus.js');
const jsanalyze = require('../jsanalyze.js');

(async () => {
  const results = [];
  const categories = {};

  for (const tc of corpus) {
    const t0 = Date.now();
    let actual;
    try {
      actual = await jsanalyze.traceTaintInJs(tc.code);
    } catch (e) {
      actual = null;
    }
    const elapsed = Date.now() - t0;

    const actualFindings = actual ? actual.length : 0;
    const expectedFindings = tc.expected.findings;
    const actualSources = actual ? actual.flatMap(f => f.sources).sort() : [];
    const actualSinks = actual ? actual.map(f => f.type) : [];

    let classification;
    if (expectedFindings > 0 && actualFindings > 0) {
      // Check source match if specified
      let sourceMatch = true;
      if (tc.expected.sources) {
        for (const s of tc.expected.sources) {
          if (!actualSources.includes(s)) { sourceMatch = false; break; }
        }
      }
      // Check sink match if specified
      let sinkMatch = true;
      if (tc.expected.sinks) {
        for (const s of tc.expected.sinks) {
          if (!actualSinks.includes(s)) { sinkMatch = false; break; }
        }
      }
      if (sourceMatch && sinkMatch) {
        classification = 'TP';
      } else {
        classification = 'WRONG'; // counts as FP + FN
      }
    } else if (expectedFindings > 0 && actualFindings === 0) {
      classification = 'FN';
    } else if (expectedFindings === 0 && actualFindings === 0) {
      classification = 'TN';
    } else {
      classification = 'FP';
    }

    const r = {
      id: tc.id,
      category: tc.category,
      description: tc.description,
      classification,
      expectedFindings,
      actualFindings,
      actualSources,
      actualSinks,
      elapsed,
    };
    results.push(r);

    if (!categories[tc.category]) categories[tc.category] = { TP: 0, FP: 0, FN: 0, TN: 0, WRONG: 0 };
    categories[tc.category][classification]++;
  }

  // Print per-case results
  console.log('');
  console.log('Per-case results:');
  console.log('─'.repeat(90));
  for (const r of results) {
    const mark = r.classification === 'TP' ? '✓' :
                 r.classification === 'TN' ? '·' :
                 r.classification === 'FN' ? '✗' :
                 r.classification === 'FP' ? '!' :
                 '⚠';
    const pad = r.id.padEnd(8);
    const cls = r.classification.padEnd(5);
    const src = r.actualSources.length ? r.actualSources.join(',') : '-';
    const ms = (r.elapsed + 'ms').padStart(6);
    console.log(`  ${mark} ${pad} ${cls} ${r.description.slice(0, 45).padEnd(45)} ${src.padEnd(20)} ${ms}`);
  }

  // Compute per-category and overall metrics
  console.log('');
  console.log('Per-category metrics:');
  console.log('─'.repeat(70));
  console.log('  Category  TP  FP  FN  TN  Wrong  Precision  Recall   F1');
  console.log('  ────────  ──  ──  ──  ──  ─────  ─────────  ──────   ──');

  let totalTP = 0, totalFP = 0, totalFN = 0, totalTN = 0, totalWrong = 0;
  for (const [cat, c] of Object.entries(categories).sort()) {
    const tp = c.TP + 0;
    const fp = c.FP + c.WRONG;
    const fn = c.FN + c.WRONG;
    const tn = c.TN;
    const precision = (tp + fp) > 0 ? (tp / (tp + fp)) : 1;
    const recall = (tp + fn) > 0 ? (tp / (tp + fn)) : 1;
    const f1 = (precision + recall) > 0 ? (2 * precision * recall / (precision + recall)) : 0;
    console.log(`  ${cat.padEnd(10)}${String(tp).padStart(2)}  ${String(c.FP).padStart(2)}  ${String(c.FN).padStart(2)}  ${String(tn).padStart(2)}  ${String(c.WRONG).padStart(5)}  ${(precision * 100).toFixed(1).padStart(8)}%  ${(recall * 100).toFixed(1).padStart(5)}%  ${(f1 * 100).toFixed(1).padStart(5)}%`);
    totalTP += tp; totalFP += fp; totalFN += fn; totalTN += tn; totalWrong += c.WRONG;
  }

  const overallP = (totalTP + totalFP) > 0 ? (totalTP / (totalTP + totalFP)) : 1;
  const overallR = (totalTP + totalFN) > 0 ? (totalTP / (totalTP + totalFN)) : 1;
  const overallF1 = (overallP + overallR) > 0 ? (2 * overallP * overallR / (overallP + overallR)) : 0;

  console.log('  ────────  ──  ──  ──  ──  ─────  ─────────  ──────   ──');
  console.log(`  ${'OVERALL'.padEnd(10)}${String(totalTP).padStart(2)}  ${String(totalFP - totalWrong).padStart(2)}  ${String(totalFN - totalWrong).padStart(2)}  ${String(totalTN).padStart(2)}  ${String(totalWrong).padStart(5)}  ${(overallP * 100).toFixed(1).padStart(8)}%  ${(overallR * 100).toFixed(1).padStart(5)}%  ${(overallF1 * 100).toFixed(1).padStart(5)}%`);

  console.log('');
  console.log(`Total test cases: ${results.length}`);
  console.log(`  True Positives:  ${totalTP}`);
  console.log(`  True Negatives:  ${totalTN}`);
  console.log(`  False Positives: ${totalFP - totalWrong}`);
  console.log(`  False Negatives: ${totalFN - totalWrong}`);
  console.log(`  Wrong (FP+FN):   ${totalWrong}`);
  console.log('');
  console.log(`Precision: ${(overallP * 100).toFixed(1)}%`);
  console.log(`Recall:    ${(overallR * 100).toFixed(1)}%`);
  console.log(`F1 Score:  ${(overallF1 * 100).toFixed(1)}%`);

  // Exit with non-zero if any FN or WRONG
  const failures = results.filter(r => r.classification === 'FN' || r.classification === 'WRONG' || r.classification === 'FP');
  if (failures.length > 0) {
    console.log('');
    console.log('Failures:');
    for (const f of failures) {
      console.log(`  ${f.id}: ${f.classification} — ${f.description} (expected ${f.expectedFindings}, got ${f.actualFindings}, sources: ${f.actualSources.join(',') || 'none'})`);
    }
  }
  process.exit(failures.length > 0 ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
