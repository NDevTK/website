// state-channel.test.js — cross-handler shared state.
//
// Two channels that used to be invisible to the whole-program
// fixpoint, both listed as open gaps in the README:
//
//   1. Symbolic heap values. The lattice knew a module global
//      could be `true`, but not WHY, so a PoC omitted the input
//      that made it true.
//
//   2. The DOM as a state channel. Elements were unwritable
//      opaques, so `el.dataset.x = tainted` followed by a read
//      elsewhere carried no taint at all.

'use strict';

const assert = require('assert');
const { analyze } = require('../src/index.js');
const tr = require('../consumers/taint-report.js');
const D = require('../src/domain.js');
const SMT = require('../src/smt.js');

function assertEqual(actual, expected, msg) {
  assert.strictEqual(actual, expected, msg);
}

const CROSS_HANDLER =
  'var state = {active:false};' +
  'window.addEventListener("message", function(a) {' +
  '  if (a.data === "flip") state.active = true;' +
  '});' +
  'window.addEventListener("message", function(b) {' +
  '  if (state.active && b.data.code) eval(b.data.code);' +
  '});';

const tests = [
  // --- mkIte ----------------------------------------------------------
  {
    name: 'smt: ite folds a boolean flag back to its guard',
    fn: async () => {
      const p = SMT.mkCmp('===', SMT.mkSym('d', 'String'), SMT.mkConst('flip'));
      const folded = SMT.mkIte(p, SMT.mkConst(true), SMT.mkConst(false));
      assertEqual(folded.expr, p.expr, 'ite(P, true, false) collapses to P');
      assertEqual(folded.isBool, true, 'result is a Bool expression');
    },
  },
  {
    name: 'smt: ite with swapped branches is the negated guard',
    fn: async () => {
      const p = SMT.mkCmp('===', SMT.mkSym('d', 'String'), SMT.mkConst('flip'));
      const folded = SMT.mkIte(p, SMT.mkConst(false), SMT.mkConst(true));
      assertEqual(folded.expr, '(not ' + p.expr + ')', 'negated guard');
    },
  },
  {
    name: 'smt: ite on a concrete condition picks the branch',
    fn: async () => {
      const t = SMT.mkIte(SMT.mkConst(true), SMT.mkConst('a'), SMT.mkConst('b'));
      const f = SMT.mkIte(SMT.mkConst(false), SMT.mkConst('a'), SMT.mkConst('b'));
      assertEqual(t.value.val, 'a', 'true condition takes the then branch');
      assertEqual(f.value.val, 'b', 'false condition takes the else branch');
    },
  },
  {
    name: 'smt: ite keeps a symbolic branch solvable',
    fn: async () => {
      const p = SMT.mkCmp('===', SMT.mkSym('k', 'String'), SMT.mkConst('go'));
      const ite = SMT.mkIte(p, SMT.mkSym('v', 'String'), SMT.mkConst(''));
      assert.ok(SMT.hasSym(ite), 'formula still references its symbols');
      assertEqual(ite.sorts.v, 'String', 'sym branch adopts the String sort');
      assertEqual(ite.stringResult, true, 'result is String-sorted');
    },
  },

  // --- Symbolic heap values -------------------------------------------
  {
    name: 'gatherStates keeps a callback\'s symbolic denotation for a heap cell',
    fn: async () => {
      // Persisted: g.ready = false, unconditionally reachable.
      // Callback exit: g.ready = true under a symbolic guard.
      const guard = SMT.mkCmp('===', SMT.mkSym('d', 'String'), SMT.mkConst('flip'));
      let persisted = D.createState();
      persisted = writeCell(persisted, 1, 'ready', D.concrete(false));
      let exit = D.createState();
      exit = writeCell(exit, 1, 'ready',
        D.withFormula(D.concrete(true), guard));
      exit = D.withPath(exit, guard);

      const plain = D.joinStates(persisted, exit);
      assert.ok(!D.overlayGet(plain.heap, 1).fields.ready.formula,
        'a plain join drops the guard (the behaviour that lost the link)');

      const gathered = D.gatherStates(persisted, exit);
      const cell = D.overlayGet(gathered.heap, 1).fields.ready;
      assert.ok(cell.formula, 'the gather keeps a formula on the merged cell');
      assertEqual(cell.formula.expr, guard.expr, 'and it is the callback guard');
      assertEqual(cell.kind, D.V.ONE_OF,
        'the lattice element is still the plain join — precision only');
    },
  },
  {
    name: 'fixpoint: cross-handler guard reaches the sink path condition',
    fn: async () => {
      const trace = await analyze(CROSS_HANDLER);
      const flow = trace.taintFlows.find(f => f.sink && f.sink.kind === 'code');
      assert.ok(flow, 'eval flow emitted');
      assert.ok(flow.pathFormula, 'flow carries a path condition');
      assert.ok(/flip/.test(flow.pathFormula.expr),
        'path condition names the value the OTHER handler must receive; got ' +
        flow.pathFormula.expr);
    },
  },
  {
    name: 'symbolTable attributes each symbol to its handler and delivery',
    fn: async () => {
      const trace = await analyze(CROSS_HANDLER);
      const names = Object.keys(trace.symbolTable);
      assert.ok(names.length >= 2, 'both handlers minted symbols');
      const fnIds = new Set();
      for (const n of names) {
        const e = trace.symbolTable[n];
        assertEqual(e.label, 'postMessage', 'label recorded for ' + n);
        assertEqual(e.delivery, 'postMessage:data', 'delivery recorded for ' + n);
        assert.ok(e.handlerContext && e.handlerContext.event === 'message',
          'handler context recorded for ' + n);
        fnIds.add(e.fnId);
      }
      assert.ok(fnIds.size >= 2,
        'symbols from two different handlers are distinguishable');
    },
  },
  {
    name: 'PoC lists the prerequisite message and delivers it first',
    fn: async () => {
      const report = await tr.analyze(CROSS_HANDLER);
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'code');
      assert.ok(flow && flow.poc, 'flow has a PoC');
      assertEqual(flow.poc.verdict, 'synthesised');
      // The flow's own binding is still the payload it evals.
      assert.deepStrictEqual(flow.poc.bindings.postMessage, { code: 'alert(1)' },
        'own binding is the eval payload');
      // The other handler's input is a prerequisite, not a binding
      // — collapsing both onto the `postMessage` key would drop one
      // of the two messages the exploit needs.
      assertEqual(flow.poc.prerequisites.length, 1, 'one prerequisite');
      const p = flow.poc.prerequisites[0];
      assertEqual(p.value, 'flip', 'prerequisite value solved by Z3');
      assertEqual(p.delivery, 'postMessage:data', 'prerequisite delivery');
      assertEqual(p.handlerContext.event, 'message', 'prerequisite handler');
      // Ordering matters: flip must be posted before the payload.
      const repro = flow.poc.reproducer;
      assert.ok(repro, 'reproducer emitted');
      const iFlip = repro.indexOf('postMessage("flip"');
      const iPayload = repro.indexOf('postMessage({"code"');
      assert.ok(iFlip >= 0, 'reproducer posts the prerequisite');
      assert.ok(iPayload >= 0, 'reproducer posts the payload');
      assert.ok(iFlip < iPayload, 'prerequisite is delivered first');
      new Function(repro);   // parse-valid
    },
  },
  {
    name: 'same-handler path guard stays a binding, not a prerequisite',
    fn: async () => {
      // Regression guard for the own-vs-prerequisite split: both
      // `action` and `payload` are fields of the SAME event, so
      // the attacker supplies one object, not two messages.
      const report = await tr.analyze(
        'window.addEventListener("message", function(ev) {' +
        '  if (ev.data.action === "run") eval(ev.data.payload);' +
        '});');
      const flow = report.flows.find(f => f.sink && f.sink.kind === 'code');
      assert.ok(flow && flow.poc, 'flow has a PoC');
      assertEqual(flow.poc.prerequisites.length, 0, 'no prerequisites');
      assertEqual(flow.poc.bindings.postMessage.action, 'run');
      assertEqual(flow.poc.bindings.postMessage.payload, 'alert(1)');
    },
  },

  // --- DOM as a state channel -----------------------------------------
  {
    name: 'dom-state: dataset write in one handler reaches a sink in another',
    fn: async () => {
      const trace = await analyze(
        'window.addEventListener("message", function(a) {' +
        '  document.getElementById("o").dataset.token = a.data;' +
        '});' +
        'window.addEventListener("click", function() {' +
        '  eval(document.getElementById("o").dataset.token);' +
        '});');
      const flow = trace.taintFlows.find(f => f.sink && f.sink.kind === 'code');
      assert.ok(flow, 'the DOM round-trip carries taint to the eval sink');
      assert.ok(flow.source.some(s => s.label === 'postMessage'),
        'taint is attributed to the message that wrote the dataset entry');
    },
  },
  {
    name: 'dom-state: setAttribute / getAttribute round-trips taint',
    fn: async () => {
      const trace = await analyze(
        'var el = document.getElementById("o");' +
        'el.setAttribute("data-x", location.hash);' +
        'document.body.innerHTML = el.getAttribute("data-x");');
      const flow = trace.taintFlows.find(f => f.sink && f.sink.prop === 'innerHTML');
      assert.ok(flow, 'attribute round-trip reaches the html sink');
      assert.ok(flow.source.some(s => s.label === 'url'),
        'source is the URL fragment written into the attribute');
    },
  },
  {
    name: 'dom-state: document.body is a singleton identity',
    fn: async () => {
      const trace = await analyze(
        'document.body.dataset.v = location.hash;' +
        'eval(document.body.dataset.v);');
      const flow = trace.taintFlows.find(f => f.sink && f.sink.kind === 'code');
      assert.ok(flow, 'two reads of document.body denote the same element');
    },
  },
  {
    name: 'dom-state: distinct ids are distinct cells',
    fn: async () => {
      const trace = await analyze(
        'document.getElementById("a").dataset.v = location.hash;' +
        'eval(document.getElementById("b").dataset.v);');
      const flow = trace.taintFlows.find(f => f.sink && f.sink.kind === 'code');
      assert.ok(!flow,
        'a write to #a must not be observable through #b');
    },
  },
  {
    name: 'dom-state: an unresolvable selector stays untracked',
    fn: async () => {
      // The engine cannot say WHICH element a computed selector
      // denotes, so it must not pretend to track it. The write
      // still raises heap-escape, as before.
      const trace = await analyze(
        'var el = document.querySelector(sel);' +
        'el.dataset.v = location.hash;' +
        'eval(el.dataset.v);');
      const flow = trace.taintFlows.find(f => f.sink && f.sink.kind === 'code');
      assert.ok(!flow, 'no flow is claimed through an unidentified element');
      assert.ok(trace.assumptions.some(a => a.reason === 'heap-escape'),
        'the untracked write is still recorded as a soundness gap');
    },
  },
  {
    name: 'dom-state: an unwritten key still reads back opaque',
    fn: async () => {
      // Tracking adds the writes we can prove; it does not claim
      // the analyzed program is the only writer.
      const trace = await analyze(
        'document.getElementById("o").dataset.other = "safe";' +
        'document.body.innerHTML = document.getElementById("o").dataset.token;');
      const flow = trace.taintFlows.find(f => f.sink && f.sink.prop === 'innerHTML');
      assert.ok(!flow || flow.source.length === 0 ||
        !flow.source.some(s => s.label === 'url'),
        'an unwritten key does not inherit another key\'s value');
    },
  },
];

// Write a field into a fresh heap cell, mirroring what
// transfer.writeHeapField does, without importing the whole
// transfer module.
function writeCell(state, objId, field, value) {
  const fields = Object.create(null);
  fields[field] = value;
  const cell = Object.freeze({
    kind: 'object', fields: Object.freeze(fields),
    typeName: null, origin: null,
  });
  return D.withHeap(state, { own: new Map([[objId, cell]]), parent: state.heap });
}

module.exports = { tests };
