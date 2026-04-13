// try.test.js — Wave 4 regression coverage.
//
// Wave 4 lands try/catch/finally + throw. The CFG approximation:
// every statement in the try body may throw, so the try-exit
// terminator is a Branch(opaqueCond, catchBlock, normalTarget)
// forcing the worklist to visit both paths. Catch body is
// lowered in the catch block with the param bound as an
// opaque. Finally runs on every exit path (try-normal + catch).
// The merge block phi-joins the try-exit and catch-exit scopes
// for every name whose binding differs.
//
// Throw routes to the enclosing catch via ctx._catchStack; an
// uncaught throw terminates the current path with a THROW
// terminator.

'use strict';

const { analyze } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { buildModule, OP } = require('../src/ir.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'Wave4: simple try/catch parses and lowers',
    fn: async () => {
      const t = await analyze('try { var x = 1; } catch (e) { var y = 2; }', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave4: try with finally parses',
    fn: async () => {
      const t = await analyze('try { x = 1; } finally { y = 2; }', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave4: try/catch/finally all three parse',
    fn: async () => {
      const t = await analyze('try { x = 1; } catch (e) { y = 2; } finally { z = 3; }', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave4: optional catch-binding (ES2019) parses',
    fn: async () => {
      const t = await analyze('try { x = 1; } catch { y = 2; }', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },

  {
    name: 'Wave4: tainted source in try flows past try/catch',
    fn: async () => {
      const t = await analyze(
        'var x = "safe"; try { x = location.hash; } catch (e) { x = "err"; } document.body.innerHTML = x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave4: tainted source in catch flows past try/catch',
    fn: async () => {
      const t = await analyze(
        'var x = "safe"; try { x = "ok"; } catch (e) { x = location.hash; } document.body.innerHTML = x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave4: both try and catch clean → no flow',
    fn: async () => {
      const t = await analyze(
        'var x; try { x = "a"; } catch (e) { x = "b"; } document.body.innerHTML = x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 0);
    },
  },
  {
    name: 'Wave4: finally runs on all exits',
    fn: async () => {
      const t = await analyze(
        'var x = "safe"; try { x = "ok"; } catch (e) { x = "err"; } finally { x = location.hash; } document.body.innerHTML = x;',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave4: throw inside try routes to catch',
    fn: async () => {
      // The catch param is opaque so the exception value is
      // conservatively untracked; but the throw routes to the
      // catch block and its body runs.
      const t = await analyze(
        'try { throw location.hash; } catch (e) { var y = 2; }', { typeDB: TDB });
      assertEqual(t.partial, false);
    },
  },
  {
    name: 'Wave4: nested try/catch preserves per-level routing',
    fn: async () => {
      const t = await analyze(
        'try { try { x = location.hash; } catch (e1) { x = "inner-err"; } document.body.innerHTML = x; } catch (e2) { document.body.innerHTML = "outer"; }',
        { typeDB: TDB });
      assertEqual(t.taintFlows.length, 1);
    },
  },
  {
    name: 'Wave4: try body produces a Branch terminator, not a Jump',
    fn: () => {
      // The try-exit branch is how we force the worklist to
      // reach the catch block. Verify the shape.
      const m = buildModule('try { x = 1; } catch (e) { y = 2; }', 'a.js');
      let hasBranchToCatch = false;
      for (const [, b] of m.top.cfg.blocks) {
        if (b.terminator && b.terminator.op === OP.BRANCH) {
          hasBranchToCatch = true;
          break;
        }
      }
      assert(hasBranchToCatch, 'a Branch terminator exists (try-exit)');
    },
  },
];

module.exports = { tests };
