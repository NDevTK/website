// csp-derive.test.js — consumers/csp-derive.js regression coverage.

'use strict';

const csp = require('../consumers/csp-derive.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  {
    name: 'csp: baseline clean bundle gets self for everything',
    fn: async () => {
      const policy = await csp.derive('var x = 1;');
      assert(policy['script-src'].indexOf("'self'") >= 0,
        'script-src has self');
      assert(policy['connect-src'].indexOf("'self'") >= 0);
      assert(policy['img-src'].indexOf("'self'") >= 0);
      assert(policy['style-src'].indexOf("'self'") >= 0);
      assertEqual(policy['report-unsafe-inline'], false);
      assertEqual(policy['report-unsafe-eval'], false);
    },
  },
  {
    name: 'csp: fetch call origin feeds connect-src',
    fn: async () => {
      const policy = await csp.derive(
        'fetch("https://api.example.com/users");');
      assert(policy['connect-src'].indexOf('https://api.example.com') >= 0,
        'api origin in connect-src: ' + JSON.stringify(policy['connect-src']));
    },
  },
  {
    name: 'csp: new WebSocket origin feeds connect-src',
    fn: async () => {
      const policy = await csp.derive(
        'var ws = new WebSocket("wss://live.example.com/feed");');
      assert(policy['connect-src'].some(s => s.indexOf('live.example.com') >= 0),
        'ws origin in connect-src: ' + JSON.stringify(policy['connect-src']));
    },
  },
  {
    name: 'csp: eval flags report-unsafe-eval',
    fn: async () => {
      const policy = await csp.derive('eval("1+1");');
      assertEqual(policy['report-unsafe-eval'], true);
    },
  },
  {
    name: 'csp: Function constructor flags report-unsafe-eval',
    fn: async () => {
      const policy = await csp.derive('var f = new Function("return 1");');
      assertEqual(policy['report-unsafe-eval'], true);
    },
  },
  {
    name: 'csp: setTimeout with string arg flags report-unsafe-eval',
    fn: async () => {
      const policy = await csp.derive('setTimeout("doThing()", 100);');
      assertEqual(policy['report-unsafe-eval'], true);
    },
  },
  {
    name: 'csp: setTimeout with function arg does NOT flag unsafe-eval',
    fn: async () => {
      const policy = await csp.derive(
        'setTimeout(function() { doThing(); }, 100);');
      assertEqual(policy['report-unsafe-eval'], false);
    },
  },
  {
    name: 'csp: innerHTML assignment flags report-unsafe-inline',
    fn: async () => {
      const policy = await csp.derive(
        'document.body.innerHTML = "<p>hi</p>";');
      assertEqual(policy['report-unsafe-inline'], true);
    },
  },
  {
    name: 'csp: originOf parses https URLs',
    fn: () => {
      assertEqual(csp.originOf('https://x.com/a/b'), 'https://x.com');
      assertEqual(csp.originOf('http://x.com:8080/a'), 'http://x.com:8080');
      assertEqual(csp.originOf('wss://live.x.com/feed'), 'wss://live.x.com');
    },
  },
  {
    name: 'csp: originOf handles special schemes',
    fn: () => {
      assertEqual(csp.originOf('data:text/plain,hi'), 'data:');
      assertEqual(csp.originOf('blob:https://x.com/abc'), 'blob:');
    },
  },
  {
    name: 'csp: originOf returns null for relative paths',
    fn: () => {
      assertEqual(csp.originOf('/api/users'), null);
      assertEqual(csp.originOf('users'), null);
    },
  },
];

module.exports = { tests };
