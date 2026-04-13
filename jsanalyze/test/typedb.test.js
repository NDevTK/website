'use strict';

const T = require('../src/typedb.js');
const db = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

const tests = [
  // --- default-typedb shape ---
  {
    name: 'default-typedb: loads with expected size',
    fn: () => {
      assert(typeof db === 'object');
      assert(Object.keys(db.types).length >= 80, 'at least 80 types');
      assert(Object.keys(db.roots).length >= 30, 'at least 30 roots');
      assert(Object.keys(db.tagMap).length >= 15, 'at least 15 tagMap entries');
      assert(Object.keys(db.eventMap).length >= 15, 'at least 15 eventMap entries');
      assert(Object.keys(db.attrSinks).length >= 20, 'at least 20 attrSinks');
    },
  },
  {
    name: 'default-typedb: createElement returnType.map wired from tagMap',
    fn: () => {
      const map = db.types.Document.methods.createElement.returnType.map;
      for (const tag in db.tagMap) {
        assertEqual(map[tag], db.tagMap[tag], 'tag ' + tag + ' should match');
      }
    },
  },
  {
    name: 'default-typedb: setAttribute sinkIfArgEquals shares attrSinks identity',
    fn: () => {
      assertEqual(
        db.types.Element.methods.setAttribute.args[0].sinkIfArgEquals.values,
        db.attrSinks,
      );
    },
  },

  // --- lookupProp / lookupMethod ---
  {
    name: 'lookupProp: declared prop',
    fn: () => {
      const d = T.lookupProp(db, 'Location', 'hash');
      assert(d, 'Location.hash should exist');
      assertEqual(d.source, 'url');
    },
  },
  {
    name: 'lookupProp: inherited prop',
    fn: () => {
      // HTMLIFrameElement extends HTMLElement extends Element.
      // innerHTML is declared on HTMLElement.
      const d = T.lookupProp(db, 'HTMLIFrameElement', 'innerHTML');
      assert(d, 'inherited innerHTML should resolve');
      assertEqual(d.sink, 'html');
    },
  },
  {
    name: 'lookupProp: missing prop returns null',
    fn: () => {
      assertEqual(T.lookupProp(db, 'HTMLElement', 'nonexistentProperty'), null);
    },
  },
  {
    name: 'lookupMethod: inherited method',
    fn: () => {
      // HTMLElement inherits addEventListener from EventTarget.
      const m = T.lookupMethod(db, 'HTMLElement', 'addEventListener');
      assert(m, 'inherited method should resolve');
    },
  },
  {
    name: 'lookupMethod: missing method returns null',
    fn: () => {
      assertEqual(T.lookupMethod(db, 'String', 'nonexistentMethod'), null);
    },
  },

  // --- resolveReturnType ---
  {
    name: 'resolveReturnType: static string',
    fn: () => {
      assertEqual(T.resolveReturnType({ returnType: 'Element' }, []), 'Element');
    },
  },
  {
    name: 'resolveReturnType: dynamic fromArg match',
    fn: () => {
      const desc = { returnType: { fromArg: 0, map: { iframe: 'HTMLIFrameElement' }, default: 'HTMLElement' } };
      assertEqual(T.resolveReturnType(desc, ['iframe']), 'HTMLIFrameElement');
    },
  },
  {
    name: 'resolveReturnType: dynamic fromArg miss falls to default',
    fn: () => {
      const desc = { returnType: { fromArg: 0, map: { iframe: 'HTMLIFrameElement' }, default: 'HTMLElement' } };
      assertEqual(T.resolveReturnType(desc, ['unknown']), 'HTMLElement');
    },
  },
  {
    name: 'resolveReturnType: no returnType',
    fn: () => {
      assertEqual(T.resolveReturnType({}, []), null);
    },
  },

  // --- defaultSinkSeverity ---
  {
    name: 'defaultSinkSeverity: all sink kinds mapped',
    fn: () => {
      assertEqual(T.defaultSinkSeverity('code'), 'critical');
      assertEqual(T.defaultSinkSeverity('html'), 'high');
      assertEqual(T.defaultSinkSeverity('url'), 'high');
      assertEqual(T.defaultSinkSeverity('navigation'), 'high');
      assertEqual(T.defaultSinkSeverity('css'), 'medium');
      assertEqual(T.defaultSinkSeverity('safe'), 'safe');
      assertEqual(T.defaultSinkSeverity('text'), 'safe');
    },
  },

  // --- sinkInfoFromPropDescriptor ---
  {
    name: 'sinkInfoFromPropDescriptor: non-sink returns null',
    fn: () => {
      assertEqual(T.sinkInfoFromPropDescriptor({ readType: 'String' }, 'hash'), null);
    },
  },
  {
    name: 'sinkInfoFromPropDescriptor: safe severity returns null',
    fn: () => {
      assertEqual(T.sinkInfoFromPropDescriptor({ sink: 'text' }, 'textContent'), null);
    },
  },
  {
    name: 'sinkInfoFromPropDescriptor: real sink shape',
    fn: () => {
      const info = T.sinkInfoFromPropDescriptor({ sink: 'html' }, 'innerHTML', 'div');
      assertEqual(info.type, 'html');
      assertEqual(info.severity, 'high');
      assertEqual(info.prop, 'innerHTML');
      assertEqual(info.elementTag, 'div');
    },
  },
  {
    name: 'sinkInfoFromPropDescriptor: explicit severity overrides default',
    fn: () => {
      const info = T.sinkInfoFromPropDescriptor({ sink: 'html', severity: 'medium' }, 'innerHTML');
      assertEqual(info.severity, 'medium');
    },
  },

  // --- classifySinkByTypeViaDB ---
  {
    name: 'classifySinkByTypeViaDB: iframe.src is url sink',
    fn: () => {
      const info = T.classifySinkByTypeViaDB(db, 'HTMLIFrameElement', 'src');
      assertEqual(info.type, 'url');
    },
  },
  {
    name: 'classifySinkByTypeViaDB: iframe.innerHTML inherits',
    fn: () => {
      const info = T.classifySinkByTypeViaDB(db, 'HTMLIFrameElement', 'innerHTML');
      assertEqual(info.type, 'html');
    },
  },

  // --- classifySinkViaDB (tag-based) ---
  {
    name: 'classifySinkViaDB: iframe.src by tag',
    fn: () => {
      const info = T.classifySinkViaDB(db, 'src', 'iframe');
      assertEqual(info.type, 'url');
      assertEqual(info.elementTag, 'iframe');
    },
  },
  {
    name: 'classifySinkViaDB: innerHTML without tag falls back to HTMLElement',
    fn: () => {
      const info = T.classifySinkViaDB(db, 'innerHTML', null);
      assertEqual(info.type, 'html');
    },
  },

  // --- classifyAttrSinkViaDB ---
  {
    name: 'classifyAttrSinkViaDB: onclick is code sink',
    fn: () => {
      const info = T.classifyAttrSinkViaDB(db, 'onclick');
      assertEqual(info.type, 'code');
    },
  },
  {
    name: 'classifyAttrSinkViaDB: case-insensitive',
    fn: () => {
      const info = T.classifyAttrSinkViaDB(db, 'ONCLICK');
      assertEqual(info.type, 'code');
    },
  },
  {
    name: 'classifyAttrSinkViaDB: non-sink attribute',
    fn: () => {
      assertEqual(T.classifyAttrSinkViaDB(db, 'data-foo'), null);
    },
  },

  // --- propIsEverASink ---
  {
    name: 'propIsEverASink: known sink prop',
    fn: () => {
      assert(T.propIsEverASink(db, 'innerHTML'));
      assert(T.propIsEverASink(db, 'src'));
    },
  },
  {
    name: 'propIsEverASink: non-sink prop',
    fn: () => {
      assert(!T.propIsEverASink(db, 'nonexistentProp'));
    },
  },

  // --- splitDottedExpr ---
  {
    name: 'splitDottedExpr: plain dotted',
    fn: () => {
      const parts = T.splitDottedExpr('a.b.c');
      assertEqual(parts.length, 3);
      assertEqual(parts[0], 'a');
      assertEqual(parts[1], 'b');
      assertEqual(parts[2], 'c');
    },
  },
  {
    name: 'splitDottedExpr: respects quoted dots',
    fn: () => {
      const parts = T.splitDottedExpr('a.b(".x").c');
      assertEqual(parts.length, 3);
      assertEqual(parts[1], 'b(".x")');
    },
  },
  {
    name: 'splitDottedExpr: respects bracket nesting',
    fn: () => {
      const parts = T.splitDottedExpr('a[b.c].d');
      assertEqual(parts.length, 2);
      assertEqual(parts[0], 'a[b.c]');
    },
  },

  // --- walkPathInDB (sources) ---
  {
    name: 'walkPathInDB: location.hash → url',
    fn: () => assertEqual(T.walkPathInDB(db, 'location.hash'), 'url'),
  },
  {
    name: 'walkPathInDB: document.cookie → cookie',
    fn: () => assertEqual(T.walkPathInDB(db, 'document.cookie'), 'cookie'),
  },
  {
    name: 'walkPathInDB: document.referrer → referrer',
    fn: () => assertEqual(T.walkPathInDB(db, 'document.referrer'), 'referrer'),
  },
  {
    name: 'walkPathInDB: localStorage selfSource',
    fn: () => assertEqual(T.walkPathInDB(db, 'localStorage'), 'storage'),
  },
  {
    name: 'walkPathInDB: prefix-match — location.hash.slice still yields url',
    fn: () => assertEqual(T.walkPathInDB(db, 'location.hash.slice'), 'url'),
  },
  {
    name: 'walkPathInDB: unknown root returns null',
    fn: () => assertEqual(T.walkPathInDB(db, 'unknownGlobal.field'), null),
  },
  {
    name: 'walkPathInDB: shadowed root aborts',
    fn: () => {
      const shadow = name => name === 'location' ? { shadowed: true } : null;
      assertEqual(T.walkPathInDB(db, 'location.hash', shadow), null);
    },
  },

  // --- classifyCallSinkViaDB ---
  {
    name: 'classifyCallSinkViaDB: eval is code sink',
    fn: () => {
      const info = T.classifyCallSinkViaDB(db, 'eval');
      assertEqual(info.type, 'code');
    },
  },
  {
    name: 'classifyCallSinkViaDB: document.write is html sink',
    fn: () => {
      const info = T.classifyCallSinkViaDB(db, 'document.write');
      assertEqual(info.type, 'html');
    },
  },
  {
    name: 'classifyCallSinkViaDB: location.assign is navigation sink',
    fn: () => {
      const info = T.classifyCallSinkViaDB(db, 'location.assign');
      assertEqual(info.type, 'navigation');
    },
  },
  {
    name: 'classifyCallSinkViaDB: non-sink call returns null',
    fn: () => {
      assertEqual(T.classifyCallSinkViaDB(db, 'Math.floor'), null);
    },
  },

  // --- isNavSinkViaDB ---
  {
    name: 'isNavSinkViaDB: location.href',
    fn: () => assert(T.isNavSinkViaDB(db, 'location.href')),
  },
  {
    name: 'isNavSinkViaDB: window.location.href (chained)',
    fn: () => assert(T.isNavSinkViaDB(db, 'window.location.href')),
  },
  {
    name: 'isNavSinkViaDB: location.assign (method)',
    fn: () => assert(T.isNavSinkViaDB(db, 'location.assign')),
  },
  {
    name: 'isNavSinkViaDB: innerHTML (non-nav)',
    fn: () => assert(!T.isNavSinkViaDB(db, 'document.body.innerHTML')),
  },

  // --- isSanitizerCallViaDB ---
  {
    name: 'isSanitizerCallViaDB: encodeURIComponent',
    fn: () => assert(T.isSanitizerCallViaDB(db, 'encodeURIComponent')),
  },
  {
    name: 'isSanitizerCallViaDB: parseInt',
    fn: () => assert(T.isSanitizerCallViaDB(db, 'parseInt')),
  },
  {
    name: 'isSanitizerCallViaDB: eval is not a sanitizer',
    fn: () => assert(!T.isSanitizerCallViaDB(db, 'eval')),
  },
  {
    name: 'isSanitizerCallViaDB: decodeURIComponent is not a sanitizer',
    fn: () => assert(!T.isSanitizerCallViaDB(db, 'decodeURIComponent')),
  },

  // --- resolveExprTypeViaDB ---
  {
    name: 'resolveExprTypeViaDB: location',
    fn: () => assertEqual(T.resolveExprTypeViaDB(db, 'location'), 'Location'),
  },
  {
    name: 'resolveExprTypeViaDB: window.location chain',
    fn: () => assertEqual(T.resolveExprTypeViaDB(db, 'window.location'), 'Location'),
  },
  {
    name: 'resolveExprTypeViaDB: document.body',
    fn: () => assertEqual(T.resolveExprTypeViaDB(db, 'document.body'), 'HTMLElement'),
  },
  {
    name: 'resolveExprTypeViaDB: new FileReader()',
    fn: () => assertEqual(T.resolveExprTypeViaDB(db, 'new FileReader()'), 'FileReader'),
  },

  // --- resolveInnerTypeViaDB ---
  {
    name: 'resolveInnerTypeViaDB: fetch() → Response',
    fn: () => assertEqual(T.resolveInnerTypeViaDB(db, 'fetch()'), 'Response'),
  },
  {
    name: 'resolveInnerTypeViaDB: non-parametric returns null',
    fn: () => assertEqual(T.resolveInnerTypeViaDB(db, 'location.hash'), null),
  },

  // --- typeLUB ---
  {
    name: 'typeLUB: same type',
    fn: () => assertEqual(T.typeLUB(db, 'HTMLElement', 'HTMLElement'), 'HTMLElement'),
  },
  {
    name: 'typeLUB: sibling HTML elements share HTMLElement',
    fn: () => assertEqual(T.typeLUB(db, 'HTMLIFrameElement', 'HTMLScriptElement'), 'HTMLElement'),
  },
  {
    name: 'typeLUB: subtype + base = base',
    fn: () => assertEqual(T.typeLUB(db, 'HTMLAnchorElement', 'HTMLElement'), 'HTMLElement'),
  },
];

module.exports = { tests };
