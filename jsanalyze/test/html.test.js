// html.test.js — Wave 12 / Phase E coverage for src/html.js.
//
// The HTML literal parser is a hand-rolled tokenizer + tree
// builder focused on the subset the DOM-conversion consumer
// needs: tags with attributes, text nodes, comments, CDATA,
// void elements, and raw-text elements (script/style/textarea/
// title). These tests lock the parser's output shape so the
// consumer can rely on it.

'use strict';

const html = require('../src/html.js');
const { analyze, query } = require('../src/index.js');
const TDB = require('../src/default-typedb.js');
const { assert, assertEqual } = require('./run.js');

function firstElement(node) {
  for (const c of node.children) if (c.type === 'element') return c;
  return null;
}

const tests = [
  // --- Entity decoding ---
  {
    name: 'html: decodeEntities handles named refs',
    fn: () => {
      assertEqual(html.decodeEntities('a &amp; b'), 'a & b');
      assertEqual(html.decodeEntities('&lt;tag&gt;'), '<tag>');
      assertEqual(html.decodeEntities('&quot;hi&quot;'), '"hi"');
      assertEqual(html.decodeEntities('&nbsp;'), '\u00A0');
    },
  },
  {
    name: 'html: decodeEntities handles numeric refs',
    fn: () => {
      assertEqual(html.decodeEntities('&#65;'), 'A');
      assertEqual(html.decodeEntities('&#x41;'), 'A');
      assertEqual(html.decodeEntities('&#x1F600;'), '\u{1F600}');
    },
  },
  {
    name: 'html: decodeEntities leaves unknown refs alone',
    fn: () => {
      // Unknown named ref passes through untouched (legacy-friendly).
      assertEqual(html.decodeEntities('&notanent;'), '&notanent;');
    },
  },

  // --- Tokenizer ---
  {
    name: 'html: tokenize splits text and tags',
    fn: () => {
      const t = html.tokenize('hello<br>world');
      assertEqual(t.length, 3);
      assertEqual(t[0].type, 'text');
      assertEqual(t[0].value, 'hello');
      assertEqual(t[1].type, 'start');
      assertEqual(t[1].tagName, 'br');
      assertEqual(t[2].type, 'text');
    },
  },
  {
    name: 'html: tokenize reads attributes',
    fn: () => {
      const t = html.tokenize('<a href="https://x" target=_blank >');
      assertEqual(t.length, 1);
      assertEqual(t[0].type, 'start');
      assertEqual(t[0].tagName, 'a');
      assertEqual(t[0].attrs.length, 2);
      assertEqual(t[0].attrs[0].name, 'href');
      assertEqual(t[0].attrs[0].value, 'https://x');
      assertEqual(t[0].attrs[1].name, 'target');
      assertEqual(t[0].attrs[1].value, '_blank');
    },
  },
  {
    name: 'html: tokenize self-closing',
    fn: () => {
      const t = html.tokenize('<img src="x.png" />');
      assertEqual(t[0].type, 'self');
      assertEqual(t[0].tagName, 'img');
    },
  },
  {
    name: 'html: tokenize comments',
    fn: () => {
      const t = html.tokenize('a<!-- hi -->b');
      assertEqual(t.length, 3);
      assertEqual(t[1].type, 'comment');
      assertEqual(t[1].value, ' hi ');
    },
  },
  {
    name: 'html: tokenize unterminated comment recovers',
    fn: () => {
      const t = html.tokenize('a<!-- oops');
      assertEqual(t.length, 2);
      assertEqual(t[1].type, 'comment');
    },
  },
  {
    name: 'html: tokenize decodes attribute entities',
    fn: () => {
      const t = html.tokenize('<a title="a &amp; b">');
      assertEqual(t[0].attrs[0].value, 'a & b');
    },
  },

  // --- Tree builder ---
  {
    name: 'html: parse flat text is a single fragment',
    fn: () => {
      const doc = html.parse('hello world');
      assertEqual(doc.type, 'fragment');
      assertEqual(doc.children.length, 1);
      assertEqual(doc.children[0].type, 'text');
      assertEqual(doc.children[0].value, 'hello world');
    },
  },
  {
    name: 'html: parse single element with text',
    fn: () => {
      const doc = html.parse('<p>hi</p>');
      const p = firstElement(doc);
      assertEqual(p.tag, 'p');
      assertEqual(p.children.length, 1);
      assertEqual(p.children[0].type, 'text');
      assertEqual(p.children[0].value, 'hi');
    },
  },
  {
    name: 'html: parse nested elements',
    fn: () => {
      const doc = html.parse('<div><span>x</span><b>y</b></div>');
      const div = firstElement(doc);
      assertEqual(div.tag, 'div');
      assertEqual(div.children.length, 2);
      assertEqual(div.children[0].tag, 'span');
      assertEqual(div.children[1].tag, 'b');
    },
  },
  {
    name: 'html: parse void elements have no children',
    fn: () => {
      const doc = html.parse('<div>a<br>b<img src="x">c</div>');
      const div = firstElement(doc);
      assertEqual(div.children.length, 5);
      assertEqual(div.children[1].tag, 'br');
      assertEqual(div.children[1].children.length, 0);
      assertEqual(div.children[3].tag, 'img');
      assertEqual(div.children[3].attrs.src, 'x');
    },
  },
  {
    name: 'html: parse raw-text script preserves content',
    fn: () => {
      const doc = html.parse('<script>var x = 1 < 2;</script>');
      const s = firstElement(doc);
      assertEqual(s.tag, 'script');
      assertEqual(s.children.length, 1);
      assertEqual(s.children[0].type, 'text');
      assertEqual(s.children[0].value, 'var x = 1 < 2;');
    },
  },
  {
    name: 'html: parse raw-text style preserves content',
    fn: () => {
      const doc = html.parse('<style>a > b { color: red; }</style>');
      const s = firstElement(doc);
      assertEqual(s.tag, 'style');
      assertEqual(s.children[0].value, 'a > b { color: red; }');
    },
  },
  {
    name: 'html: parse implicit close for unmatched end',
    fn: () => {
      const doc = html.parse('<div><span>hi</div>');
      const div = firstElement(doc);
      // The unclosed <span> gets implicitly closed when </div>
      // pops the stack past it.
      assertEqual(div.tag, 'div');
      assertEqual(div.children[0].tag, 'span');
    },
  },
  {
    name: 'html: parse handles attributes with entities',
    fn: () => {
      const doc = html.parse('<a title="&lt;">x</a>');
      const a = firstElement(doc);
      assertEqual(a.attrs.title, '<');
    },
  },
  {
    name: 'html: parse handles doctype',
    fn: () => {
      const doc = html.parse('<!DOCTYPE html><html></html>');
      assertEqual(doc.children.length, 2);
      assertEqual(doc.children[0].type, 'doctype');
    },
  },
  {
    name: 'html: parse handles CDATA',
    fn: () => {
      const doc = html.parse('<svg><![CDATA[<text>foo</text>]]></svg>');
      const svg = firstElement(doc);
      assertEqual(svg.children[0].type, 'text');
      assertEqual(svg.children[0].value, '<text>foo</text>');
    },
  },
  {
    name: 'html: parse deeply nested 500-level does not overflow',
    fn: () => {
      let src = '';
      for (let i = 0; i < 500; i++) src += '<div>';
      for (let i = 0; i < 500; i++) src += '</div>';
      const doc = html.parse(src);
      assertEqual(doc.type, 'fragment');
      // Walk down and count depth.
      let depth = 0;
      let node = doc;
      while (node && node.children && node.children[0] && node.children[0].type === 'element') {
        node = node.children[0];
        depth++;
      }
      assertEqual(depth, 500);
    },
  },

  // --- Serialization round-trip ---
  {
    name: 'html: serialize round-trips a simple tree',
    fn: () => {
      const s = '<div class="x"><p>hi &amp; hello</p></div>';
      const doc = html.parse(s);
      const out = html.serialize(doc);
      // After decode + re-escape, `&amp;` round-trips.
      assertEqual(out, '<div class="x"><p>hi &amp; hello</p></div>');
    },
  },
  {
    name: 'html: serialize void elements drop end tag',
    fn: () => {
      const doc = html.parse('<img src="a.png">');
      assertEqual(html.serialize(doc), '<img src="a.png">');
    },
  },
  {
    name: 'html: serialize escapes < and & in text',
    fn: () => {
      // Construct a tree manually to bypass parsing.
      const node = {
        type: 'fragment',
        children: [{ type: 'text', value: 'a < b & c', loc: { start: 0, end: 0 } }],
        loc: { start: 0, end: 0 },
      };
      assertEqual(html.serialize(node), 'a &lt; b &amp; c');
    },
  },

  // --- Tag/attribute case preservation + token serializer ---
  {
    name: 'html: tokens preserve original tag casing in tagRaw',
    fn: () => {
      const t = html.tokenize('<DIV class="x"></DIV>');
      assertEqual(t[0].tagName, 'div');
      assertEqual(t[0].tagRaw, 'DIV');
      assertEqual(t[1].tagName, 'div');
      assertEqual(t[1].tagRaw, 'DIV');
    },
  },
  {
    name: 'html: tokens preserve original attribute casing in nameRaw',
    fn: () => {
      const t = html.tokenize('<input DataValue="5" AUTOfocus>');
      const a0 = t[0].attrs[0];
      const a1 = t[0].attrs[1];
      assertEqual(a0.name, 'datavalue');
      assertEqual(a0.nameRaw, 'DataValue');
      assertEqual(a1.name, 'autofocus');
      assertEqual(a1.nameRaw, 'AUTOfocus');
    },
  },
  {
    name: 'html: tokens record attribute quoting style',
    fn: () => {
      const t = html.tokenize(`<a href="d" title='t' data-x=bare>`);
      assertEqual(t[0].attrs[0].quoted, '"');
      assertEqual(t[0].attrs[1].quoted, "'");
      assertEqual(t[0].attrs[2].quoted, null);
    },
  },
  {
    name: 'html: serializeTokens round-trips tag with preserved casing',
    fn: () => {
      const t = html.tokenize('<DIV class="x"></DIV>');
      const out = html.serializeTokens(t);
      // Raw case preserved; attribute quote style default to ".
      assertEqual(out, '<DIV class="x"></DIV>');
    },
  },
  {
    name: 'html: serializeTokens attribute mutation',
    fn: () => {
      const t = html.tokenize('<button onclick="go()">Go</button>');
      // Remove the onclick attribute and add data-handler="0".
      t[0].attrs = t[0].attrs.filter(a => a.name !== 'onclick');
      t[0].attrs.push({ name: 'data-handler', nameRaw: 'data-handler', value: '0', quoted: '"' });
      const out = html.serializeTokens(t);
      assertEqual(out, '<button data-handler="0">Go</button>');
    },
  },
  {
    name: 'html: serializeTokens tag rename via tagRaw',
    fn: () => {
      const t = html.tokenize('<style>body{}</style>');
      // Rename style → link, add href attribute (simulate extraction).
      t[0].tagName = 'link';
      t[0].tagRaw = 'link';
      t[0].attrs = [
        { name: 'rel', nameRaw: 'rel', value: 'stylesheet', quoted: '"' },
        { name: 'href', nameRaw: 'href', value: 'out.css', quoted: '"' },
      ];
      // Walk forward and blank out the text + closing tag; style
      // is a raw-text element, so the tokens include TEXT + close.
      // We want `<link rel="stylesheet" href="out.css">` only.
      // Keep the first token (the renamed open) and drop the rest.
      const trimmed = [t[0]];
      const out = html.serializeTokens(trimmed);
      assertEqual(out, '<link rel="stylesheet" href="out.css">');
    },
  },
  {
    name: 'html: serializeTokens escapes special chars in attribute values',
    fn: () => {
      const t = [
        { type: 'start', tagName: 'a', tagRaw: 'a', attrs: [
          { name: 'title', nameRaw: 'title', value: 'a & "b" <c>', quoted: '"' },
        ] },
      ];
      const out = html.serializeTokens(t);
      assertEqual(out, '<a title="a &amp; &quot;b&quot; &lt;c>">');
    },
  },

  // --- Raw-text element coverage ---
  {
    name: 'html: iframe is a raw-text element (content not parsed)',
    fn: () => {
      const doc = html.parse('<iframe><p>fallback &amp; text</p></iframe>');
      const iframe = firstElement(doc);
      assertEqual(iframe.tag, 'iframe');
      // The inner <p> should appear as raw text, NOT as a child element.
      assertEqual(iframe.children.length, 1);
      assertEqual(iframe.children[0].type, 'text');
      assert(iframe.children[0].value.indexOf('<p>') >= 0,
        'iframe content is raw text including the inner tag');
    },
  },
  {
    name: 'html: noscript is a raw-text element',
    fn: () => {
      const doc = html.parse('<noscript><a href="/">x</a></noscript>');
      const ns = firstElement(doc);
      assertEqual(ns.tag, 'noscript');
      assertEqual(ns.children[0].type, 'text');
    },
  },

  // --- Wider entity coverage ---
  {
    name: 'html: decodeEntities handles ported legacy entities',
    fn: () => {
      assertEqual(html.decodeEntities('&mdash;'), '\u2014');
      assertEqual(html.decodeEntities('&ndash;'), '\u2013');
      assertEqual(html.decodeEntities('&ldquo;&rdquo;'), '\u201C\u201D');
      assertEqual(html.decodeEntities('&hellip;'), '\u2026');
      assertEqual(html.decodeEntities('&euro;'), '\u20AC');
      assertEqual(html.decodeEntities('&laquo;&raquo;'), '\u00AB\u00BB');
      assertEqual(html.decodeEntities('&deg;'), '\u00B0');
      assertEqual(html.decodeEntities('&plusmn;'), '\u00B1');
    },
  },

  // --- element tree exposes case + ordered attr list ---
  {
    name: 'html: parsed element has tagRaw and attrList',
    fn: () => {
      const doc = html.parse('<DIV ID="x" CLASS="y">hi</DIV>');
      const div = firstElement(doc);
      assertEqual(div.tag, 'div');
      assertEqual(div.tagRaw, 'DIV');
      assert(Array.isArray(div.attrList), 'attrList present');
      assertEqual(div.attrList.length, 2);
      assertEqual(div.attrList[0].nameRaw, 'ID');
      assertEqual(div.attrList[1].nameRaw, 'CLASS');
    },
  },

  // --- End-to-end: innerHTML extraction pipeline ---
  {
    name: 'html e2e: innerHTML assignment recorded on trace',
    fn: async () => {
      const t = await analyze(
        'document.body.innerHTML = "<p>hi</p>";',
        { typeDB: TDB });
      const assigns = query.innerHtmlAssignments(t);
      assertEqual(assigns.length, 1);
      assertEqual(assigns[0].kind, 'innerHTML');
      assert(assigns[0].targetType, 'targetType is set');
      assertEqual(assigns[0].value.kind, 'concrete');
      assertEqual(assigns[0].value.value, '<p>hi</p>');
    },
  },
  {
    name: 'html e2e: concrete innerHTML parses into a tree',
    fn: async () => {
      const t = await analyze(
        'document.body.innerHTML = "<div class=\\"box\\">hi <b>bold</b></div>";',
        { typeDB: TDB });
      const assigns = query.innerHtmlAssignments(t);
      assertEqual(assigns.length, 1);
      const tree = html.parse(assigns[0].value.value);
      assertEqual(tree.type, 'fragment');
      const div = tree.children[0];
      assertEqual(div.type, 'element');
      assertEqual(div.tag, 'div');
      assertEqual(div.attrs.class, 'box');
      // <div>hi <b>bold</b></div> → text("hi ") + <b>bold</b>
      assertEqual(div.children.length, 2);
      assertEqual(div.children[0].type, 'text');
      assertEqual(div.children[0].value, 'hi ');
      assertEqual(div.children[1].type, 'element');
      assertEqual(div.children[1].tag, 'b');
    },
  },
  {
    name: 'html e2e: tainted innerHTML carries labels on the assignment record',
    fn: async () => {
      const t = await analyze(
        'document.body.innerHTML = location.hash;',
        { typeDB: TDB });
      const assigns = query.innerHtmlAssignments(t);
      assertEqual(assigns.length, 1);
      // The assigned value is an opaque tainted string — the
      // consumer sees it's not concrete and falls back to a
      // runtime-guarded rewrite.
      assert(assigns[0].value.kind !== 'concrete',
        'tainted value is not concrete');
      assert(assigns[0].labels.indexOf('url') >= 0,
        'url label is surfaced on the assignment record');
    },
  },
  {
    name: 'html e2e: multi-file analysis collects all innerHTML sites',
    fn: async () => {
      const t = await analyze({
        'a.js': 'document.body.innerHTML = "<p>A</p>";',
        'b.js': 'document.body.innerHTML = "<p>B</p>";',
      }, { typeDB: TDB });
      const assigns = query.innerHtmlAssignments(t);
      assertEqual(assigns.length, 2);
    },
  },
  {
    name: 'html e2e: non-html sinks are NOT recorded as innerHtmlAssignments',
    fn: async () => {
      // Setting a.href is a navigation sink, not an html sink,
      // so it must not appear in innerHtmlAssignments.
      const t = await analyze(
        'var a = document.createElement("a"); a.href = "https://x";',
        { typeDB: TDB });
      const assigns = query.innerHtmlAssignments(t);
      assertEqual(assigns.length, 0);
    },
  },
];

module.exports = { tests };
