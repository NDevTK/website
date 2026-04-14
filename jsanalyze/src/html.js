// html.js — HTML literal parser (Wave 12 / Phase E, D10)
//
// A focused HTML tokenizer + tree builder for the subset the
// DOM-conversion consumer needs:
//
//   * Start / end tags with attributes and self-close `/>`
//   * Text nodes (including entity references)
//   * Comments (`<!-- ... -->`)
//   * CDATA (`<![CDATA[ ... ]]>`) — passed through as text
//   * Void elements (area, base, br, col, embed, hr, img,
//     input, link, meta, param, source, track, wbr) — treated
//     as self-closing regardless of the closing tag
//   * Raw-text elements (script, style, textarea, title) —
//     everything up to the matching `</tag>` is treated as a
//     single text node, without tag recognition inside
//
// Intentionally NOT covered:
//
//   * Full HTML5 insertion mode / foster parenting / table
//     misnesting / form-element quirks. The DOM conversion
//     rewrites well-formed fragments; consumers that need
//     full HTML5 pre-parse via a real parser and feed us the
//     output.
//   * HTML5 doctype handling beyond recognition of the `<!DOCTYPE`
//     prefix as a one-shot prefix node.
//
// Output shape (parsed tree):
//
//   type HtmlNode =
//     | { type: 'element', tag: string, attrs: Record<string,string>,
//         children: HtmlNode[], loc: {start,end} }
//     | { type: 'text', value: string, loc: {start,end} }
//     | { type: 'comment', value: string, loc: {start,end} }
//     | { type: 'doctype', value: string, loc: {start,end} }
//     | { type: 'fragment', children: HtmlNode[] }
//
// `loc` offsets index into the input string (start inclusive,
// end exclusive). The root is always a `fragment` with the
// top-level siblings as children.
//
// The parser is iterative (no recursion) so deeply nested
// markup doesn't blow the JS stack. Every error is tolerant:
// unclosed tags, missing end quotes, malformed comments all
// recover by treating the malformed region as text and
// continuing. Unterminated raw-text elements consume to the
// end of the input.

'use strict';

// Void elements per HTML5. Checked lowercase.
const VOID_ELEMENTS = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img',
  'input', 'link', 'meta', 'param', 'source', 'track', 'wbr',
]);

// Raw-text elements. Everything between the open tag and the
// matching close is treated as a single text node.
const RAW_TEXT_ELEMENTS = new Set([
  'script', 'style', 'textarea', 'title',
]);

// Named entity references we recognise. The parser decodes
// these in text and attribute values. Numeric references
// (&#NN; / &#xNN;) are handled directly.
const NAMED_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00A0',
  copy: '\u00A9', reg: '\u00AE', trade: '\u2122',
};

// --- Entity decoding ----------------------------------------------------

function decodeEntities(s) {
  if (s.indexOf('&') < 0) return s;
  let out = '';
  let i = 0;
  while (i < s.length) {
    const ch = s.charCodeAt(i);
    if (ch !== 38 /* & */) { out += s[i]; i++; continue; }
    // Find the semicolon.
    const end = s.indexOf(';', i + 1);
    if (end < 0 || end - i > 10) {
      out += s[i];
      i++;
      continue;
    }
    const inner = s.slice(i + 1, end);
    let decoded = null;
    if (inner[0] === '#') {
      // Numeric reference.
      let cp;
      if (inner[1] === 'x' || inner[1] === 'X') {
        cp = parseInt(inner.slice(2), 16);
      } else {
        cp = parseInt(inner.slice(1), 10);
      }
      if (Number.isFinite(cp) && cp >= 0 && cp <= 0x10FFFF) {
        decoded = String.fromCodePoint(cp);
      }
    } else if (NAMED_ENTITIES[inner] !== undefined) {
      decoded = NAMED_ENTITIES[inner];
    }
    if (decoded != null) {
      out += decoded;
      i = end + 1;
    } else {
      out += s[i];
      i++;
    }
  }
  return out;
}

// --- Tokenizer ----------------------------------------------------------

const TOK_TEXT = 'text';
const TOK_START = 'start';
const TOK_END = 'end';
const TOK_SELF = 'self';
const TOK_COMMENT = 'comment';
const TOK_DOCTYPE = 'doctype';
const TOK_CDATA = 'cdata';

// tokenize(src) → Token[]. Each token is
//   { type, start, end, ...payload }
// Start/self tokens have `tagName` (lowercase) and
// `attrs: Array<{name, value}>`. End tokens have `tagName`.
// Text / comment / doctype / cdata tokens carry `value`.
function tokenize(src) {
  const tokens = [];
  const n = src.length;
  let i = 0;
  while (i < n) {
    const ch = src.charCodeAt(i);
    if (ch === 60 /* < */) {
      // Possible tag-like construct. Peek ahead.
      if (src.substr(i, 4) === '<!--') {
        // Comment. Scan for -->.
        const end = src.indexOf('-->', i + 4);
        if (end < 0) {
          tokens.push({ type: TOK_COMMENT, start: i, end: n, value: src.slice(i + 4) });
          i = n;
        } else {
          tokens.push({ type: TOK_COMMENT, start: i, end: end + 3, value: src.slice(i + 4, end) });
          i = end + 3;
        }
        continue;
      }
      if (src.substr(i, 9) === '<![CDATA[') {
        const end = src.indexOf(']]>', i + 9);
        if (end < 0) {
          tokens.push({ type: TOK_CDATA, start: i, end: n, value: src.slice(i + 9) });
          i = n;
        } else {
          tokens.push({ type: TOK_CDATA, start: i, end: end + 3, value: src.slice(i + 9, end) });
          i = end + 3;
        }
        continue;
      }
      if (src.substr(i, 2) === '<!') {
        // Doctype or unknown markup declaration. Scan to next >.
        const end = src.indexOf('>', i + 2);
        if (end < 0) {
          tokens.push({ type: TOK_DOCTYPE, start: i, end: n, value: src.slice(i + 2) });
          i = n;
        } else {
          tokens.push({ type: TOK_DOCTYPE, start: i, end: end + 1, value: src.slice(i + 2, end) });
          i = end + 1;
        }
        continue;
      }
      if (src.charCodeAt(i + 1) === 47 /* / */) {
        // End tag. </tagName>
        let j = i + 2;
        while (j < n && !isTagNameTerminator(src.charCodeAt(j))) j++;
        const tagName = src.slice(i + 2, j).toLowerCase();
        // Skip to >.
        while (j < n && src.charCodeAt(j) !== 62 /* > */) j++;
        const end = j < n ? j + 1 : n;
        tokens.push({ type: TOK_END, start: i, end, tagName });
        i = end;
        continue;
      }
      // Start / self-close tag.
      const startTok = parseStartTag(src, i);
      if (startTok) {
        tokens.push(startTok);
        i = startTok.end;
        continue;
      }
      // Not a recognised tag — emit a literal `<` as text and advance.
      tokens.push({ type: TOK_TEXT, start: i, end: i + 1, value: '<' });
      i++;
      continue;
    }
    // Text run. Scan to next `<`.
    let j = i + 1;
    while (j < n && src.charCodeAt(j) !== 60) j++;
    tokens.push({ type: TOK_TEXT, start: i, end: j, value: decodeEntities(src.slice(i, j)) });
    i = j;
  }
  return tokens;
}

function isTagNameTerminator(code) {
  return code === 32 || code === 9 || code === 10 || code === 13 ||
    code === 47 /* / */ || code === 62 /* > */;
}

function parseStartTag(src, start) {
  const n = src.length;
  // Must be `<letter...`.
  const ch = src.charCodeAt(start + 1);
  if (!(ch >= 65 && ch <= 90 /* A-Z */) &&
      !(ch >= 97 && ch <= 122 /* a-z */)) {
    return null;
  }
  let i = start + 1;
  // Read tag name.
  while (i < n && !isTagNameTerminator(src.charCodeAt(i))) i++;
  const tagName = src.slice(start + 1, i).toLowerCase();
  const attrs = [];
  // Read attributes.
  while (i < n) {
    // Skip whitespace.
    while (i < n && isWs(src.charCodeAt(i))) i++;
    if (i >= n) break;
    const c = src.charCodeAt(i);
    if (c === 62 /* > */) {
      return { type: TOK_START, start, end: i + 1, tagName, attrs };
    }
    if (c === 47 /* / */) {
      // Possible self-close. Skip /, allow optional whitespace, expect >.
      i++;
      while (i < n && isWs(src.charCodeAt(i))) i++;
      if (i < n && src.charCodeAt(i) === 62) {
        return { type: TOK_SELF, start, end: i + 1, tagName, attrs };
      }
      continue;
    }
    // Attribute name.
    const nameStart = i;
    while (i < n) {
      const cc = src.charCodeAt(i);
      if (isWs(cc) || cc === 61 /* = */ || cc === 62 || cc === 47) break;
      i++;
    }
    if (i === nameStart) {
      // Stuck — advance to avoid infinite loop.
      i++;
      continue;
    }
    const name = src.slice(nameStart, i).toLowerCase();
    let value = '';
    // Skip whitespace.
    while (i < n && isWs(src.charCodeAt(i))) i++;
    if (i < n && src.charCodeAt(i) === 61 /* = */) {
      i++;
      while (i < n && isWs(src.charCodeAt(i))) i++;
      if (i < n) {
        const q = src.charCodeAt(i);
        if (q === 34 /* " */ || q === 39 /* ' */) {
          const quote = src[i];
          i++;
          const valStart = i;
          while (i < n && src[i] !== quote) i++;
          value = decodeEntities(src.slice(valStart, i));
          if (i < n) i++;   // consume closing quote
        } else {
          const valStart = i;
          while (i < n && !isWs(src.charCodeAt(i)) && src.charCodeAt(i) !== 62) i++;
          value = decodeEntities(src.slice(valStart, i));
        }
      }
    } else {
      // Boolean attribute — value equals the attribute name per
      // HTML5 when the attribute is present with no value.
      value = '';
    }
    attrs.push({ name, value });
  }
  // Ran out of input before closing `>`. Return an incomplete tag.
  return { type: TOK_START, start, end: n, tagName, attrs };
}

function isWs(code) {
  return code === 32 || code === 9 || code === 10 || code === 13 || code === 12;
}

// --- Tree builder -------------------------------------------------------

// parse(src) → HtmlNode fragment. Iterative stack-based tree
// builder. Void elements become leaf `element` nodes with no
// children. Raw-text elements consume all content up to the
// matching end tag as a single text node. Unmatched end tags
// are dropped silently.
function parse(src) {
  const tokens = tokenize(src);
  const root = { type: 'fragment', children: [], loc: { start: 0, end: src.length } };
  const stack = [root];
  let i = 0;
  while (i < tokens.length) {
    const tok = tokens[i];
    const top = stack[stack.length - 1];
    switch (tok.type) {
      case TOK_TEXT: {
        top.children.push({ type: 'text', value: tok.value, loc: { start: tok.start, end: tok.end } });
        i++;
        break;
      }
      case TOK_COMMENT: {
        top.children.push({ type: 'comment', value: tok.value, loc: { start: tok.start, end: tok.end } });
        i++;
        break;
      }
      case TOK_DOCTYPE: {
        top.children.push({ type: 'doctype', value: tok.value, loc: { start: tok.start, end: tok.end } });
        i++;
        break;
      }
      case TOK_CDATA: {
        top.children.push({ type: 'text', value: tok.value, loc: { start: tok.start, end: tok.end } });
        i++;
        break;
      }
      case TOK_SELF: {
        const elem = makeElement(tok);
        top.children.push(elem);
        i++;
        break;
      }
      case TOK_START: {
        const elem = makeElement(tok);
        if (VOID_ELEMENTS.has(tok.tagName)) {
          top.children.push(elem);
          i++;
          break;
        }
        if (RAW_TEXT_ELEMENTS.has(tok.tagName)) {
          // Consume tokens up to the matching close tag as a
          // single raw-text node. The tokenizer already produced
          // TEXT tokens for everything inside, but it ALSO
          // recognised tag-like constructs inside — for raw
          // elements we must concatenate the source range
          // between the start tag's end and the matching close
          // tag's start (skipping the intermediate tokens).
          let j = i + 1;
          let rawEnd = tok.end;
          while (j < tokens.length) {
            const t2 = tokens[j];
            if (t2.type === TOK_END && t2.tagName === tok.tagName) break;
            j++;
          }
          if (j < tokens.length) {
            rawEnd = tokens[j].start;
            const raw = src.slice(tok.end, rawEnd);
            if (raw.length > 0) {
              elem.children.push({
                type: 'text',
                value: raw,
                loc: { start: tok.end, end: rawEnd },
              });
            }
            elem.loc.end = tokens[j].end;
            top.children.push(elem);
            i = j + 1;
          } else {
            // No matching close; raw text runs to end of input.
            const raw = src.slice(tok.end);
            if (raw.length > 0) {
              elem.children.push({
                type: 'text',
                value: raw,
                loc: { start: tok.end, end: src.length },
              });
            }
            elem.loc.end = src.length;
            top.children.push(elem);
            i = tokens.length;
          }
          break;
        }
        // Normal element: push onto the stack.
        top.children.push(elem);
        stack.push(elem);
        i++;
        break;
      }
      case TOK_END: {
        // Find the matching element on the stack and pop to it.
        let found = -1;
        for (let k = stack.length - 1; k >= 1; k--) {
          if (stack[k].type === 'element' && stack[k].tag === tok.tagName) {
            found = k;
            break;
          }
        }
        if (found >= 0) {
          // Pop everything above `found` (implicit close) and
          // then `found` itself.
          for (let k = stack.length - 1; k >= found; k--) {
            stack[k].loc.end = tok.end;
          }
          stack.length = found;
        }
        // Unmatched close tags are silently dropped.
        i++;
        break;
      }
    }
  }
  // Close any remaining open elements at end of input.
  while (stack.length > 1) {
    stack[stack.length - 1].loc.end = src.length;
    stack.pop();
  }
  return root;
}

function makeElement(startTok) {
  const attrs = Object.create(null);
  for (const a of startTok.attrs) attrs[a.name] = a.value;
  return {
    type: 'element',
    tag: startTok.tagName,
    attrs,
    children: [],
    loc: { start: startTok.start, end: startTok.end },
  };
}

// --- Serialisation ------------------------------------------------------

// serialize(node) → string. Round-trip for testing and for
// the dom-convert consumer that wants to stringify a rewritten
// subtree. Uses minimal escaping (no entity normalisation
// beyond what's required for well-formed output).
function serialize(node) {
  if (node.type === 'text') return escapeText(node.value);
  if (node.type === 'comment') return '<!--' + node.value + '-->';
  if (node.type === 'doctype') return '<!' + node.value + '>';
  if (node.type === 'fragment') {
    let out = '';
    for (const c of node.children) out += serialize(c);
    return out;
  }
  if (node.type === 'element') {
    let out = '<' + node.tag;
    for (const name in node.attrs) {
      out += ' ' + name + '="' + escapeAttr(node.attrs[name]) + '"';
    }
    if (VOID_ELEMENTS.has(node.tag)) {
      out += '>';
      return out;
    }
    out += '>';
    if (RAW_TEXT_ELEMENTS.has(node.tag)) {
      // Raw-text elements: don't escape inner content.
      for (const c of node.children) {
        out += c.type === 'text' ? c.value : serialize(c);
      }
    } else {
      for (const c of node.children) out += serialize(c);
    }
    out += '</' + node.tag + '>';
    return out;
  }
  return '';
}

function escapeText(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '&') out += '&amp;';
    else if (ch === '<') out += '&lt;';
    else if (ch === '>') out += '&gt;';
    else out += ch;
  }
  return out;
}

function escapeAttr(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '&') out += '&amp;';
    else if (ch === '"') out += '&quot;';
    else if (ch === '<') out += '&lt;';
    else out += ch;
  }
  return out;
}

module.exports = {
  parse,
  serialize,
  tokenize,
  decodeEntities,
  VOID_ELEMENTS,
  RAW_TEXT_ELEMENTS,
};
