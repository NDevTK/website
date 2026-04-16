// default-typedb.js — default TypeDB for the browser runtime.
//
// Pure data. Every source / sink / sanitizer / event-type
// decision the engine makes is expressed as a TypeDescriptor on
// a named type. The lookup helpers in `src/typedb.js` apply the
// same generic logic to every entry — there are no hardcoded
// name literals in the engine itself.
//
// Consumers who want to add, remove, or replace types can pass
// a custom `typeDB` via `analyze(input, { typeDB })`. The engine
// treats a custom DB identically to this preset.
//
// This DB was ported verbatim from the original single-file
// engine's `DEFAULT_TYPE_DB` block (~1500 lines of declarative
// data) with no behavioural changes. That DB is the source of
// truth for browser semantics; rewriting it risks losing DOM
// edge cases that took years to surface.
//
// Label vocabulary used below (sources and sink kinds):
//   sources: 'url', 'cookie', 'referrer', 'window.name', 'storage',
//            'network', 'postMessage', 'file', 'dragdrop',
//            'clipboard'
//   sinks:   'html', 'code', 'url', 'navigation', 'css', 'text'
//
// Inheritance: every HTMLxElement extends HTMLElement which
// extends Element which extends EventTarget. String methods
// live on String. Event subtypes extend Event. Promise.then /
// .catch live on Promise. The chain gives each subtype access
// to its parent's props and methods automatically.

'use strict';

const DEFAULT_TYPE_DB = {
  types: {
    // --- Base types ---
    EventTarget: {
      methods: {
        // addEventListener(event, handler, options?) — the
        // handler (arg 1) is a callback. `callbackArgs: [1]`
        // tells the engine to walk its body interprocedurally
        // at the addEventListener site so any unsafe sinks
        // inside the handler show up on the trace even if the
        // event itself never fires.
        addEventListener: { args: [{}, {}], callbackArgs: [1], callbackEventNameArg: 0 },
        removeEventListener: { args: [{}, {}] },
        dispatchEvent: { args: [{}] },
      },
    },
    Event: {
      extends: 'EventTarget',
      props: {
        // Generic Event has no taint-relevant props; subtypes override.
      },
    },
    // Event types whose source reads carry per-invocation
    // values get `sourceScope: 'call'`. Two `event.data` reads
    // in two different `message` handlers MUST receive distinct
    // SMT symbols — each postMessage delivery is independent.
    // Without this, Z3 would unsoundly correlate the two.
    MessageEvent: {
      extends: 'Event',
      sourceScope: 'call',
      props: {
        data:   { source: 'postMessage', delivery: 'postMessage:data'   },
        origin: { source: 'postMessage', delivery: 'postMessage:origin' },
      },
    },
    HashChangeEvent: {
      extends: 'Event',
      sourceScope: 'call',
      props: {
        newURL: { source: 'url', delivery: 'location-href' },
        oldURL: { source: 'url', delivery: 'location-href' },
      },
    },
    PopStateEvent: {
      extends: 'Event',
      sourceScope: 'call',
      props: {
        state: { source: 'url', delivery: 'history-state' },
      },
    },
    ErrorEvent: {
      extends: 'Event',
      sourceScope: 'call',
      props: {
        message:  { source: 'network', delivery: 'network-response' },
        filename: { source: 'url',     delivery: 'location-href'     },
      },
    },
    StorageEvent: {
      extends: 'Event',
      sourceScope: 'call',
      props: {
        newValue: { source: 'storage', delivery: 'localStorage' },
        oldValue: { source: 'storage', delivery: 'localStorage' },
        url:      { source: 'url',     delivery: 'location-href' },
      },
    },
    DataTransfer: {
      sourceScope: 'call',
      props: {
        files: { source: 'file', delivery: 'file-drop' },
      },
      methods: {
        getData: { source: 'dragdrop', returnType: 'String', delivery: 'file-drop' },
      },
    },
    DragEvent: {
      extends: 'Event',
      sourceScope: 'call',
      props: {
        dataTransfer: { readType: 'DataTransfer' },
      },
    },
    ClipboardData: {
      sourceScope: 'call',
      methods: {
        getData: { source: 'clipboard', returnType: 'String', delivery: 'clipboard-paste' },
      },
    },
    ClipboardEvent: {
      extends: 'Event',
      sourceScope: 'call',
      props: {
        clipboardData: { readType: 'ClipboardData' },
      },
    },
    FileReader: {
      extends: 'EventTarget',
      sourceScope: 'call',
      props: {
        result:       { source: 'file',    delivery: 'file-drop'        },
        response:     { source: 'network', delivery: 'network-response' },
        responseText: { source: 'network', delivery: 'network-response' },
      },
    },
    ProgressEvent: {
      extends: 'Event',
      props: {
        target: { readType: 'FileReader' },
      },
    },

    // --- DOM structural types ---
    Location: {
      // Reading a bare Location binding — e.g. `document.body.
      // innerHTML = window.location` — produces a URL string via
      // the implicit toString() the consumer performs, so the
      // binding itself carries the `url` label. Matches the
      // legacy behaviour of the `'window.location': 'url'` and
      // `'location': …` entries that over-tagged intermediate
      // Location references.
      selfSource: 'url',
      props: {
        search:   { source: 'url', readType: 'String', delivery: 'location-search'   },
        hash:     { source: 'url', readType: 'String', delivery: 'location-fragment' },
        href:     { source: 'url', readType: 'String', sink: 'navigation', exploit: 'url-javascript-scheme', delivery: 'location-href' },
        pathname: { source: 'url', readType: 'String', delivery: 'location-pathname' },
        host:     { source: 'url', readType: 'String', delivery: 'location-href'     },
        hostname: { source: 'url', readType: 'String', delivery: 'location-href'     },
        origin:   { source: 'url', readType: 'String', delivery: 'location-href'     },
        port:     { source: 'url', readType: 'String', delivery: 'location-href'     },
        protocol: { source: 'url', readType: 'String', delivery: 'location-href'     },
      },
      methods: {
        assign:   { args: [{ sink: 'navigation', exploit: 'url-javascript-scheme' }] },
        replace:  { args: [{ sink: 'navigation', exploit: 'url-javascript-scheme' }] },
        reload:   {},
        toString: { source: 'url', returnType: 'String' },
      },
    },
    History: {
      methods: {
        pushState:    {},
        replaceState: {},
        back:         {},
        forward:      {},
        go:           {},
      },
    },
    Navigation: {
      methods: {
        navigate: { args: [{ sink: 'navigation', exploit: 'url-javascript-scheme' }] },
      },
    },
    Storage: {
      // Reading a bare `localStorage` / `sessionStorage`
      // binding directly yields the `storage` label — matches
      // the legacy TAINT_SOURCES entries for those roots.
      selfSource: 'storage',
      methods: {
        getItem:    { source: 'storage', returnType: 'String', delivery: 'localStorage' },
        setItem:    {},
        removeItem: {},
        clear:      {},
        key:        {},
      },
    },
    Document: {
      extends: 'EventTarget',
      props: {
        URL:         { source: 'url',      readType: 'String', delivery: 'location-href'     },
        documentURI: { source: 'url',      readType: 'String', delivery: 'location-href'     },
        baseURI:     { source: 'url',      readType: 'String', delivery: 'location-href'     },
        cookie:      { source: 'cookie',   readType: 'String', delivery: 'cookie'            },
        referrer:    { source: 'referrer', readType: 'String', delivery: 'referrer'          },
        domain:      { source: 'referrer', readType: 'String', sink: 'origin' },
        location:    { readType: 'Location' },
        body:        { readType: 'HTMLElement' },
        documentElement: { readType: 'HTMLElement' },
      },
      methods: {
        createElement: {
          returnType: { fromArg: 0, map: {}, default: 'HTMLElement' },
        },
        createTextNode:    { returnType: 'Node' },
        createDocumentFragment: { returnType: 'DocumentFragment' },
        getElementById:    { returnType: 'HTMLElement' },
        getElementsByTagName: { returnType: 'HTMLCollection' },
        getElementsByClassName: { returnType: 'HTMLCollection' },
        querySelector:     { returnType: 'HTMLElement' },
        querySelectorAll:  { returnType: 'NodeList' },
        // document.write / writeln: streaming parser DOES execute
        // script tags in the written chunk — different exec
        // context from innerHTML.
        write:   { args: [{ sink: 'html', exploit: 'html-document-write' }] },
        writeln: { args: [{ sink: 'html', exploit: 'html-document-write' }] },
      },
    },
    Window: {
      extends: 'EventTarget',
      props: {
        location:       { readType: 'Location' },
        name:           { source: 'window.name', readType: 'String', delivery: 'window-name' },
        document:       { readType: 'Document' },
        history:        { readType: 'History' },
        navigation:     { readType: 'Navigation' },
        localStorage:   { readType: 'Storage' },
        sessionStorage: { readType: 'Storage' },
        top:            { readType: 'Window' },
        parent:         { readType: 'Window' },
        opener:         { readType: 'Window' },
        self:           { readType: 'Window' },
        frames:         { readType: 'Window' },
      },
      methods: {
        open: { args: [{ sink: 'navigation', severity: 'medium', exploit: 'url-javascript-scheme' }] },
        postMessage: {},
        // setTimeout / setInterval: arg 0 is either a string
        // (code sink — unsafe-eval path) OR a callback
        // function. The callback variant needs interprocedural
        // walking so any sink inside the timer body shows up.
        setTimeout:  { args: [{ sink: 'code', exploit: 'js-expression' }], callbackArgs: [0] },
        setInterval: { args: [{ sink: 'code', exploit: 'js-expression' }], callbackArgs: [0] },
        clearTimeout:  {},
        clearInterval: {},
        queueMicrotask: { args: [{}], callbackArgs: [0] },
        requestAnimationFrame: { args: [{}], callbackArgs: [0] },
        requestIdleCallback:   { args: [{}], callbackArgs: [0] },
      },
    },

    // --- Element hierarchy ---
    Node: {
      extends: 'EventTarget',
      props: {
        // Baseline safe read/write. Subtypes (HTMLScriptElement,
        // HTMLStyleElement) override with stronger sinks. Carrying
        // sink:'text' here means unknown-tag writes resolve to the
        // safe baseline rather than scanning every subtype.
        textContent: { sink: 'text', severity: 'safe' },
      },
      methods: {
        appendChild:  { args: [{}] },
        insertBefore: { args: [{}, {}] },
        removeChild:  { args: [{}] },
        replaceChild: { args: [{}, {}] },
      },
    },
    DocumentFragment: {
      extends: 'Node',
    },
    Element: {
      extends: 'Node',
      props: {
        // innerHTML / outerHTML: HTML5 parser spec says
        // <script> tags injected here DO NOT execute. We use
        // the 'html-innerHTML' exploit context whose attempts
        // are event-handler shapes (img onerror, svg onload).
        innerHTML: { sink: 'html', exploit: 'html-innerHTML' },
        outerHTML: { sink: 'html', exploit: 'html-innerHTML' },
      },
      methods: {
        insertAdjacentHTML: { args: [{}, { sink: 'html', exploit: 'html-innerHTML' }] },
        setAttribute: {
          // arg[0] is the attribute name, arg[1] is its value. The
          // per-attr sink classification lives on db.attrSinks so
          // it's reusable from both the call-site sinkIfArgEquals
          // handler AND the checkSinkSetAttribute (direct attr
          // write) code path. The sinkIfArgEquals.values object is
          // wired to db.attrSinks at DB finalisation time below,
          // so there's one source of truth.
          args: [{ sinkIfArgEquals: { arg: 1, values: null } }, {}],
        },
        removeAttribute: { args: [{}] },
        getAttribute:    { args: [{}], returnType: 'String' },
        // DOM queries on an element return NodeList /
        // HTMLCollection — same typed-iterable semantics as
        // the Document-level equivalents.
        querySelector:     { returnType: 'HTMLElement' },
        querySelectorAll:  { returnType: 'NodeList' },
        getElementsByTagName:   { returnType: 'HTMLCollection' },
        getElementsByClassName: { returnType: 'HTMLCollection' },
        closest:           { returnType: 'HTMLElement' },
        matches:           { args: [{}] },
        getBoundingClientRect: {},
      },
    },
    HTMLElement: { extends: 'Element' },
    HTMLIFrameElement: {
      extends: 'HTMLElement',
      props: {
        src:    { sink: 'url',  exploit: 'url-javascript-scheme' },
        srcdoc: { sink: 'html', exploit: 'html-document-write'   },
      },
    },
    HTMLScriptElement: {
      extends: 'HTMLElement',
      props: {
        src:         { sink: 'url',  exploit: 'url-script' },
        textContent: { sink: 'code', exploit: 'js-expression' },
        text:        { sink: 'code', exploit: 'js-expression' },
        innerText:   { sink: 'code', exploit: 'js-expression' },
      },
    },
    HTMLEmbedElement: {
      extends: 'HTMLElement',
      props: { src: { sink: 'url', exploit: 'url-javascript-scheme' } },
    },
    HTMLObjectElement: {
      extends: 'HTMLElement',
      props: { data: { sink: 'url', exploit: 'url-javascript-scheme' } },
    },
    HTMLFrameElement: {
      extends: 'HTMLElement',
      props: { src: { sink: 'url', exploit: 'url-javascript-scheme' } },
    },
    HTMLAnchorElement: {
      extends: 'HTMLElement',
      props: { href: { sink: 'url', exploit: 'url-javascript-scheme' } },
    },
    HTMLAreaElement: {
      extends: 'HTMLElement',
      props: { href: { sink: 'url', exploit: 'url-javascript-scheme' } },
    },
    HTMLBaseElement: {
      extends: 'HTMLElement',
      props: { href: { sink: 'url', exploit: 'url-javascript-scheme' } },
    },
    HTMLLinkElement: {
      extends: 'HTMLElement',
      props: { href: { sink: 'url', exploit: 'url-javascript-scheme' } },
    },
    HTMLFormElement: {
      extends: 'HTMLElement',
      props: { action: { sink: 'url', exploit: 'url-javascript-scheme' } },
    },
    HTMLInputElement: {
      extends: 'HTMLElement',
      props: { formAction: { sink: 'url', severity: 'medium', exploit: 'url-javascript-scheme' } },
    },
    HTMLButtonElement: {
      extends: 'HTMLElement',
      props: { formAction: { sink: 'url', severity: 'medium', exploit: 'url-javascript-scheme' } },
    },
    HTMLStyleElement: {
      extends: 'HTMLElement',
      props: {
        textContent: { sink: 'css' },
        innerText:   { sink: 'css' },
      },
    },
    HTMLImageElement: { extends: 'HTMLElement' },
    HTMLVideoElement: { extends: 'HTMLElement' },
    HTMLAudioElement: { extends: 'HTMLElement' },
    HTMLSourceElement: { extends: 'HTMLElement' },
    HTMLTrackElement: { extends: 'HTMLElement' },
    HTMLCollection: {
      // Element-typed iterable: `.forEach(el => ...)` binds
      // `el` as an HTMLElement (see typed-iterable handler
      // in applyMethod).
      iteratesType: 'HTMLElement',
      methods: {
        item:         { returnType: 'HTMLElement' },
        namedItem:    { returnType: 'HTMLElement' },
      },
    },
    NodeList: {
      iteratesType: 'HTMLElement',
      methods: {
        item:    { returnType: 'HTMLElement' },
        forEach: { args: [{}] },
        entries: {},
        keys:    {},
        values:  {},
      },
    },

    // --- Network types ---
    Response: {
      props: {
        ok:         { readType: 'Boolean' },
        status:     {},
        statusText: {},
        url:        { source: 'url', readType: 'String' },
        headers:    { readType: 'Headers' },
        body:       { source: 'network' },
        bodyUsed:   {},
        redirected: {},
        type:       {},
      },
      methods: {
        // Each body-reader method returns Promise<T> — the
        // walker reads `innerType` when it sees a `.then(cb)`
        // or `await` on the result chain so `cb` / the awaited
        // value is typed correctly.
        json:        { source: 'network', returnType: 'Promise', innerType: 'Object' },
        text:        { source: 'network', returnType: 'Promise', innerType: 'String' },
        blob:        { source: 'network', returnType: 'Promise', innerType: 'Blob' },
        arrayBuffer: { source: 'network', returnType: 'Promise', innerType: 'ArrayBuffer' },
        formData:    { source: 'network', returnType: 'Promise', innerType: 'FormData' },
        clone:       { returnType: 'Response' },
      },
    },
    // Promise<T>: `innerType` on the chain binding records T.
    // `.then(cb)` dispatches the callback with a typed first
    // arg whose typeName is the innerType. `.catch/finally`
    // don't expose the resolved value's type the same way.
    Promise: {
      methods: {
        then:    { args: [{ usesReceiverInnerType: true }, {}] },
        catch:   { args: [{}] },
        finally: { args: [{}] },
      },
    },
    // ArrayBuffer / Object placeholder types.
    ArrayBuffer: {},
    Object: {},
    Boolean: {},
    XMLHttpRequest: {
      extends: 'EventTarget',
      props: {
        responseText: { source: 'network', readType: 'String' },
        response:     { source: 'network' },
        responseXML:  { source: 'network' },
        status:       {},
        statusText:   {},
      },
      methods: {
        open:            { args: [{}, {}] },
        send:            { args: [{}] },
        setRequestHeader:{ args: [{}, {}] },
        getResponseHeader: { args: [{}], returnType: 'String' },
        abort:           {},
      },
    },
    WebSocket: {
      extends: 'EventTarget',
      methods: {
        send:  { args: [{}] },
        close: {},
      },
    },
    EventSource: {
      extends: 'EventTarget',
      methods: {
        close: {},
      },
    },

    // --- String (for label-preserving string methods) ---
    //
    // `smtOp` names a string-theory operation understood by
    // `applySmtCallOp` in src/transfer.js. When the receiver has
    // a formula and the arg formulas are available, the call's
    // return value is given a derived SMT formula so downstream
    // path-condition composition and PoC synthesis can solve for
    // a concrete attacker input. Descriptors WITHOUT `smtOp` fall
    // back to the opaque-with-labels behaviour and, if a taint
    // flow reaches a sink without a valueFormula, raise an
    // `unsolvable-math` assumption naming the unmodelled op.
    String: {
      methods: {
        slice:       { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'slice'       },
        substring:   { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'substring'   },
        substr:      { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'substr'      },
        // to_lower / to_upper aren't universally supported across
        // Z3 WASM builds; keep the helpers in smt.js but route
        // the TypeDB through the unmodelled fallback so the
        // direct-flow demo payload fires instead of a parse error.
        toLowerCase: { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'unmodelled:toLowerCase' },
        toUpperCase: { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'unmodelled:toUpperCase' },
        trim:        { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'unmodelled:trim'      },
        trimStart:   { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'unmodelled:trimStart' },
        trimEnd:     { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'unmodelled:trimEnd'   },
        charAt:      { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'charAt'      },
        concat:      { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'concat'      },
        repeat:      { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'unmodelled:repeat' },
        replace:     { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'replace'     },
        replaceAll:  { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'replaceAll'  },
        padStart:    { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'unmodelled:padStart' },
        padEnd:      { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'unmodelled:padEnd'   },
        normalize:   { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'unmodelled:normalize' },
        split:       { preservesLabelsFromReceiver: true, smtOp: 'unmodelled:split' },
        indexOf:     { returnType: 'Int', smtOp: 'indexOf'   },
        lastIndexOf: { returnType: 'Int', smtOp: 'unmodelled:lastIndexOf' },
        includes:    { returnType: 'Bool', smtOp: 'includes'   },
        startsWith:  { returnType: 'Bool', smtOp: 'startsWith' },
        endsWith:    { returnType: 'Bool', smtOp: 'endsWith'   },
        toString:    { returnType: 'String', preservesLabelsFromReceiver: true, smtOp: 'identity' },
      },
      props: {
        length: { smtOp: 'length' },
      },
    },

    // --- Global callables ---
    GlobalEval: {
      call: { args: [{ sink: 'code', severity: 'high', exploit: 'js-expression' }] },
    },
    GlobalFunctionCtor: {
      construct: { args: [{ sink: 'code', severity: 'high', exploit: 'js-expression' }, { sink: 'code', severity: 'high', exploit: 'js-expression' }] },
      call:      { args: [{ sink: 'code', severity: 'high', exploit: 'js-expression' }, { sink: 'code', severity: 'high', exploit: 'js-expression' }] },
    },
    GlobalSetTimeout: {
      // Arg 0 is either a code-string (sink: 'code') or a
      // callback function. callbackArgs: [0] tells the engine
      // to walk the callback when it's a function value.
      call: { args: [{ sink: 'code', severity: 'high' }, {}], callbackArgs: [0] },
    },
    GlobalSetInterval: {
      call: { args: [{ sink: 'code', severity: 'high' }, {}], callbackArgs: [0] },
    },
    GlobalFetch: {
      // `fetch(...)` returns Promise<Response>. The walker
      // attaches `innerType: 'Response'` to the result chain
      // so `.then(r => r.json())` types `r` as Response. The
      // `source: 'network'` label is applied to the Promise
      // itself (matches the legacy TAINT_SOURCE_CALLS
      // behaviour that treats the call result as attacker-
      // influenced data).
      call: { source: 'network', returnType: 'Promise', innerType: 'Response' },
    },
    GlobalXMLHttpRequestCtor: {
      construct: { source: 'network', returnType: 'XMLHttpRequest' },
    },
    // Constructor singletons for common instance types. These
    // let `new FileReader()` / `new WebSocket(url)` / etc.
    // resolve to their instance type at binding-tag time.
    GlobalFileReaderCtor: {
      construct: { returnType: 'FileReader' },
    },
    GlobalWebSocketCtor: {
      construct: { source: 'network', returnType: 'WebSocket' },
    },
    GlobalEventSourceCtor: {
      construct: { source: 'network', returnType: 'EventSource' },
    },
    GlobalURLCtor: {
      construct: { returnType: 'URL' },
    },
    // URL instances — props carry the `url` label because
    // constructing a URL from any string doesn't sanitize it.
    URL: {
      props: {
        href:     { source: 'url', readType: 'String' },
        hash:     { source: 'url', readType: 'String' },
        search:   { source: 'url', readType: 'String' },
        pathname: { source: 'url', readType: 'String' },
        host:     { source: 'url', readType: 'String' },
        hostname: { source: 'url', readType: 'String' },
        origin:   { source: 'url', readType: 'String' },
        port:     { source: 'url', readType: 'String' },
        protocol: { source: 'url', readType: 'String' },
        searchParams: { readType: 'URLSearchParams' },
      },
    },
    // URLSearchParams: iterating / reading query-string
    // values produces url-labelled strings.
    URLSearchParams: {
      methods: {
        get:    { source: 'url', returnType: 'String' },
        getAll: { source: 'url' },
        keys:   {},
        values: { source: 'url' },
        entries:{ source: 'url' },
        has:    {},
        toString: { source: 'url', returnType: 'String' },
      },
    },
    // Blob / File: opaque file content.
    Blob: {
      methods: {
        text:      { source: 'file', returnType: 'Promise' },
        arrayBuffer: { source: 'file', returnType: 'Promise' },
        stream:    { source: 'file' },
        slice:     { returnType: 'Blob', preservesLabelsFromReceiver: true },
      },
    },
    File: {
      extends: 'Blob',
      props: {
        name:         { source: 'file', readType: 'String' },
        lastModified: {},
      },
    },
    FileList: {
      iteratesType: 'File',
      methods: {
        item: { returnType: 'File' },
      },
    },
    // FormData: form submission payload.
    FormData: {
      methods: {
        get:    { source: 'postMessage', returnType: 'String' },
        getAll: { source: 'postMessage' },
        has:    {},
        keys:   {},
        values: { source: 'postMessage' },
        entries:{ source: 'postMessage' },
        append: {}, set: {}, delete: {},
      },
    },
    GlobalFormDataCtor: {
      construct: { returnType: 'FormData' },
    },
    // Headers: HTTP header access. Response headers carry
    // server-controlled data so they're network-labelled.
    Headers: {
      methods: {
        get:    { source: 'network', returnType: 'String' },
        has:    {},
        keys:   {},
        values: { source: 'network' },
        entries:{ source: 'network' },
        forEach:{ args: [{}] },
      },
    },
    GlobalHeadersCtor: {
      construct: { returnType: 'Headers' },
    },
    // BroadcastChannel: cross-tab messaging, equivalent to
    // window.postMessage from a security standpoint.
    BroadcastChannel: {
      extends: 'EventTarget',
      methods: {
        postMessage: { args: [{}] },
        close: {},
      },
    },
    GlobalBroadcastChannelCtor: {
      construct: { returnType: 'BroadcastChannel' },
    },
    // MessagePort: postMessage channel.
    MessagePort: {
      extends: 'EventTarget',
      methods: {
        postMessage: { args: [{}] },
        start: {}, close: {},
      },
    },
    // Worker / SharedWorker / ServiceWorker: postMessage channels.
    Worker: {
      extends: 'EventTarget',
      methods: {
        postMessage: { args: [{}] },
        terminate: {},
      },
    },
    GlobalWorkerCtor: {
      construct: { args: [{ sink: 'url', severity: 'high' }], returnType: 'Worker' },
    },
    IDBObjectStore: {
      methods: {
        get: { source: 'storage' },
        put: {},
        add: {},
        delete: {},
      },
    },
    CacheStorage: {
      methods: {
        match: { source: 'storage' },
        open: {},
        has: {},
        delete: {},
      },
    },
    GlobalDecodeURIComponent: {
      call: { source: 'url', returnType: 'String', preservesLabelsFromArg: 0 },
    },
    GlobalDecodeURI: {
      call: { source: 'url', returnType: 'String', preservesLabelsFromArg: 0 },
    },
    GlobalAtob: {
      call: { source: 'url', returnType: 'String', preservesLabelsFromArg: 0 },
    },
    // Sanitizers: functions whose return type has no
    // preservesLabelsFrom* field, so labels do not flow from
    // the argument to the return. The engine treats a function
    // without a preserve hint as label-stripping automatically.
    // Sanitizers: `sanitizer: true` on the call descriptor
    // marks the result as label-free regardless of arg taint.
    // The walker's opaque-call path consults this flag.
    GlobalEncodeURIComponent: { call: { returnType: 'String', sanitizer: true } },
    GlobalEncodeURI:          { call: { returnType: 'String', sanitizer: true } },
    GlobalEscape:             { call: { returnType: 'String', sanitizer: true } },
    GlobalBtoa:               { call: { returnType: 'String', sanitizer: true } },
    GlobalParseInt:           { call: { sanitizer: true } },
    GlobalParseFloat:         { call: { sanitizer: true } },
    GlobalNumber:             { call: { sanitizer: true } },
    GlobalBoolean:            { call: { sanitizer: true } },
    // DOMPurify is an object whose .sanitize() method neutralises
    // HTML taint labels, yielding a string safe for innerHTML.
    DOMPurify: {
      methods: {
        sanitize: { returnType: 'String', sanitizer: true },
      },
    },
  },

  // Root name → type. Applied when the name is not shadowed by an
  // in-scope user declaration.
  roots: {
    location:       'Location',
    window:         'Window',
    document:       'Document',
    navigator:      'Window',     // coarse; refine if needed
    history:        'History',
    navigation:     'Navigation',
    localStorage:   'Storage',
    sessionStorage: 'Storage',
    top:            'Window',
    parent:         'Window',
    opener:         'Window',
    self:           'Window',
    frames:         'Window',

    // Global callables modeled as singletons
    eval:        'GlobalEval',
    Function:    'GlobalFunctionCtor',
    setTimeout:  'GlobalSetTimeout',
    setInterval: 'GlobalSetInterval',
    fetch:          'GlobalFetch',
    XMLHttpRequest: 'GlobalXMLHttpRequestCtor',
    FileReader:     'GlobalFileReaderCtor',
    WebSocket:      'GlobalWebSocketCtor',
    EventSource:    'GlobalEventSourceCtor',
    URL:              'GlobalURLCtor',
    URLSearchParams:  'GlobalURLCtor',   // ctor also returns searchable
    FormData:         'GlobalFormDataCtor',
    Headers:          'GlobalHeadersCtor',
    BroadcastChannel: 'GlobalBroadcastChannelCtor',
    Worker:            'GlobalWorkerCtor',
    caches:         'CacheStorage',
    decodeURIComponent: 'GlobalDecodeURIComponent',
    decodeURI:          'GlobalDecodeURI',
    atob:               'GlobalAtob',
    encodeURIComponent: 'GlobalEncodeURIComponent',
    encodeURI:          'GlobalEncodeURI',
    escape:             'GlobalEscape',
    btoa:               'GlobalBtoa',
    parseInt:           'GlobalParseInt',
    parseFloat:         'GlobalParseFloat',
    Number:             'GlobalNumber',
    Boolean:            'GlobalBoolean',
    DOMPurify:          'DOMPurify',
  },

  // createElement(tag) and similar → specific HTMLxElement type.
  tagMap: {
    iframe: 'HTMLIFrameElement',
    script: 'HTMLScriptElement',
    embed:  'HTMLEmbedElement',
    object: 'HTMLObjectElement',
    frame:  'HTMLFrameElement',
    a:      'HTMLAnchorElement',
    area:   'HTMLAreaElement',
    base:   'HTMLBaseElement',
    link:   'HTMLLinkElement',
    form:   'HTMLFormElement',
    input:  'HTMLInputElement',
    button: 'HTMLButtonElement',
    style:  'HTMLStyleElement',
    img:    'HTMLImageElement',
    video:  'HTMLVideoElement',
    audio:  'HTMLAudioElement',
    source: 'HTMLSourceElement',
    track:  'HTMLTrackElement',
  },

  // Attribute-name sinks: writing these attributes (via
  // `setAttribute(attr, v)` OR a direct attribute-write path)
  // classifies the value under the named sink kind regardless
  // of the concrete element type.
  attrSinks: {
    onclick: 'code', onload: 'code', onerror: 'code',
    onmouseover: 'code', onfocus: 'code', onblur: 'code',
    onsubmit: 'code', onchange: 'code', oninput: 'code',
    onkeydown: 'code', onkeyup: 'code', onkeypress: 'code',
    onmousedown: 'code', onmouseup: 'code', onmousemove: 'code',
    ondblclick: 'code', oncontextmenu: 'code', ondrag: 'code',
    ondrop: 'code', onscroll: 'code', onwheel: 'code',
    ontouchstart: 'code', ontouchend: 'code', ontouchmove: 'code',
    onanimationend: 'code', ontransitionend: 'code',
    style: 'css',
  },

  // addEventListener(eventName, fn) → the fn's first param gets this type.
  eventMap: {
    message:      'MessageEvent',
    messageerror: 'MessageEvent',
    hashchange:   'HashChangeEvent',
    popstate:     'PopStateEvent',
    error:        'ErrorEvent',
    storage:      'StorageEvent',
    drop:         'DragEvent',
    dragover:     'DragEvent',
    dragenter:    'DragEvent',
    dragleave:    'DragEvent',
    dragstart:    'DragEvent',
    dragend:      'DragEvent',
    paste:        'ClipboardEvent',
    copy:         'ClipboardEvent',
    cut:          'ClipboardEvent',
    load:         'ProgressEvent',
    loadend:      'ProgressEvent',
    loadstart:    'ProgressEvent',
    progress:     'ProgressEvent',
  },

  // Exploit shape library, keyed by the `exploit` name declared
  // on sink descriptors. Each entry carries an ordered list of
  // `attempts`; a taint-report consumer walks the list building
  // an SMT predicate per attempt and asks Z3 to solve each
  // against the flow's pathFormula ∧ valueFormula. First SAT
  // wins, and the attempt's `payload` is the VALUE that arrives
  // at the sink when the model is realised.
  //
  //   trigger — the SMT predicate shape applied to the flow's
  //             valueFormula. 'contains' / 'equals' / 'prefixof'.
  //   payload — the string that must appear at the sink.
  //
  // Users who want to swap exploit shapes (custom sandbox, new
  // canary, etc.) replace this table via `options.typeDB` —
  // no code change needed.
  exploits: {
    // innerHTML / outerHTML / insertAdjacentHTML: HTML5 parsing
    // deliberately refuses to execute <script> tags injected
    // through these APIs. Attempts use shapes that DO execute:
    // event handlers on image / svg / iframe elements.
    'html-innerHTML': {
      attempts: [
        { name: 'img-onerror',    trigger: 'contains', payload: '<img src=x onerror=alert(1)>' },
        { name: 'svg-onload',     trigger: 'contains', payload: '<svg onload=alert(1)>' },
        { name: 'iframe-srcdoc',  trigger: 'contains', payload: '<iframe srcdoc="<img src=x onerror=alert(1)>"></iframe>' },
        { name: 'attr-breakout',  trigger: 'contains', payload: '" onerror="alert(1)' },
      ],
    },
    // document.write / writeln: streaming parser; <script> DOES
    // execute. Script tag is the cleanest reproducer.
    'html-document-write': {
      attempts: [
        { name: 'script-tag',  trigger: 'contains', payload: '<script>alert(1)</script>' },
        { name: 'img-onerror', trigger: 'contains', payload: '<img src=x onerror=alert(1)>' },
      ],
    },
    // URL-valued sinks (location.href, iframe.src, anchor.href,
    // window.open, etc.). Browser executes only when the value
    // STARTS with `javascript:` — so 'equals' is the tightest
    // constraint. 'data:text/html,...' is a fallback for frames
    // that disallow javascript:.
    'url-javascript-scheme': {
      attempts: [
        { name: 'javascript-url', trigger: 'equals', payload: 'javascript:alert(1)' },
        { name: 'data-html',      trigger: 'equals', payload: 'data:text/html,<script>alert(1)</script>' },
      ],
    },
    // script.src loads external JavaScript. The value must be
    // a URL serving a script with the desired side effect. For
    // a PoC we point at a data: URL whose body is the payload.
    'url-script': {
      attempts: [
        { name: 'data-script', trigger: 'equals', payload: 'data:text/javascript,alert(1)' },
      ],
    },
    // eval / new Function / setTimeout(string). Value must be
    // valid JS. 'equals alert(1)' is the tightest constraint;
    // secondary 'contains ;alert(1);' handles cases where the
    // value is embedded inside an existing expression.
    'js-expression': {
      attempts: [
        { name: 'alert-canary',  trigger: 'equals',   payload: 'alert(1)' },
        { name: 'embedded-semi', trigger: 'contains', payload: ';alert(1);' },
      ],
    },
  },
};

// Wire createElement's dynamic return-type map from tagMap so
// the two stay in sync. Kept here (not inline in the Document
// descriptor above) so tagMap remains the single source of
// truth.
(function () {
  var map = DEFAULT_TYPE_DB.types.Document.methods.createElement.returnType.map;
  for (var tag in DEFAULT_TYPE_DB.tagMap) {
    map[tag] = DEFAULT_TYPE_DB.tagMap[tag];
  }
  // Wire Element.setAttribute's sinkIfArgEquals.values to
  // db.attrSinks so attribute classification has exactly one
  // source of truth — the values object — shared by both the
  // call-site sinkIfArgEquals evaluator AND the direct
  // setAttribute(attr, v) sink checker.
  DEFAULT_TYPE_DB.types.Element.methods.setAttribute.args[0].sinkIfArgEquals.values = DEFAULT_TYPE_DB.attrSinks;
})();

module.exports = DEFAULT_TYPE_DB;
