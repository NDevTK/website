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
// This DB is ported verbatim from the legacy
// `htmldom/jsanalyze.js` engine (the `DEFAULT_TYPE_DB` block at
// lines 14299-15057) with no behavioural changes. The legacy
// DB is the source of truth for browser semantics; rewriting it
// risks losing DOM edge cases that took years to surface.
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
        addEventListener: { args: [{}, {}] },
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
    MessageEvent: {
      extends: 'Event',
      props: {
        data:   { source: 'postMessage' },
        origin: { source: 'postMessage' },
      },
    },
    HashChangeEvent: {
      extends: 'Event',
      props: {
        newURL: { source: 'url' },
        oldURL: { source: 'url' },
      },
    },
    PopStateEvent: {
      extends: 'Event',
      props: {
        state: { source: 'url' },
      },
    },
    ErrorEvent: {
      extends: 'Event',
      props: {
        message:  { source: 'network' },
        filename: { source: 'url' },
      },
    },
    StorageEvent: {
      extends: 'Event',
      props: {
        newValue: { source: 'storage' },
        oldValue: { source: 'storage' },
        url:      { source: 'url' },
      },
    },
    DataTransfer: {
      props: {
        files: { source: 'file' },
      },
      methods: {
        getData: { source: 'dragdrop', returnType: 'String' },
      },
    },
    DragEvent: {
      extends: 'Event',
      props: {
        dataTransfer: { readType: 'DataTransfer' },
      },
    },
    ClipboardData: {
      methods: {
        getData: { source: 'clipboard', returnType: 'String' },
      },
    },
    ClipboardEvent: {
      extends: 'Event',
      props: {
        clipboardData: { readType: 'ClipboardData' },
      },
    },
    FileReader: {
      extends: 'EventTarget',
      props: {
        result:       { source: 'file' },
        response:     { source: 'network' },
        responseText: { source: 'network' },
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
        search:   { source: 'url', readType: 'String' },
        hash:     { source: 'url', readType: 'String' },
        href:     { source: 'url', readType: 'String', sink: 'navigation' },
        pathname: { source: 'url', readType: 'String' },
        host:     { source: 'url', readType: 'String' },
        hostname: { source: 'url', readType: 'String' },
        origin:   { source: 'url', readType: 'String' },
        port:     { source: 'url', readType: 'String' },
        protocol: { source: 'url', readType: 'String' },
      },
      methods: {
        assign:   { args: [{ sink: 'navigation' }] },
        replace:  { args: [{ sink: 'navigation' }] },
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
        navigate: { args: [{ sink: 'navigation' }] },
      },
    },
    Storage: {
      // Reading a bare `localStorage` / `sessionStorage`
      // binding directly yields the `storage` label — matches
      // the legacy TAINT_SOURCES entries for those roots.
      selfSource: 'storage',
      methods: {
        getItem:    { source: 'storage', returnType: 'String' },
        setItem:    {},
        removeItem: {},
        clear:      {},
        key:        {},
      },
    },
    Document: {
      extends: 'EventTarget',
      props: {
        URL:         { source: 'url',      readType: 'String' },
        documentURI: { source: 'url',      readType: 'String' },
        baseURI:     { source: 'url',      readType: 'String' },
        cookie:      { source: 'cookie',   readType: 'String' },
        referrer:    { source: 'referrer', readType: 'String' },
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
        write:             { args: [{ sink: 'html' }] },
        writeln:           { args: [{ sink: 'html' }] },
      },
    },
    Window: {
      extends: 'EventTarget',
      props: {
        location:       { readType: 'Location' },
        name:           { source: 'window.name', readType: 'String' },
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
        open: { args: [{ sink: 'navigation', severity: 'medium' }] },
        postMessage: {},
        setTimeout:  { args: [{ sink: 'code' }] },
        setInterval: { args: [{ sink: 'code' }] },
        clearTimeout:  {},
        clearInterval: {},
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
        innerHTML: { sink: 'html' },
        outerHTML: { sink: 'html' },
      },
      methods: {
        insertAdjacentHTML: { args: [{}, { sink: 'html' }] },
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
        src:    { sink: 'url' },
        srcdoc: { sink: 'html' },
      },
    },
    HTMLScriptElement: {
      extends: 'HTMLElement',
      props: {
        src:         { sink: 'url' },
        textContent: { sink: 'code' },
        text:        { sink: 'code' },
        innerText:   { sink: 'code' },
      },
    },
    HTMLEmbedElement: {
      extends: 'HTMLElement',
      props: { src: { sink: 'url' } },
    },
    HTMLObjectElement: {
      extends: 'HTMLElement',
      props: { data: { sink: 'url' } },
    },
    HTMLFrameElement: {
      extends: 'HTMLElement',
      props: { src: { sink: 'url' } },
    },
    HTMLAnchorElement: {
      extends: 'HTMLElement',
      props: { href: { sink: 'url' } },
    },
    HTMLAreaElement: {
      extends: 'HTMLElement',
      props: { href: { sink: 'url' } },
    },
    HTMLBaseElement: {
      extends: 'HTMLElement',
      props: { href: { sink: 'url' } },
    },
    HTMLLinkElement: {
      extends: 'HTMLElement',
      props: { href: { sink: 'url' } },
    },
    HTMLFormElement: {
      extends: 'HTMLElement',
      props: { action: { sink: 'url' } },
    },
    HTMLInputElement: {
      extends: 'HTMLElement',
      props: { formAction: { sink: 'url', severity: 'medium' } },
    },
    HTMLButtonElement: {
      extends: 'HTMLElement',
      props: { formAction: { sink: 'url', severity: 'medium' } },
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
    String: {
      methods: {
        slice:       { returnType: 'String', preservesLabelsFromReceiver: true },
        substring:   { returnType: 'String', preservesLabelsFromReceiver: true },
        substr:      { returnType: 'String', preservesLabelsFromReceiver: true },
        toLowerCase: { returnType: 'String', preservesLabelsFromReceiver: true },
        toUpperCase: { returnType: 'String', preservesLabelsFromReceiver: true },
        trim:        { returnType: 'String', preservesLabelsFromReceiver: true },
        trimStart:   { returnType: 'String', preservesLabelsFromReceiver: true },
        trimEnd:     { returnType: 'String', preservesLabelsFromReceiver: true },
        charAt:      { returnType: 'String', preservesLabelsFromReceiver: true },
        concat:      { returnType: 'String', preservesLabelsFromReceiver: true },
        repeat:      { returnType: 'String', preservesLabelsFromReceiver: true },
        replace:     { returnType: 'String', preservesLabelsFromReceiver: true },
        replaceAll:  { returnType: 'String', preservesLabelsFromReceiver: true },
        padStart:    { returnType: 'String', preservesLabelsFromReceiver: true },
        padEnd:      { returnType: 'String', preservesLabelsFromReceiver: true },
        normalize:   { returnType: 'String', preservesLabelsFromReceiver: true },
        split:       { preservesLabelsFromReceiver: true },
        indexOf:     {},
        lastIndexOf: {},
        includes:    {},
        startsWith:  {},
        endsWith:    {},
        toString:    { returnType: 'String', preservesLabelsFromReceiver: true },
      },
      props: {
        length: {},
      },
    },

    // --- Global callables ---
    GlobalEval: {
      call: { args: [{ sink: 'code', severity: 'high' }] },
    },
    GlobalFunctionCtor: {
      construct: { args: [{ sink: 'code', severity: 'high' }, { sink: 'code', severity: 'high' }] },
      call:      { args: [{ sink: 'code', severity: 'high' }, { sink: 'code', severity: 'high' }] },
    },
    GlobalSetTimeout: {
      call: { args: [{ sink: 'code', severity: 'high' }, {}] },
    },
    GlobalSetInterval: {
      call: { args: [{ sink: 'code', severity: 'high' }, {}] },
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
