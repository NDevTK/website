// Monaco Editor initialization and multi-file project support.
(function () {
  'use strict';
  var CDN = 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.53.0/min/vs';

  require.config({
    paths: { vs: CDN },
    'vs/nls': { availableLanguages: { '*': '' } }
  });

  window.MonacoEnvironment = {
    getWorkerUrl: function () {
      return 'data:text/javascript;charset=utf-8,' + encodeURIComponent(
        'self.MonacoEnvironment = { baseUrl: "' + CDN + '/" };' +
        'importScripts("' + CDN + '/base/worker/workerMain.js");'
      );
    }
  };

  require(['vs/editor/editor.main'], function () {
    var defaultInput = '<div style="position: fixed; z-index: -99; width: 100%; height: 100%">\n  <iframe credentialless loading="lazy" id="background" title="background" sandbox="allow-scripts" frameborder="0" height="100%" width="100%" src="https://random.ndev.tk/"></iframe>\n</div>\n<button onclick="alert(\'hello\')">Greet</button>\n<script>\nvar items = [\'Home\', \'About\', \'Contact\', location.search];\nvar html = \'<nav>\';\nfor (var i = 0; i < items.length; i++) {\n  html += \'<a href="/\' + items[i].toLowerCase() + \'"\' + \'>\' + items[i] + \'</a>\';\n}\nhtml += \'</nav>\';\ndocument.body.innerHTML = html;\n\nvar postMessageHandler = function(msg) {\n  var content = msg.data;\n  var msgObj = eval(content);\n  if (msgObj.isActive) {\n    document.write("PostMessage arrived!");\n  }\n}\nwindow.addEventListener(\'message\', postMessageHandler, false);\n\nvar redirect = location.hash.slice(1);\nlocation.href = redirect;\n\nvar frame = document.createElement(\'iframe\');\nframe.src = redirect;\ndocument.body.appendChild(frame);\n<\/script>';

    var editor = monaco.editor.create(document.getElementById('editor'), {
      value: defaultInput,
      language: 'html',
      theme: 'vs-dark',
      minimap: { enabled: false },
      fontSize: 13,
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
      wordWrap: 'on',
      automaticLayout: true,
    });

    window._monacoIn = editor;
    window._monacoOut = { setValue: function() {}, getValue: function() { return ''; } };

    // Script load order:
    //   1. jsanalyze/vendor/acorn.mjs           (globalThis.acorn)
    //   2. analyzer/jsanalyze-z3-browser.js     (Z3 bootstrap)
    //   3. jsanalyze/browser-bundle.js          (globalThis.Jsanalyze)
    //   4. analyzer/jsanalyze-bridge.js         (window.__runAllConsumers)
    function appendScript(src, onload) {
      var s = document.createElement('script');
      s.src = src;
      if (onload) s.onload = onload;
      document.body.appendChild(s);
    }
    // Monaco's AMD loader defines window.define with .amd set. Acorn's
    // UMD build would register as an anonymous AMD module and collide
    // with Monaco's own lazy module loads. Use the ESM build instead.
    import('../jsanalyze/vendor/acorn.mjs').then(function (mod) {
      globalThis.acorn = mod;
      appendScript('jsanalyze-z3-browser.js', function () {
        appendScript('../jsanalyze/browser-bundle.js', function () {
          appendScript('jsanalyze-bridge.js');
        });
      });
    });

    // --- State -----------------------------------------------------------
    var folderFiles = { 'example.html': defaultInput };
    var outputFiles = {};
    var dirHandle = null;
    var activeFile = null;          // { path: string, view: 'source' | 'converted' }
    var taintResults = null;
    var cspResults = null;
    var fetchResults = null;
    var rejectedAssumptions = [];
    var allAssumptions = [];
    var editorDecorations = [];
    var analysisMode = 'precise';
    var customAccept = null;
    var convertAllRunning = false;
    var activeTab = 'taint';

    function langFor(name) {
      if (/\.html?$/i.test(name)) return 'html';
      if (/\.css$/i.test(name)) return 'css';
      return 'javascript';
    }

    function iconFor(name) {
      if (/\.html?$/i.test(name)) return 'H';
      if (/\.js$/i.test(name))    return 'J';
      if (/\.css$/i.test(name))   return 'C';
      return '·';
    }

    // --- Folder reader --------------------------------------------------
    async function readFolder(dirHandle, prefix) {
      var files = {};
      for await (var entry of dirHandle.values()) {
        var path = prefix ? prefix + '/' + entry.name : entry.name;
        if (entry.kind === 'file' && /\.(html?|js|css)$/i.test(entry.name)) {
          files[path] = await (await entry.getFile()).text();
        } else if (entry.kind === 'directory' &&
                   !/^(node_modules|\.git|\.svn|dist|build)$/.test(entry.name)) {
          Object.assign(files, await readFolder(entry, path));
        }
      }
      return files;
    }

    // --- Accept-set presets ---------------------------------------------
    function currentAcceptSet() {
      if (analysisMode === 'custom') return customAccept || [];
      if (typeof globalThis.__buildAcceptSet === 'function') {
        return globalThis.__buildAcceptSet(analysisMode);
      }
      return null;
    }

    // --- File list rendering --------------------------------------------
    // Single unified tree. One row per input file. Output files don't
    // get their own row — they live behind the Source / Converted toggle
    // on the active file.
    function findingsForFile(path) {
      if (!taintResults) return 0;
      var n = 0;
      for (var i = 0; i < taintResults.findings.length; i++) {
        if (taintResults.findings[i].file === path) n++;
      }
      return n;
    }

    function renderFileList() {
      var container = document.getElementById('fileList');
      var countEl = document.getElementById('fileCount');
      var paths = Object.keys(folderFiles).sort();
      countEl.textContent = paths.length ? paths.length + ' file' + (paths.length === 1 ? '' : 's') : '';
      if (!paths.length) {
        container.innerHTML = '<div class="empty-hint">No files</div>';
        return;
      }
      container.innerHTML = '';
      paths.forEach(function (path) {
        var el = document.createElement('div');
        el.className = 'file-item' +
          (activeFile && activeFile.path === path ? ' active' : '');
        var icon = document.createElement('span');
        icon.className = 'icon';
        icon.textContent = iconFor(path);
        el.appendChild(icon);
        var name = document.createElement('span');
        name.className = 'name';
        name.textContent = path;
        el.appendChild(name);

        var badge = document.createElement('span');
        badge.className = 'badge';
        var n = findingsForFile(path);
        var hasOutput = outputFiles[path] != null;
        if (n > 0) {
          badge.classList.add('findings');
          badge.textContent = n + ' issue' + (n === 1 ? '' : 's');
        } else if (hasOutput) {
          badge.classList.add('converted');
          badge.textContent = 'converted';
        } else if (/\.(html?|js)$/i.test(path)) {
          badge.classList.add('clean');
          badge.textContent = 'clean';
        } else {
          badge.classList.add('clean');
          badge.textContent = '';
        }
        if (badge.textContent) el.appendChild(badge);

        el.addEventListener('click', function () { selectFile(path, 'source'); });
        container.appendChild(el);
      });
    }

    // --- File selection + Source/Converted toggle -----------------------
    function selectFile(path, view) {
      view = view || 'source';
      activeFile = { path: path, view: view };
      var content = view === 'converted'
        ? (outputFiles[path] || '')
        : (folderFiles[path] || '');
      editor.setValue(content);
      monaco.editor.setModelLanguage(editor.getModel(), langFor(path));
      editor.updateOptions({ readOnly: view === 'converted' });
      document.getElementById('editorFilename').textContent =
        path + (view === 'converted' ? '  (converted)' : '');

      var hasOutput = outputFiles[path] != null;
      document.getElementById('downloadCurrent').disabled = !hasOutput;

      var btnSrc = document.getElementById('viewOriginal');
      var btnCvt = document.getElementById('viewConverted');
      btnSrc.classList.toggle('active', view === 'source');
      btnCvt.classList.toggle('active', view === 'converted');
      btnCvt.disabled = !hasOutput;

      renderFileList();
      updateEditorDecorations();
    }

    // --- Analysis pipeline ----------------------------------------------
    async function convertAll() {
      if (convertAllRunning || !folderFiles) return;
      convertAllRunning = true;
      try {
        if (globalThis.__runAllConsumers) {
          var opts = { accept: currentAcceptSet() };
          var all = await globalThis.__runAllConsumers(folderFiles, opts);
          outputFiles         = all.convertedFiles || {};
          taintResults        = all.taint  || { findings: [], summary: { total: 0 } };
          cspResults          = all.csp    || null;
          fetchResults        = all.fetches || [];
          rejectedAssumptions = all.rejectedAssumptions || [];
          allAssumptions      = all.allAssumptions || [];
        } else {
          outputFiles = {};
        }
        renderFileList();
        renderTaint();
        renderCsp();
        renderFetch();
        renderRejected();
        updateTabCounts();
        updateEditorDecorations();
        document.getElementById('downloadAll').disabled = !Object.keys(outputFiles).length;

        // If the active file's converted view was showing but it no
        // longer has an output, fall back to source.
        if (activeFile && activeFile.view === 'converted' &&
            outputFiles[activeFile.path] == null) {
          selectFile(activeFile.path, 'source');
        } else if (activeFile) {
          // Re-enable the Converted toggle if output appeared.
          var btnCvt = document.getElementById('viewConverted');
          btnCvt.disabled = outputFiles[activeFile.path] == null;
        }
      } finally {
        convertAllRunning = false;
      }
    }

    // --- Tab switching --------------------------------------------------
    function setTab(tab) {
      activeTab = tab;
      var tabs = document.querySelectorAll('.dock-tab');
      for (var i = 0; i < tabs.length; i++) {
        tabs[i].classList.toggle('active', tabs[i].dataset.tab === tab);
      }
      var panels = document.querySelectorAll('.dock-panel');
      for (var j = 0; j < panels.length; j++) {
        panels[j].classList.toggle('active', panels[j].dataset.panel === tab);
      }
    }

    function updateTabCounts() {
      var t = taintResults ? taintResults.findings.length : 0;
      var c = cspResults ? Object.keys(cspResults).filter(function (k) {
        return !/^report-/.test(k) && Array.isArray(cspResults[k]) && cspResults[k].length;
      }).length : 0;
      var n = fetchResults ? fetchResults.length : 0;
      var r = rejectedAssumptions ? rejectedAssumptions.length : 0;
      document.getElementById('countTaint').textContent = t;
      document.getElementById('countTaint').classList.toggle('high', t > 0);
      document.getElementById('countCsp').textContent = c;
      document.getElementById('countNetwork').textContent = n;
      document.getElementById('countRejected').textContent = r;
      document.getElementById('countRejected').classList.toggle('high', r > 0);
    }

    // --- Exploit delivery formatting -----------------------------------
    //
    // Turns a finding's `poc` into a reproducer snippet the user
    // can run. Keyed off the source label (e.g. `url` →
    // attacker-supplied URL, `postMessage` → postMessage call).
    // Multi-source flows get one snippet per binding, joined with
    // newlines.
    function formatDelivery(sourceLabel, payload) {
      var json = JSON.stringify(payload);
      switch (sourceLabel) {
        case 'url':
        case 'attacker-input':
          return '// Deliver as URL — victim visits:\n' +
                 '// https://target.example/page#' + encodeURIComponent(payload) + '\n' +
                 '// (or ?q=' + encodeURIComponent(payload) + ')';
        case 'referrer':
          return '// Attacker page sets document.referrer to:\n// ' + payload;
        case 'postMessage':
          return 'window.postMessage(' + json + ', "*");';
        case 'persistent-state':
          return 'localStorage.setItem("key", ' + json + ');\n' +
                 '// or: document.cookie = "key=" + ' + json + ';';
        case 'dom-state':
          return '// Plant in DOM first, e.g.:\n' +
                 'document.querySelector("#target").textContent = ' + json + ';';
        case 'ui-interaction':
          return '// Victim types / pastes / drops:\n// ' + payload;
        case 'network':
          return '// Backend responds with:\n// ' + payload;
        default:
          return '// ' + (sourceLabel || 'attacker-input') + ' = ' + payload;
      }
    }

    function formatExploitDelivery(finding) {
      var poc = finding.poc;
      if (!poc || poc.payload == null) return '';
      var header = '// ' + (finding.severity || '').toUpperCase() + ': ' +
        finding.sources.join(', ') + ' → ' + finding.sink.prop +
        (finding.sink.elementTag ? ' on <' + finding.sink.elementTag + '>' : '') +
        '\n// Attempt: ' + (poc.attempt || 'direct') +
        (finding.file ? '\n// Site: ' + finding.file +
          (finding.location && finding.location.line ? ':' + finding.location.line : '') : '') +
        '\n// Payload: ' + poc.payload + '\n';
      var bindings = poc.bindings;
      if (!bindings || Object.keys(bindings).length === 0) {
        // Single-source direct flow.
        var label = finding.sources[0] || 'attacker-input';
        return header + '\n' + formatDelivery(label, poc.payload);
      }
      var parts = [header];
      var keys = Object.keys(bindings);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (k === '__const__') continue;
        parts.push('\n// Source: ' + k);
        parts.push(formatDelivery(k, bindings[k]));
      }
      return parts.join('\n');
    }

    // --- Assumption chips -----------------------------------------------
    function buildAssumptionChips(assumptions) {
      if (!assumptions || !assumptions.length) return null;
      var accept = currentAcceptSet();
      var acceptSet = accept ? new Set(accept) : null;
      var wrap = document.createElement('div');
      var seen = Object.create(null);
      for (var i = 0; i < assumptions.length; i++) {
        var a = assumptions[i];
        if (seen[a.reason]) continue;
        seen[a.reason] = true;
        var chip = document.createElement('span');
        chip.className = 'assumption-chip severity-' + (a.severity || 'precision');
        if (acceptSet && !acceptSet.has(a.reason)) {
          chip.className += ' rejected';
        }
        chip.textContent = a.reason;
        chip.title = (a.details || '') +
          (a.location && a.location.file
            ? '\n@ ' + a.location.file + ':' + (a.location.line || 0)
            : '') +
          '\nseverity: ' + (a.severity || 'precision');
        wrap.appendChild(chip);
      }
      return wrap;
    }

    // --- Taint panel ----------------------------------------------------
    function renderTaint() {
      var container = document.getElementById('panelTaint');
      if (!taintResults || !taintResults.findings.length) {
        container.innerHTML = '<div class="empty-hint" style="padding: 0.8rem 0.9rem; color: #555; font-style: italic;">No security issues found</div>';
        return;
      }
      container.innerHTML = '';
      var f = taintResults.findings;
      for (var i = 0; i < f.length; i++) {
        var finding = f[i];
        var el = document.createElement('div');
        el.className = 'row';

        var head = document.createElement('div');
        head.className = 'row-head';

        var sev = document.createElement('span');
        sev.className = 'severity ' + finding.severity;
        sev.textContent = finding.severity.toUpperCase();
        head.appendChild(sev);

        var flow = document.createElement('span');
        var sinkLabel = finding.sink.prop +
          (finding.sink.elementTag ? ' on <' + finding.sink.elementTag + '>' : '');
        flow.innerHTML = finding.sources.join(', ') +
          ' <span class="flow-arrow">&rarr;</span> ' + sinkLabel;
        head.appendChild(flow);

        if (finding.poc && finding.poc.verdict) {
          var v = document.createElement('span');
          v.className = 'verdict ' + finding.poc.verdict;
          v.textContent = finding.poc.verdict;
          head.appendChild(v);
        }

        if (finding.file) {
          var loc = document.createElement('span');
          loc.className = 'row-loc';
          loc.textContent = finding.file +
            (finding.location && finding.location.line ? ':' + finding.location.line : '');
          head.appendChild(loc);
        }

        el.appendChild(head);

        if (finding.poc && finding.poc.payload != null) {
          var p = document.createElement('div');
          p.className = 'row-payload';
          var lbl = document.createElement('span');
          lbl.className = 'row-payload-label';
          lbl.textContent = 'payload' +
            (finding.poc.attempt ? ' (' + finding.poc.attempt + ')' : '');
          p.appendChild(lbl);
          p.appendChild(document.createTextNode(finding.poc.payload));
          var copyBtn = document.createElement('button');
          copyBtn.className = 'copy-exploit';
          copyBtn.textContent = 'Copy exploit';
          copyBtn.addEventListener('click', (function (f) {
            return function (ev) {
              ev.stopPropagation();
              var snippet = formatExploitDelivery(f);
              navigator.clipboard.writeText(snippet).then(function () {
                copyBtn.textContent = 'Copied!';
                setTimeout(function () { copyBtn.textContent = 'Copy exploit'; }, 1200);
              }, function () {
                copyBtn.textContent = 'Copy failed';
              });
            };
          })(finding));
          p.appendChild(copyBtn);
          el.appendChild(p);
        } else if (finding.poc && finding.poc.note) {
          var note = document.createElement('div');
          note.className = 'row-sub';
          note.textContent = finding.poc.note;
          el.appendChild(note);
        }

        if (finding.conditions && finding.conditions.length) {
          var cond = document.createElement('div');
          cond.className = 'row-sub';
          cond.textContent = 'when ' + finding.conditions.join(' && ');
          el.appendChild(cond);
        }

        var chips = buildAssumptionChips(finding.assumptions);
        if (chips) el.appendChild(chips);

        (function (fi) {
          el.addEventListener('click', function () {
            if (fi.file && folderFiles[fi.file]) {
              selectFile(fi.file, 'source');
              if (fi.location && fi.location.line) {
                editor.revealLineInCenter(fi.location.line);
              }
            }
          });
        })(finding);
        container.appendChild(el);
      }
    }

    // --- CSP panel ------------------------------------------------------
    function renderCsp() {
      var container = document.getElementById('panelCsp');
      if (!cspResults) {
        container.innerHTML = '<div class="empty-hint" style="padding: 0.8rem 0.9rem; color: #555; font-style: italic;">CSP derivation pending</div>';
        return;
      }
      container.innerHTML = '';
      var directives = ['default-src','script-src','style-src','img-src','connect-src','frame-src','worker-src','font-src','media-src','object-src','base-uri','form-action','frame-ancestors'];
      var hasAny = false;
      directives.forEach(function (d) {
        var vals = cspResults[d];
        if (!vals || !vals.length) return;
        hasAny = true;
        var el = document.createElement('div');
        el.className = 'row';
        var dir = document.createElement('div');
        dir.className = 'csp-dir';
        dir.textContent = d;
        el.appendChild(dir);
        var val = document.createElement('div');
        val.className = 'csp-val';
        val.textContent = vals.join(' ');
        el.appendChild(val);
        container.appendChild(el);
      });
      if (cspResults['report-unsafe-inline']) {
        var w = document.createElement('div');
        w.className = 'row';
        var ww = document.createElement('div');
        ww.className = 'csp-warn';
        ww.textContent = "! 'unsafe-inline' required: bundle uses innerHTML / inline handlers the analyser couldn't otherwise justify";
        w.appendChild(ww);
        container.appendChild(w);
        hasAny = true;
      }
      if (cspResults['report-unsafe-eval']) {
        var w2 = document.createElement('div');
        w2.className = 'row';
        var ww2 = document.createElement('div');
        ww2.className = 'csp-warn';
        ww2.textContent = "! 'unsafe-eval' required: bundle calls eval / new Function / setTimeout(string)";
        w2.appendChild(ww2);
        container.appendChild(w2);
        hasAny = true;
      }
      if (!hasAny) {
        container.innerHTML = '<div class="empty-hint" style="padding: 0.8rem 0.9rem; color: #555; font-style: italic;">No directives derived</div>';
      }
    }

    // --- Fetch panel ----------------------------------------------------
    function renderFetch() {
      var container = document.getElementById('panelNetwork');
      if (!fetchResults || !fetchResults.length) {
        container.innerHTML = '<div class="empty-hint" style="padding: 0.8rem 0.9rem; color: #555; font-style: italic;">No network calls discovered</div>';
        return;
      }
      container.innerHTML = '';
      fetchResults.forEach(function (s) {
        var el = document.createElement('div');
        el.className = 'row';
        var head = document.createElement('div');
        head.className = 'row-head';

        var api = document.createElement('span');
        api.className = 'fetch-api';
        api.textContent = s.api;
        head.appendChild(api);

        if (s.method) {
          var m = document.createElement('span');
          m.className = 'fetch-method';
          m.textContent = s.method;
          head.appendChild(m);
        }

        var url = document.createElement('span');
        url.className = 'fetch-url' + (s.urlLabels && s.urlLabels.length ? ' tainted' : '');
        url.textContent = s.url || '<dynamic url>';
        head.appendChild(url);

        var loc = s.site || null;
        if (loc && loc.file) {
          var ls = document.createElement('span');
          ls.className = 'row-loc';
          ls.textContent = loc.file + (loc.line ? ':' + loc.line : '');
          head.appendChild(ls);
        }

        el.appendChild(head);

        if (loc && loc.file) {
          (function (lc) {
            el.addEventListener('click', function () {
              if (folderFiles[lc.file]) {
                selectFile(lc.file, 'source');
                if (lc.line) editor.revealLineInCenter(lc.line);
              }
            });
          })(loc);
        }

        container.appendChild(el);
      });
    }

    // --- Rejected assumptions panel -------------------------------------
    function renderRejected() {
      var container = document.getElementById('panelRejected');
      if (!rejectedAssumptions || !rejectedAssumptions.length) {
        container.innerHTML = '<div class="empty-hint" style="padding: 0.8rem 0.9rem; color: #555; font-style: italic;">None — the accept set covered every raised assumption</div>';
        return;
      }
      container.innerHTML = '';
      for (var i = 0; i < rejectedAssumptions.length; i++) {
        var a = rejectedAssumptions[i];
        var el = document.createElement('div');
        el.className = 'row';
        var head = document.createElement('div');
        head.className = 'row-head';
        var r = document.createElement('span');
        r.className = 'rejected-reason';
        r.textContent = a.reason;
        head.appendChild(r);
        var sev = document.createElement('span');
        sev.className = 'severity ' + (a.severity === 'soundness' ? 'high' : 'medium');
        sev.textContent = a.severity || 'precision';
        head.appendChild(sev);
        if (a.location && a.location.file) {
          var ls = document.createElement('span');
          ls.className = 'row-loc';
          ls.textContent = a.location.file + (a.location.line ? ':' + a.location.line : '');
          head.appendChild(ls);
        }
        el.appendChild(head);
        if (a.details) {
          var d = document.createElement('div');
          d.className = 'row-sub';
          d.textContent = a.details;
          el.appendChild(d);
        }
        (function (ai) {
          el.addEventListener('click', function () {
            if (ai.location && ai.location.file && folderFiles[ai.location.file]) {
              selectFile(ai.location.file, 'source');
              if (ai.location.line) editor.revealLineInCenter(ai.location.line);
            }
          });
        })(a);
        container.appendChild(el);
      }
    }

    // --- Editor decorations ---------------------------------------------
    function updateEditorDecorations() {
      if (!taintResults || !activeFile) {
        editorDecorations = editor.deltaDecorations(editorDecorations, []);
        return;
      }
      if (activeFile.view === 'converted') {
        // Decorations are keyed to source-file line numbers; the converted
        // view's line mapping is different, so skip.
        editorDecorations = editor.deltaDecorations(editorDecorations, []);
        return;
      }
      var file = activeFile.path;
      var decorations = [];
      for (var i = 0; i < taintResults.findings.length; i++) {
        var f = taintResults.findings[i];
        if (f.file !== file || !f.location || !f.location.line) continue;
        var line = f.location.line;
        var cls = 'taint-decoration-' + f.severity;
        var sinkLabel = (f.sink.kind ? f.sink.kind + ':' : '') + f.sink.prop +
          (f.sink.elementTag ? ' on <' + f.sink.elementTag + '>' : '');
        var hoverLines = [
          '**' + f.severity.toUpperCase() + '**: ' +
            f.sources.join(', ') + ' \u2192 ' + sinkLabel,
        ];
        if (f.poc && f.poc.payload != null) {
          hoverLines.push('', '_payload:_ `' + f.poc.payload + '`');
        }
        if (f.conditions && f.conditions.length) {
          hoverLines.push('', '_when:_ `' + f.conditions.join(' && ') + '`');
        }
        if (f.assumptions && f.assumptions.length) {
          var reasons = [];
          var seen = {};
          for (var ri = 0; ri < f.assumptions.length; ri++) {
            var rr = f.assumptions[ri].reason;
            if (!seen[rr]) { seen[rr] = 1; reasons.push(rr); }
          }
          hoverLines.push('', '_assumes:_ ' + reasons.join(', '));
        }
        decorations.push({
          range: new monaco.Range(line, 1, line, 1),
          options: {
            isWholeLine: true,
            className: cls,
            hoverMessage: { value: hoverLines.join('\n') },
          }
        });
      }
      editorDecorations = editor.deltaDecorations(editorDecorations, decorations);
    }

    // --- Mode + custom accept modal -------------------------------------
    var modeSelect = document.getElementById('analysisMode');
    var customBtn = document.getElementById('customAccept');
    var modal = document.getElementById('acceptModal');
    var modalBody = document.getElementById('acceptModalBody');
    var modalClose = document.getElementById('acceptModalClose');
    var modalApply = document.getElementById('acceptModalApply');

    function populateModal() {
      var hint = modalBody.querySelector('.modal-hint');
      modalBody.innerHTML = '';
      if (hint) modalBody.appendChild(hint);
      var catalog = globalThis.__assumptionCatalog || [];
      var preset = customAccept != null
        ? customAccept
        : (globalThis.__buildAcceptSet
            ? (globalThis.__buildAcceptSet(analysisMode) ||
               Array.from(globalThis.Jsanalyze.DEFAULT_ACCEPT || []))
            : []);
      var presetSet = new Set(preset);
      catalog.forEach(function (group) {
        var g = document.createElement('div');
        g.className = 'accept-group';
        var h = document.createElement('div');
        h.className = 'accept-group-head';
        h.textContent = group.group;
        g.appendChild(h);
        var n = document.createElement('div');
        n.className = 'accept-group-note';
        n.textContent = group.note;
        g.appendChild(n);
        group.reasons.forEach(function (reason) {
          var lbl = document.createElement('label');
          lbl.className = 'accept-reason';
          var cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.value = reason;
          cb.checked = presetSet.has(reason);
          lbl.appendChild(cb);
          lbl.appendChild(document.createTextNode(reason));
          g.appendChild(lbl);
        });
        modalBody.appendChild(g);
      });
    }

    function openCustomModal() { populateModal(); modal.style.display = 'flex'; }
    function closeCustomModal() { modal.style.display = 'none'; }

    modeSelect.addEventListener('change', function () {
      analysisMode = modeSelect.value;
      customBtn.style.display = (analysisMode === 'custom') ? '' : 'none';
      if (analysisMode === 'custom') openCustomModal();
      else convertAll();
    });
    customBtn.addEventListener('click', openCustomModal);
    modalClose.addEventListener('click', closeCustomModal);
    modal.addEventListener('click', function (e) {
      if (e.target === modal) closeCustomModal();
    });
    modalApply.addEventListener('click', function () {
      var checks = modalBody.querySelectorAll('input[type=checkbox]');
      var picked = [];
      for (var i = 0; i < checks.length; i++) {
        if (checks[i].checked) picked.push(checks[i].value);
      }
      customAccept = picked;
      analysisMode = 'custom';
      modeSelect.value = 'custom';
      customBtn.style.display = '';
      closeCustomModal();
      convertAll();
    });

    // --- Dock tab clicks ------------------------------------------------
    var tabs = document.querySelectorAll('.dock-tab');
    for (var ti = 0; ti < tabs.length; ti++) {
      tabs[ti].addEventListener('click', (function (t) {
        return function () { setTab(t); };
      })(tabs[ti].dataset.tab));
    }

    // --- View toggle (Source / Converted) -------------------------------
    document.getElementById('viewOriginal').addEventListener('click', function () {
      if (activeFile) selectFile(activeFile.path, 'source');
    });
    document.getElementById('viewConverted').addEventListener('click', function () {
      if (activeFile && outputFiles[activeFile.path] != null) {
        selectFile(activeFile.path, 'converted');
      }
    });

    // --- Open Folder ----------------------------------------------------
    document.getElementById('openFolder').addEventListener('click', async function () {
      if (!window.showDirectoryPicker) {
        alert('File System Access API not supported. Use Chrome or Edge.');
        return;
      }
      try {
        dirHandle = await window.showDirectoryPicker({ mode: 'read' });
        folderFiles = await readFolder(dirHandle, '');
        outputFiles = {};
        document.getElementById('folderName').textContent = dirHandle.name;
        renderFileList();
        await convertAll();
        var first = Object.keys(folderFiles).sort().find(function (n) {
          return /\.html?$/i.test(n);
        });
        if (first) selectFile(first, 'source');
      } catch (e) {
        if (e.name !== 'AbortError') console.error(e);
      }
    });

    // --- Downloads ------------------------------------------------------
    document.getElementById('downloadCurrent').addEventListener('click', function () {
      if (!activeFile || outputFiles[activeFile.path] == null) return;
      downloadFile(activeFile.path, outputFiles[activeFile.path]);
    });

    document.getElementById('downloadAll').addEventListener('click', async function () {
      if (!Object.keys(outputFiles).length) return;
      try {
        var saveHandle = dirHandle;
        if (!saveHandle || !saveHandle.requestPermission) {
          if (!window.showDirectoryPicker) {
            Object.keys(outputFiles).forEach(function (path) {
              downloadFile(path, outputFiles[path]);
            });
            return;
          }
          saveHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
        } else {
          var perm = await saveHandle.requestPermission({ mode: 'readwrite' });
          if (perm !== 'granted') {
            saveHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
          }
        }
        var convertedDir = await saveHandle.getDirectoryHandle('converted', { create: true });
        for (var path of Object.keys(outputFiles)) {
          var parts = path.split('/');
          var dir = convertedDir;
          for (var pi = 0; pi < parts.length - 1; pi++) {
            dir = await dir.getDirectoryHandle(parts[pi], { create: true });
          }
          var fileHandle = await dir.getFileHandle(parts[parts.length - 1], { create: true });
          var writable = await fileHandle.createWritable();
          await writable.write(outputFiles[path]);
          await writable.close();
        }
        document.getElementById('folderName').textContent += ' — saved to converted/';
      } catch (e) {
        if (e.name !== 'AbortError') console.error('Save failed:', e);
      }
    });

    function downloadFile(name, content) {
      var blob = new Blob([content], { type: 'text/plain' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = name.indexOf('/') >= 0 ? name.slice(name.lastIndexOf('/') + 1) : name;
      a.click();
      URL.revokeObjectURL(url);
    }

    document.getElementById('copy').addEventListener('click', async function () {
      try {
        await navigator.clipboard.writeText(editor.getValue());
        this.textContent = 'Copied!';
        var btn = this;
        setTimeout(function () { btn.textContent = 'Copy'; }, 1200);
      } catch (e) {}
    });

    // --- Auto-reconvert on edit -----------------------------------------
    var reconvertTimer = null;
    editor.onDidChangeModelContent(function () {
      if (activeFile && activeFile.view === 'source' &&
          folderFiles[activeFile.path] !== undefined) {
        folderFiles[activeFile.path] = editor.getValue();
      }
      clearTimeout(reconvertTimer);
      reconvertTimer = setTimeout(convertAll, 500);
    });

    // --- Initial analyse ------------------------------------------------
    var initTimer = setInterval(function () {
      if (globalThis.__runAllConsumers) {
        clearInterval(initTimer);
        convertAll();
        selectFile('example.html', 'source');
      }
    }, 50);
  });
})();
