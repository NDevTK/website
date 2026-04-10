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

    // Single editor — shows whichever file is selected.
    var editor = monaco.editor.create(document.getElementById('editor'), {
      value: defaultInput,
      language: 'html',
      theme: 'vs-dark',
      minimap: { enabled: false },
      fontSize: 14,
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
      wordWrap: 'on',
      automaticLayout: true,
    });

    // Expose for htmldom.js paste-mode auto-convert.
    window._monacoIn = editor;
    window._monacoOut = { setValue: function() {}, getValue: function() { return ''; } };

    // Load jsanalyze-schemas first (needed by the bindingToValue
    // seam inside htmldom.js). Then htmldom.js (which contains the
    // walker + legacy converter). Then the jsanalyze consumer
    // wrappers so page scripts can reach them as globals.
    function appendScript(src, onload) {
      var s = document.createElement('script');
      s.src = src;
      if (onload) s.onload = onload;
      document.body.appendChild(s);
    }
    appendScript('jsanalyze-schemas.js', function () {
      appendScript('htmldom.js', function () {
        appendScript('jsanalyze-query.js');
        appendScript('htmldom-convert.js');
        appendScript('fetch-trace.js');
        appendScript('taint-report.js');
        appendScript('csp-derive.js');
      });
    });

    // --- State ---
    // Start with the example as a single file.
    var folderFiles = { 'example.html': defaultInput };
    var outputFiles = {};
    var dirHandle = null; // FSA directory handle from Open Folder
    var activeFile = null;

    function langFor(name) {
      if (/\.html?$/i.test(name)) return 'html';
      if (/\.css$/i.test(name)) return 'css';
      return 'javascript';
    }

    function iconFor(name) {
      if (/\.html?$/i.test(name)) return '📄';
      if (/\.js$/i.test(name)) return '📜';
      if (/\.css$/i.test(name)) return '🎨';
      return '📎';
    }

    // --- File reading ---
    async function readFolder(dirHandle, prefix) {
      var files = {};
      for await (var entry of dirHandle.values()) {
        var path = prefix ? prefix + '/' + entry.name : entry.name;
        if (entry.kind === 'file' && /\.(html?|js|css)$/i.test(entry.name)) {
          files[path] = await (await entry.getFile()).text();
        } else if (entry.kind === 'directory' && !/^(node_modules|\.git|\.svn|dist|build)$/.test(entry.name)) {
          Object.assign(files, await readFolder(entry, path));
        }
      }
      return files;
    }

    // resolveScriptSrcs and convertPage are in htmldom.js — use the exported API.

    // --- Sidebar rendering ---
    function renderSidebar() {
      renderFileList('originalFiles', folderFiles, 'original');
      renderOutputList();
    }

    function renderFileList(containerId, files, source) {
      var container = document.getElementById(containerId);
      container.innerHTML = '';
      if (!files || !Object.keys(files).length) {
        container.innerHTML = '<div class="empty-hint">No files</div>';
        return;
      }
      Object.keys(files).sort().forEach(function(path) {
        var el = document.createElement('div');
        el.className = 'file-item' + (activeFile && activeFile.path === path && activeFile.source === source ? ' active' : '');
        el.innerHTML = '<span class="icon">' + iconFor(path) + '</span><span class="name">' + path + '</span>';
        // Badge for original files.
        if (source === 'original') {
          var badge = document.createElement('span');
          badge.className = 'badge';
          var isHtml = /\.html?$/i.test(path);
          // Check if this page has output files.
          var hasOutput = isHtml && Object.keys(outputFiles).some(function(op) { return op.indexOf(path.replace(/\.[^.]+$/, '')) === 0; });
          if (hasOutput) {
            badge.className += ' converted';
            badge.textContent = 'converted';
          } else if (isHtml && (/\.innerHTML\s*[+=]/.test(files[path]) || /\bon[a-z]+="|style="/i.test(files[path]))) {
            badge.className += ' has-inner';
            badge.textContent = 'unsafe';
          } else if (/\.js$/i.test(path)) {
            badge.className += ' clean';
            badge.textContent = 'script';
          } else if (/\.css$/i.test(path)) {
            badge.className += ' clean';
            badge.textContent = 'style';
          } else {
            badge.className += ' clean';
            badge.textContent = isHtml ? 'clean' : '';
          }
          el.appendChild(badge);
        } else {
          var badge = document.createElement('span');
          badge.className = 'badge generated';
          badge.textContent = 'generated';
          el.appendChild(badge);
        }
        el.addEventListener('click', function() { selectFile(path, source); });
        container.appendChild(el);
      });
    }

    function renderOutputList() {
      var container = document.getElementById('outputFiles');
      if (!Object.keys(outputFiles).length) {
        container.innerHTML = '<div class="empty-hint">Convert files to see output</div>';
        return;
      }
      renderFileList('outputFiles', outputFiles, 'output');
    }

    // --- File selection ---
    function selectFile(path, source) {
      activeFile = { path: path, source: source };
      var content = source === 'output' ? outputFiles[path] : folderFiles[path];
      editor.setValue(content || '');
      monaco.editor.setModelLanguage(editor.getModel(), langFor(path));
      editor.updateOptions({ readOnly: source === 'output' });
      document.getElementById('editorFilename').textContent = (source === 'output' ? '[output] ' : '') + path;
      document.getElementById('downloadCurrent').disabled = source !== 'output';
      renderSidebar();
      updateEditorDecorations();
    }

    // --- Conversion ---
    // Use the project-level API from htmldom.js.
    var convertAllRunning = false;
    var taintResults = null;
    var editorDecorations = [];
    function convertAll() {
      if (convertAllRunning || !folderFiles) return;
      convertAllRunning = true;
      // __convertProject processes each HTML page independently.
      outputFiles = globalThis.__convertProject ? globalThis.__convertProject(folderFiles) : {};
      // Run taint analysis.
      if (globalThis.__traceTaint) {
        try {
          taintResults = globalThis.__traceTaint(folderFiles);
        } catch (e) {
          taintResults = { findings: [], summary: { total: 0 } };
        }
      }
      renderSidebar();
      renderTaintFindings();
      updateEditorDecorations();
      document.getElementById('downloadAll').disabled = !Object.keys(outputFiles).length;
      convertAllRunning = false;
    }

    function renderTaintFindings() {
      var container = document.getElementById('taintFindings');
      var summary = document.getElementById('taintSummary');
      if (!taintResults || !taintResults.findings.length) {
        container.innerHTML = '<div class="empty-hint">No security issues found</div>';
        summary.style.display = 'none';
        return;
      }
      var f = taintResults.findings;
      summary.style.display = '';
      var parts = [];
      if (taintResults.summary.high) parts.push(taintResults.summary.high + ' high');
      if (taintResults.summary.medium) parts.push(taintResults.summary.medium + ' medium');
      summary.textContent = f.length + ' finding' + (f.length === 1 ? '' : 's') + (parts.length ? ': ' + parts.join(', ') : '');
      container.innerHTML = '';
      for (var i = 0; i < f.length; i++) {
        var finding = f[i];
        var el = document.createElement('div');
        el.className = 'finding-item';
        var sev = document.createElement('span');
        sev.className = 'finding-severity ' + finding.severity;
        sev.textContent = finding.severity.toUpperCase();
        el.appendChild(sev);
        var desc = document.createTextNode(finding.sources.join(', ') + ' \u2192 ' + finding.sink.prop + (finding.sink.elementTag ? ' on <' + finding.sink.elementTag + '>' : ''));
        el.appendChild(desc);
        if (finding.file) {
          var flow = document.createElement('div');
          flow.className = 'finding-flow';
          flow.textContent = finding.file + (finding.location && finding.location.line ? ':' + finding.location.line : '');
          el.appendChild(flow);
        }
        if (finding.conditions && finding.conditions.length) {
          var cond = document.createElement('div');
          cond.className = 'finding-cond';
          cond.textContent = 'when: ' + finding.conditions.join(' && ');
          el.appendChild(cond);
        }
        (function(fi) {
          el.addEventListener('click', function() {
            if (fi.file && folderFiles[fi.file]) {
              selectFile(fi.file, 'original');
              if (fi.location && fi.location.line) {
                editor.revealLineInCenter(fi.location.line);
              }
            }
          });
        })(finding);
        container.appendChild(el);
      }
    }

    function updateEditorDecorations() {
      if (!taintResults || !activeFile) { editorDecorations = editor.deltaDecorations(editorDecorations, []); return; }
      var file = activeFile.path;
      var decorations = [];
      for (var i = 0; i < taintResults.findings.length; i++) {
        var f = taintResults.findings[i];
        if (f.file !== file || !f.location || !f.location.line) continue;
        var line = f.location.line;
        var cls = f.severity === 'high' ? 'taint-decoration-high' : 'taint-decoration-medium';
        decorations.push({
          range: new monaco.Range(line, 1, line, 1),
          options: {
            isWholeLine: true,
            className: cls,
            glyphMarginClassName: 'taint-glyph-' + f.severity,
            hoverMessage: { value: '**' + f.severity.toUpperCase() + '**: ' + f.sources.join(', ') + ' \u2192 ' + f.sink.prop + (f.conditions.length ? '\n\nConditions: ' + f.conditions.join(' && ') : '') },
          }
        });
      }
      editorDecorations = editor.deltaDecorations(editorDecorations, decorations);
    }

    // --- Event handlers ---

    document.getElementById('openFolder').addEventListener('click', async function() {
      if (!window.showDirectoryPicker) {
        alert('File System Access API not supported. Use Chrome or Edge.');
        return;
      }
      try {
        dirHandle = await window.showDirectoryPicker({ mode: 'read' });
        folderFiles = await readFolder(dirHandle, '');
        outputFiles = {};
        document.getElementById('folderName').textContent = dirHandle.name;
        renderSidebar();
        convertAll();
        var first = Object.keys(folderFiles).sort().find(function(n) { return /\.html?$/i.test(n); });
        if (first) selectFile(first, 'original');
      } catch (e) {
        if (e.name !== 'AbortError') console.error(e);
      }
    });

    document.getElementById('downloadCurrent').addEventListener('click', function() {
      if (!activeFile || activeFile.source !== 'output') return;
      downloadFile(activeFile.path, outputFiles[activeFile.path]);
    });

    document.getElementById('downloadAll').addEventListener('click', async function() {
      if (!Object.keys(outputFiles).length) return;
      try {
        // Use the opened folder's handle or prompt for one.
        var saveHandle = dirHandle;
        if (!saveHandle || !saveHandle.requestPermission) {
          if (!window.showDirectoryPicker) {
            // Fallback: download each file individually.
            Object.keys(outputFiles).forEach(function(path) { downloadFile(path, outputFiles[path]); });
            return;
          }
          saveHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
        } else {
          // Request write permission on the existing handle.
          var perm = await saveHandle.requestPermission({ mode: 'readwrite' });
          if (perm !== 'granted') {
            saveHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
          }
        }
        // Create 'converted' subfolder.
        var convertedDir = await saveHandle.getDirectoryHandle('converted', { create: true });
        // Write each output file, creating subdirectories as needed.
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

    document.getElementById('copy').addEventListener('click', async function() {
      try {
        await navigator.clipboard.writeText(editor.getValue());
        this.textContent = 'Copied!';
        var btn = this;
        setTimeout(function() { btn.textContent = 'Copy'; }, 1200);
      } catch (e) {}
    });

    // On editor change: update the source file and re-convert all.
    var reconvertTimer = null;
    editor.onDidChangeModelContent(function() {
      // Update the source file if editing an original.
      if (activeFile && activeFile.source === 'original' && folderFiles[activeFile.path] !== undefined) {
        folderFiles[activeFile.path] = editor.getValue();
      }
      // Debounce re-conversion.
      clearTimeout(reconvertTimer);
      reconvertTimer = setTimeout(function() { convertAll(); }, 500);
    });

    // Initial conversion of the example file.
    // Wait for htmldom.js to load before converting.
    var initTimer = setInterval(function() {
      if (globalThis.__convertProject) {
        clearInterval(initTimer);
        convertAll();
        selectFile('example.html', 'original');
      }
    }, 50);
  });
})();
