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
    var defaultInput = '<div style="position: fixed; z-index: -99; width: 100%; height: 100%">\n  <iframe credentialless loading="lazy" id="background" title="background" sandbox="allow-scripts" frameborder="0" height="100%" width="100%" src="https://random.ndev.tk/"></iframe>\n</div>\n<button onclick="alert(\'hello\')">Greet</button>\n<script>\nvar items = [\'Home\', \'About\', \'Contact\', location.search];\nvar html = \'<nav>\';\nfor (var i = 0; i < items.length; i++) {\n  html += \'<a href="/\' + items[i].toLowerCase() + \'"\' + \'>\' + items[i] + \'</a>\';\n}\nhtml += \'</nav>\';\ndocument.body.innerHTML = html;\n<\/script>';

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

    // Expose for htmldom.js (it reads _monacoIn / _monacoOut).
    window._monacoIn = editor;
    window._monacoOut = {
      setValue: function(v) { outputForCurrent = v; },
      getValue: function() { return outputForCurrent; }
    };

    // Load htmldom.js.
    var s = document.createElement('script');
    s.src = 'htmldom.js';
    document.body.appendChild(s);

    // --- State ---
    var folderFiles = null;      // { path: content } — original files
    var outputFiles = {};         // { path: content } — generated output files
    var outputForCurrent = '';    // output captured from htmldom.js convert()
    var activeFile = null;        // { path, source: 'original'|'output' }
    var pasteMode = true;

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

    function resolveScriptSrcs(html, htmlPath, files) {
      var dir = htmlPath.indexOf('/') >= 0 ? htmlPath.slice(0, htmlPath.lastIndexOf('/')) : '';
      return html.replace(/<script\s+src="([^"]+)"[^>]*><\/script>/gi, function(match, src) {
        var parts = (dir ? dir + '/' + src : src).split('/');
        var norm = [];
        for (var i = 0; i < parts.length; i++) {
          if (parts[i] === '..') norm.pop();
          else if (parts[i] !== '.') norm.push(parts[i]);
        }
        return files[norm.join('/')] ? '<script>\n' + files[norm.join('/')] + '\n<\/script>' : match;
      });
    }

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
          if (outputFiles[path]) {
            badge.className += ' converted';
            badge.textContent = 'converted';
          } else if (/\.innerHTML\s*[+=]/.test(files[path]) || /\bon[a-z]+="|style="/i.test(files[path])) {
            badge.className += ' has-inner';
            badge.textContent = 'unsafe';
          } else {
            badge.className += ' clean';
            badge.textContent = 'clean';
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
    }

    // --- Conversion ---
    function convertFile(path) {
      var content = folderFiles[path];
      if (/\.html?$/i.test(path)) {
        content = resolveScriptSrcs(content, path, folderFiles);
      }
      // Feed to htmldom.js converter via the editor.
      var prev = activeFile;
      editor.setValue(content);
      // htmldom.js auto-converts on change, output captured in outputForCurrent.

      return new Promise(function(resolve) {
        setTimeout(function() {
          var result = outputForCurrent || '';
          if (!result || result === '// (no nodes parsed)') {
            resolve(false);
            return;
          }
          // Parse output into separate files.
          // The converter outputs "// === filename ===" separators for multi-file output.
          var parts = result.split(/^\/\/ === (.+?) ===$/m);
          if (parts.length > 1) {
            // parts[0] is before first separator (usually empty), then alternating name/content.
            for (var i = 1; i < parts.length; i += 2) {
              var name = parts[i].trim();
              var body = (parts[i + 1] || '').trim();
              if (body) outputFiles[name] = body;
            }
          } else {
            // Single output — use the path with .converted extension.
            var outName = path.replace(/\.[^.]+$/, '.safe.js');
            outputFiles[outName] = result;
          }
          resolve(true);
        }, 150);
      });
    }

    // --- Event handlers ---

    document.getElementById('openFolder').addEventListener('click', async function() {
      if (!window.showDirectoryPicker) {
        alert('File System Access API not supported. Use Chrome or Edge.');
        return;
      }
      try {
        var dirHandle = await window.showDirectoryPicker({ mode: 'read' });
        folderFiles = await readFolder(dirHandle, '');
        outputFiles = {};
        pasteMode = false;
        document.getElementById('sidebarPanel').style.display = '';
        document.getElementById('folderName').textContent = dirHandle.name;
        document.getElementById('processAll').disabled = false;
        renderSidebar();
        // Auto-select first HTML file.
        var first = Object.keys(folderFiles).sort().find(function(n) { return /\.html?$/i.test(n); });
        if (first) selectFile(first, 'original');
      } catch (e) {
        if (e.name !== 'AbortError') console.error(e);
      }
    });

    document.getElementById('pasteMode').addEventListener('click', function() {
      folderFiles = null;
      outputFiles = {};
      activeFile = null;
      pasteMode = true;
      document.getElementById('sidebarPanel').style.display = 'none';
      document.getElementById('processAll').disabled = true;
      document.getElementById('downloadCurrent').disabled = true;
      document.getElementById('downloadAll').disabled = true;
      document.getElementById('folderName').textContent = '';
      document.getElementById('editorFilename').textContent = 'Paste mode';
      editor.setValue(defaultInput);
      editor.updateOptions({ readOnly: false });
      monaco.editor.setModelLanguage(editor.getModel(), 'html');
    });

    document.getElementById('processAll').addEventListener('click', async function() {
      if (!folderFiles) return;
      this.disabled = true;
      this.textContent = 'Converting...';
      var paths = Object.keys(folderFiles).filter(function(p) {
        return /\.(html?|js)$/i.test(p);
      });
      for (var i = 0; i < paths.length; i++) {
        await convertFile(paths[i]);
      }
      renderSidebar();
      document.getElementById('downloadAll').disabled = !Object.keys(outputFiles).length;
      this.disabled = false;
      this.textContent = 'Convert All';
      // Show first output file.
      var firstOut = Object.keys(outputFiles).sort()[0];
      if (firstOut) selectFile(firstOut, 'output');
    });

    document.getElementById('downloadCurrent').addEventListener('click', function() {
      if (!activeFile || activeFile.source !== 'output') return;
      downloadFile(activeFile.path, outputFiles[activeFile.path]);
    });

    document.getElementById('downloadAll').addEventListener('click', function() {
      Object.keys(outputFiles).forEach(function(path) {
        downloadFile(path, outputFiles[path]);
      });
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

    // Auto-detect language in paste mode.
    editor.onDidChangeModelContent(function() {
      if (pasteMode) {
        var text = editor.getValue();
        monaco.editor.setModelLanguage(editor.getModel(), /^\s*</.test(text) ? 'html' : 'javascript');
      }
    });
  });
})();
