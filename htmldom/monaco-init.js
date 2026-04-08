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
    // Start with the example as a single file.
    var folderFiles = { 'example.html': defaultInput };
    var outputFiles = {};
    var outputForCurrent = '';
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
    // Convert a single file and store results in outputFiles.
    function convertFile(path) {
      var content = folderFiles[path];
      if (/\.html?$/i.test(path)) {
        content = resolveScriptSrcs(content, path, folderFiles);
      }
      editor.setValue(content);
      return new Promise(function(resolve) {
        setTimeout(function() {
          var result = outputForCurrent || '';
          if (!result || result === '// (no nodes parsed)') { resolve(); return; }
          var parts = result.split(/^\/\/ === (.+?) ===$/m);
          if (parts.length > 1) {
            for (var i = 1; i < parts.length; i += 2) {
              var name = parts[i].trim();
              var body = (parts[i + 1] || '').trim();
              if (body) outputFiles[name] = body;
            }
          } else {
            outputFiles[path.replace(/\.[^.]+$/, '.safe.js')] = result;
          }
          resolve();
        }, 150);
      });
    }

    // Convert all files in the folder sequentially.
    var convertAllRunning = false;
    async function convertAll() {
      if (convertAllRunning) return;
      convertAllRunning = true;
      outputFiles = {};
      // Save current editor state.
      var savedFile = activeFile;
      var savedContent = editor.getValue();
      var paths = Object.keys(folderFiles).filter(function(p) {
        return /\.(html?|js)$/i.test(p);
      });
      for (var i = 0; i < paths.length; i++) {
        await convertFile(paths[i]);
      }
      // Restore editor to what the user was viewing.
      if (savedFile && folderFiles[savedFile.path]) {
        editor.setValue(savedFile.source === 'output' ? (outputFiles[savedFile.path] || '') : savedContent);
        editor.updateOptions({ readOnly: savedFile.source === 'output' });
      } else {
        editor.setValue(savedContent);
      }
      renderSidebar();
      document.getElementById('downloadAll').disabled = !Object.keys(outputFiles).length;
      convertAllRunning = false;
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
        document.getElementById('folderName').textContent = dirHandle.name;
        renderSidebar();
        // Convert all files, then show first HTML file.
        await convertAll();
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
    convertAll().then(function() {
      selectFile('example.html', 'original');
    });
  });
})();
