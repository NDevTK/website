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

    function autoResize(editor, container) {
      function update() {
        var contentHeight = editor.getContentHeight();
        container.style.height = Math.max(contentHeight, 100) + 'px';
        editor.layout();
      }
      editor.onDidContentSizeChange(update);
      update();
    }

    var editorOpts = {
      theme: 'vs-dark', minimap: { enabled: false }, fontSize: 14,
      lineNumbers: 'on', scrollBeyondLastLine: false,
      scrollbar: { vertical: 'hidden', horizontal: 'hidden', handleMouseWheel: false },
      wordWrap: 'on', automaticLayout: true,
    };

    window._monacoIn = monaco.editor.create(document.getElementById('inEditor'),
      Object.assign({ value: defaultInput, language: 'html' }, editorOpts));

    window._monacoOut = monaco.editor.create(document.getElementById('outEditor'),
      Object.assign({ value: '', language: 'javascript', readOnly: true }, editorOpts));

    // Tab switching.
    var activeTab = 'input';
    document.querySelectorAll('.editor-tabs .tab').forEach(function(tab) {
      tab.addEventListener('click', function() {
        activeTab = tab.dataset.tab;
        document.querySelectorAll('.editor-tabs .tab').forEach(function(t) { t.classList.toggle('active', t === tab); });
        document.getElementById('inEditor').style.display = activeTab === 'input' ? '' : 'none';
        document.getElementById('outEditor').style.display = activeTab === 'output' ? '' : 'none';
        if (activeTab === 'input') window._monacoIn.layout();
        else window._monacoOut.layout();
      });
    });

    // Auto-detect language.
    window._monacoIn.onDidChangeModelContent(function () {
      var text = window._monacoIn.getValue();
      var model = window._monacoIn.getModel();
      var lang = /^\s*</.test(text) ? 'html' : 'javascript';
      if (model) monaco.editor.setModelLanguage(model, lang);
    });

    // Load htmldom.js.
    var s = document.createElement('script');
    s.src = 'htmldom.js';
    document.body.appendChild(s);

    // --- Multi-file project support ---

    var folderFiles = null;   // { path: content }
    var convertedFiles = {};  // { path: convertedContent }
    var currentFile = null;

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
        var key = norm.join('/');
        return files[key] ? '<script>\n' + files[key] + '\n<\/script>' : match;
      });
    }

    function getFileIcon(name) {
      if (/\.html?$/i.test(name)) return '📄';
      if (/\.js$/i.test(name)) return '📜';
      if (/\.css$/i.test(name)) return '🎨';
      return '📎';
    }

    function buildFileTree() {
      var tree = document.getElementById('fileTree');
      tree.innerHTML = '';
      if (!folderFiles) return;
      var paths = Object.keys(folderFiles).sort();
      paths.forEach(function(path) {
        var el = document.createElement('div');
        el.className = 'file-item' + (path === currentFile ? ' active' : '');
        el.dataset.path = path;

        var icon = document.createElement('span');
        icon.className = 'icon';
        icon.textContent = getFileIcon(path);
        el.appendChild(icon);

        var name = document.createElement('span');
        name.textContent = path;
        el.appendChild(name);

        // Badge: converted / has innerHTML / clean.
        var badge = document.createElement('span');
        badge.className = 'badge';
        if (convertedFiles[path]) {
          badge.className += ' converted';
          badge.textContent = 'converted';
        } else if (/\.innerHTML\s*[+=]/.test(folderFiles[path])) {
          badge.className += ' has-inner';
          badge.textContent = 'innerHTML';
        } else {
          badge.className += ' clean';
          badge.textContent = 'clean';
        }
        el.appendChild(badge);

        el.addEventListener('click', function() { selectFile(path); });
        tree.appendChild(el);
      });
    }

    function selectFile(path) {
      // Save current output if converted.
      if (currentFile && activeTab === 'output') {
        var out = window._monacoOut.getValue();
        if (out) convertedFiles[currentFile] = out;
      }

      currentFile = path;
      var content = folderFiles[path];
      if (/\.html?$/i.test(path)) {
        content = resolveScriptSrcs(content, path, folderFiles);
      }
      window._monacoIn.setValue(content);

      // Show converted output if available.
      if (convertedFiles[path]) {
        window._monacoOut.setValue(convertedFiles[path]);
      }

      document.getElementById('downloadCurrent').disabled = !convertedFiles[path];
      buildFileTree();
    }

    function convertCurrent() {
      // Trigger the converter (htmldom.js listens on input change).
      // Give it a tick to process, then capture the output.
      setTimeout(function() {
        if (currentFile && window._monacoOut) {
          var out = window._monacoOut.getValue();
          if (out && out !== '// (no nodes parsed)') {
            convertedFiles[currentFile] = out;
          }
          document.getElementById('downloadCurrent').disabled = !convertedFiles[currentFile];
          buildFileTree();
          updateStatus();
        }
      }, 100);
    }

    function updateStatus() {
      if (!folderFiles) return;
      var total = Object.keys(folderFiles).length;
      var converted = Object.keys(convertedFiles).length;
      document.getElementById('folderName').textContent = converted + '/' + total + ' files converted';
      document.getElementById('downloadAll').disabled = converted === 0;
    }

    // Auto-convert on input change when in folder mode.
    window._monacoIn.onDidChangeModelContent(function() {
      if (folderFiles && currentFile) convertCurrent();
    });

    // Open Folder.
    document.getElementById('openFolder').addEventListener('click', async function() {
      if (!window.showDirectoryPicker) {
        alert('File System Access API not supported. Use Chrome or Edge.');
        return;
      }
      try {
        var dirHandle = await window.showDirectoryPicker({ mode: 'read' });
        folderFiles = await readFolder(dirHandle, '');
        convertedFiles = {};
        document.getElementById('sidebarPanel').style.display = '';
        document.getElementById('folderName').textContent = dirHandle.name;
        document.getElementById('processAll').disabled = false;
        buildFileTree();
        updateStatus();

        // Auto-select first HTML file.
        var htmlFiles = Object.keys(folderFiles).filter(function(n) { return /\.html?$/i.test(n); });
        if (htmlFiles.length) selectFile(htmlFiles[0]);
      } catch (e) {
        if (e.name !== 'AbortError') console.error(e);
      }
    });

    // Paste Mode — hide sidebar, clear folder state.
    document.getElementById('pasteMode').addEventListener('click', function() {
      folderFiles = null;
      convertedFiles = {};
      currentFile = null;
      document.getElementById('sidebarPanel').style.display = 'none';
      document.getElementById('processAll').disabled = true;
      document.getElementById('downloadCurrent').disabled = true;
      document.getElementById('downloadAll').disabled = true;
      document.getElementById('folderName').textContent = '';
      document.getElementById('fileSelect').style.display = 'none';
      window._monacoIn.setValue(defaultInput);
    });

    // Convert All — process each file sequentially.
    document.getElementById('processAll').addEventListener('click', async function() {
      if (!folderFiles) return;
      var btn = this;
      btn.disabled = true;
      btn.textContent = 'Converting...';
      var paths = Object.keys(folderFiles).filter(function(p) {
        return /\.(html?|js)$/i.test(p) && /\.innerHTML\s*[+=]/.test(folderFiles[p]);
      });
      for (var i = 0; i < paths.length; i++) {
        selectFile(paths[i]);
        await new Promise(function(resolve) { setTimeout(resolve, 200); });
        var out = window._monacoOut.getValue();
        if (out && out !== '// (no nodes parsed)') {
          convertedFiles[paths[i]] = out;
        }
      }
      buildFileTree();
      updateStatus();
      btn.disabled = false;
      btn.textContent = 'Convert All';
    });

    // Download current file.
    document.getElementById('downloadCurrent').addEventListener('click', function() {
      if (!currentFile || !convertedFiles[currentFile]) return;
      downloadFile(currentFile.replace(/\.[^.]+$/, '.converted.js'), convertedFiles[currentFile]);
    });

    // Download all converted files as individual downloads.
    document.getElementById('downloadAll').addEventListener('click', function() {
      var paths = Object.keys(convertedFiles);
      if (paths.length === 0) return;
      paths.forEach(function(path) {
        downloadFile(path.replace(/\.[^.]+$/, '.converted.js'), convertedFiles[path]);
      });
    });

    function downloadFile(name, content) {
      var blob = new Blob([content], { type: 'text/javascript' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = name.indexOf('/') >= 0 ? name.slice(name.lastIndexOf('/') + 1) : name;
      a.click();
      URL.revokeObjectURL(url);
    }

    // Copy output.
    document.getElementById('copy').addEventListener('click', async function() {
      var text = window._monacoOut.getValue();
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        this.textContent = 'Copied!';
        var btn = this;
        setTimeout(function() { btn.textContent = 'Copy Output'; }, 1200);
      } catch (e) {}
    });
  });
})();
