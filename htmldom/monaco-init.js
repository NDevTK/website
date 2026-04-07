// Monaco Editor initialization.
// Uses the AMD loader from the CDN. The loader must be fully loaded
// (via the <script> tag) before this script runs.
(function () {
  'use strict';
  var CDN = 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.53.0/min/vs';

  // Configure the AMD loader.
  require.config({
    paths: { vs: CDN },
    'vs/nls': { availableLanguages: { '*': '' } }
  });

  // Monaco web workers need a special proxy for cross-origin CDN loading.
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

    function autoResize(editor, container, minHeight) {
      function update() {
        var contentHeight = editor.getContentHeight();
        var height = Math.max(contentHeight, minHeight || 100);
        container.style.height = height + 'px';
        editor.layout();
      }
      editor.onDidContentSizeChange(update);
      update();
    }

    window._monacoIn = monaco.editor.create(document.getElementById('inEditor'), {
      value: defaultInput,
      language: 'html',
      theme: 'vs-dark',
      minimap: { enabled: false },
      fontSize: 14,
      lineNumbers: 'on',
      scrollBeyondLastLine: false,
      scrollbar: { vertical: 'hidden', horizontal: 'hidden', handleMouseWheel: false },
      wordWrap: 'on',
      automaticLayout: true,
    });
    autoResize(window._monacoIn, document.getElementById('inEditor'), 100);

    window._monacoOut = monaco.editor.create(document.getElementById('outEditor'), {
      value: '',
      language: 'javascript',
      theme: 'vs-dark',
      minimap: { enabled: false },
      fontSize: 14,
      lineNumbers: 'on',
      readOnly: true,
      scrollBeyondLastLine: false,
      scrollbar: { vertical: 'hidden', horizontal: 'hidden', handleMouseWheel: false },
      wordWrap: 'on',
      automaticLayout: true,
    });
    autoResize(window._monacoOut, document.getElementById('outEditor'), 50);

    window._monacoIn.onDidChangeModelContent(function () {
      var text = window._monacoIn.getValue();
      var model = window._monacoIn.getModel();
      var lang = /^\s*</.test(text) ? 'html' : 'javascript';
      if (model && monaco.editor.getModel(model.uri)) {
        monaco.editor.setModelLanguage(model, lang);
      }
    });

    // Load htmldom.js after Monaco is ready.
    var s = document.createElement('script');
    s.src = 'htmldom.js';
    document.body.appendChild(s);

    // --- File System Access API: folder selection ---

    // Stored file contents from the opened folder.
    var folderFiles = null; // { name: content } map

    // Recursively read all .html, .htm, .js files from a directory handle.
    async function readFolderRecursive(dirHandle, prefix) {
      var files = {};
      for await (var entry of dirHandle.values()) {
        var path = prefix ? prefix + '/' + entry.name : entry.name;
        if (entry.kind === 'file') {
          if (/\.(html?|js)$/i.test(entry.name)) {
            var file = await entry.getFile();
            files[path] = await file.text();
          }
        } else if (entry.kind === 'directory' && entry.name !== 'node_modules' && entry.name !== '.git') {
          var sub = await readFolderRecursive(entry, path);
          for (var k in sub) files[k] = sub[k];
        }
      }
      return files;
    }

    // Resolve <script src="..."> references in an HTML file to build a
    // combined source with all scripts inlined in order. This gives the
    // converter full cross-file scope.
    function resolveScriptSrcs(htmlContent, htmlPath, files) {
      var dir = htmlPath.indexOf('/') >= 0 ? htmlPath.slice(0, htmlPath.lastIndexOf('/')) : '';
      return htmlContent.replace(/<script\s+src="([^"]+)"[^>]*><\/script>/gi, function(match, src) {
        var resolved = dir ? dir + '/' + src : src;
        // Normalize path (handle ../ etc.)
        var parts = resolved.split('/');
        var normalized = [];
        for (var i = 0; i < parts.length; i++) {
          if (parts[i] === '..') { normalized.pop(); }
          else if (parts[i] !== '.') { normalized.push(parts[i]); }
        }
        var key = normalized.join('/');
        if (files[key]) {
          return '<script>\n' + files[key] + '\n<\/script>';
        }
        return match; // keep original if file not found
      });
    }

    // Populate the file selector dropdown.
    function populateFileSelect(files) {
      var sel = document.getElementById('fileSelect');
      sel.innerHTML = '<option value="">-- Select a file --</option>';
      var names = Object.keys(files).sort();
      for (var i = 0; i < names.length; i++) {
        var opt = document.createElement('option');
        opt.value = names[i];
        opt.textContent = names[i];
        sel.appendChild(opt);
      }
      sel.style.display = names.length ? '' : 'none';
    }

    // When a file is selected, load it into the editor with scripts resolved.
    document.getElementById('fileSelect').addEventListener('change', function() {
      var name = this.value;
      if (!name || !folderFiles) return;
      var content = folderFiles[name];
      if (/\.html?$/i.test(name)) {
        content = resolveScriptSrcs(content, name, folderFiles);
      }
      window._monacoIn.setValue(content);
    });

    // Open folder button.
    document.getElementById('openFolder').addEventListener('click', async function() {
      if (!window.showDirectoryPicker) {
        alert('File System Access API not supported in this browser.');
        return;
      }
      try {
        var dirHandle = await window.showDirectoryPicker({ mode: 'read' });
        document.getElementById('folderName').textContent = dirHandle.name;
        folderFiles = await readFolderRecursive(dirHandle, '');
        populateFileSelect(folderFiles);

        // Auto-select the first HTML file.
        var htmlFiles = Object.keys(folderFiles).filter(function(n) { return /\.html?$/i.test(n); });
        if (htmlFiles.length) {
          var sel = document.getElementById('fileSelect');
          sel.value = htmlFiles[0];
          sel.dispatchEvent(new Event('change'));
        }
      } catch (e) {
        if (e.name !== 'AbortError') {
          console.error('Failed to read folder:', e);
        }
      }
    });
  });
})();
