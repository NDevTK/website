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
      var js = 'self.MonacoEnvironment = { baseUrl: "' + CDN + '/" }; importScripts("' + CDN + '/base/worker/workerMain.js");';
      return URL.createObjectURL(new Blob([js], { type: 'text/javascript' }));
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
  });
})();
