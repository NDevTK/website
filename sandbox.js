"use strict";
if (window.origin !== "null") {
    // Clear document
    window.document.write('');
    
    let f = document.createElement("iframe");
    f.sandbox = "allow-scripts allow-modals";
    f.src = window.location.href;
    f.addEventListener('popstate', function (event) {
        console.log(event);
    });
    f.style = "width: 100%; height: 100%;";
    
    window.addEventListener('DOMContentLoaded', (event) => {
        document.body.appendChild(f);
    });
}
