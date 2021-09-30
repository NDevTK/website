"use strict";
if (window.origin !== "null") {
    document.body.innerHTML = '';
    let f = document.createElement("iframe");
    f.sandbox = "allow-scripts allow-modals";
    f.src = window.location.href;
    f.addEventListener('popstate', function (event) {
        console.log(event);
    });
    f.style = "width: 100%; height: 100%;";
    f.frameBorder = 0;
    
    window.addEventListener('DOMContentLoaded', (event) => {
        document.body.style = 'margin:0px;padding:0px;overflow:hidden';
        document.body.appendChild(f);
    });
}
