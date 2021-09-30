"use strict";
if (window.origin !== "null") {
    let f = document.createElement("iframe");
    f.sandbox = "allow-scripts";
    f.src = window.location.href;
    f.addEventListener('popstate', function (event) {
        console.log(event);
    });
    f.style = "width: 100%; height: 100%;";
    window.document.body.appendChild(f);
    throw "No sandbox";
}
