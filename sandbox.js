<script>
"use strict";
if (window.origin !== "null") {
    let f = document.createElement("iframe");
    f.sandbox = "allow-scripts";
    f.src = window.location.href;
    f.style = "width: 100%; height: 100%;";
    window.document.body.appendChild(f);
    throw "No sandbox";
}
</script>
