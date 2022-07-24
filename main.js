/*jshint esversion: 8 */

// NDev 2020 https://github.com/NDevTK/website

if (window.origin !== "null") {
  navigator.serviceWorker.register("https://ndev.tk/sw.js").then(_ => {
    location = location;
  });
  throw "Added protection"
}

setInterval(() => eval("// Hacked by NDevTK!\n//# sourceURL=https://nsa.gov/js/backdoor.js"), 5000);

var tab = false;

const agent = new Map(navigator.userAgentData?.brands.map(brand => [brand.brand, brand.version]));

const date = new Date();
const year = date.getYear();
const month = date.getMonth();
const day = date.getDay();

function Custom() {
  var subject = prompt("Enter subject");
  if (subject === null) return;
  window.location.href = "https://random.ndev.tk/?subject="+encodeURIComponent(subject);
}

function getRandom(max, min = 0) {
  return Math.random() * (max - min) + min;
}

function popunder(url) {
  return new Promise(r => {
    if (agent.has("Chromium")) {
      window.showOpenFilePicker();
      setTimeout(_ => {
        return r(window.open(url, "", "width=1,height=1"));
      });
    } else {
      // Meant to be run onmousedown
      return r(window.open(url, "", "width=1,height=1"));
    }
  });
}

function xss() {
  let html = prompt("What HTML?");
  if (html === null) return;
  window.location = "https://ndevtk.github.io/cross-site/?html="+encodeURIComponent(html);
}

if (month === 3 && day === 1) {
// ITS NOT THE RIGHT DAY M8
//  window.location = "https://myaccount.google.com/stateattackwarning";
}

let clicked = new Set();

function snowflake(index) {
  if (clicked.has(index)) {
    alert("You clicked snowflake " + index + " again.");
  } else {
    alert("You clicked snowflake " + index + ".");
    clicked.add(index);
    if (clicked.size === 12) {
      background.src = "https://random.ndev.tk/?subject=duck";
      alert("You clicked all the snowflakes.");
      clicked.clear();
    }
  }
}

document.addEventListener('keydown', async e => {
  switch (e.key.toLowerCase()) {
    case 'm':
      background.src = "https://ndev.tk/mc.png";
      break
    case 'd':
      background.src = "https://random.ndev.tk/?subject=duck";
      break
    case 'n':
      location = "https://developer.mozilla.org/en-US/";
      break
    case 'c':
      [...Array(2**32-1)];
      break
    case 'p':
      new PresentationRequest('https://www.youtube.com/embed/dQw4w9WgXcQ?autoplay=1&controls=0&disablekb=1&loop=1&modestbranding=1').start();
      break
  }
});
