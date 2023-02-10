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
    case 's':
      const snowflakes = document.getElementsByClassName('snowflake');
      if (snowflakes.length === 0) return;
      const userSnowflake = prompt('What should be used as the snowflake?');
      for (const snowflake of snowflakes) {
        snowflake.innerText = (userSnowflake.length > 0) ? userSnowflake : '🦆';
      }
      break
  }
});

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function razerRGB() {
  // Code runs if razer software instaled.
  for (;;) {
    razer.createKeyboardEffect('CHROMA_STATIC', 255);
    razer.createHeadsetEffect('CHROMA_STATIC', 255);
    razer.createMouseEffect('CHROMA_STATIC', 255);
    razer.createChromaLinkEffect('CHROMA_STATIC', 255);
    razer.createMousematEffect('CHROMA_STATIC', 255);
    await sleep(3000);
    razer.createKeyboardEffect('CHROMA_NONE');
    razer.createHeadsetEffect('CHROMA_NONE');
    razer.createMouseEffect('CHROMA_NONE');
    razer.createChromaLinkEffect('CHROMA_NONE');
    razer.createMousematEffect('CHROMA_NONE');
    await sleep(3000);
  }
}

// Razer SDK (https://assets.razerzone.com/dev_portal/REST/html/index.html)
function ChromaSDK() {
    var razerAPI;
    var razerTimer;
}

function razerHeartbeat() {
    var request = new XMLHttpRequest();

    request.open("PUT", razerAPI + "/heartbeat", true);

    request.setRequestHeader("content-type", "application/json");

    request.send(null);

    request.onreadystatechange = function () {
        if ((request.readyState == 4) && (request.status == 200)){
            //console.log(request.responseText);
        }
    }
}

ChromaSDK.prototype = {
    init: function () {
        var request = new XMLHttpRequest();

        request.open("POST", "http://localhost:54235/razer/chromasdk", true);

        request.setRequestHeader("content-type", "application/json");

        var data = JSON.stringify({
            "title": "NDevTK",
            "description": "NDevTK website",
            "author": {
                "name": "NDevTK",
                "contact": "ndev.tk"
            },
            "device_supported": [
                "keyboard",
                "mouse",
                "headset",
                "mousepad",
                "keypad",
                "chromalink"],
            "category": "application"
        });

        request.send(data);

        request.onreadystatechange = function () {
            if (request.readyState == 4 && request.status == 200) {
                razerAPI = JSON.parse(request.responseText)["uri"];
                razerHeartbeat();
                razerTimer = setInterval(razerHeartbeat, 10000);
                setTimeout(razerRGB, 2000);
            }
        }
    },
    uninit: function () {
        var request = new XMLHttpRequest();

        request.open("DELETE", uri, true);

        request.setRequestHeader("content-type", "application/json");

        request.send(null);

        request.onreadystatechange = function () {
            if (request.readyState == 4) {
                console.log(request.responseText);
            }
        }

        clearInterval(razerTimer);
    },
    createKeyboardEffect: function (effect, data) {
        var jsonObj;

        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        } else if (effect == "CHROMA_CUSTOM_KEY") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        }

        var request = new XMLHttpRequest();

        request.open("PUT", razerAPI + "/keyboard", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);
    },
    preCreateKeyboardEffect: function (effect, data) {
        var jsonObj;

        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        } else if (effect == "CHROMA_CUSTOM_KEY") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        }

        var request = new XMLHttpRequest();

        request.open("POST", razerAPI + "/keyboard", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        return JSON.parse(request.responseText)['id'];
    },
    createMousematEffect: function (effect, data) {
        var jsonObj;

        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        }

        var request = new XMLHttpRequest();

        request.open("PUT", razerAPI + "/mousepad", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);
    },
    preCreateMousematEffect: function (effect, data) {
        var jsonObj;

        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        }

        var request = new XMLHttpRequest();

        request.open("POST", razerAPI + "/mousepad", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('preCreateMousematEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);

        return JSON.parse(request.responseText)['id'];
    },
    createMouseEffect: function (effect, data) {
        var jsonObj;

        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM2") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        }

        var request = new XMLHttpRequest();

        request.open("PUT", razerAPI + "/mouse", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);
    },
    preCreateMouseEffect: function (effect, data) {
        var jsonObj;

        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM2") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        }

        var request = new XMLHttpRequest();

        request.open("POST", razerAPI + "/mouse", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        return JSON.parse(request.responseText)['id'];
    },
    createHeadsetEffect: function (effect, data) {
        var jsonObj;

        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        }

        var request = new XMLHttpRequest();

        request.open("PUT", razerAPI + "/headset", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);
    },
    preCreateHeadsetEffect: function (effect, data) {
        var jsonObj;

        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        }
        var request = new XMLHttpRequest();
        request.open("POST", razerAPI + "/headset", false);
        request.setRequestHeader("content-type", "application/json");
        request.send(jsonObj);
        return JSON.parse(request.responseText)['id'];
    },
    createKeypadEffect: function (effect, data) {
        var jsonObj;

        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        }
        var request = new XMLHttpRequest();

        request.open("PUT", razerAPI + "/keypad", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);
    },
    preCreateKeypadEffect: function (effect, data) {
        var jsonObj;

        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        }
        var request = new XMLHttpRequest();
        request.open("POST", razerAPI + "/keypad", false);
        request.setRequestHeader("content-type", "application/json");
        request.send(jsonObj);
        return JSON.parse(request.responseText)['id'];
    },
    createChromaLinkEffect: function (effect, data) {
        var jsonObj;
        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        }
        var request = new XMLHttpRequest();
        request.open("PUT", razerAPI + "/chromalink", false);
        request.setRequestHeader("content-type", "application/json");
        request.send(jsonObj);
    },
    preCreateChromaLinkEffect: function (effect, data) {
        var jsonObj;
        if (effect == "CHROMA_NONE") {
            jsonObj = JSON.stringify({ "effect": effect });
        } else if (effect == "CHROMA_CUSTOM") {
            jsonObj = JSON.stringify({ "effect": effect, "param": data });
        } else if (effect == "CHROMA_STATIC") {
            var color = { "color": data };
            jsonObj = JSON.stringify({ "effect": effect, "param": color });
        }
        var request = new XMLHttpRequest();
        request.open("POST", razerAPI + "/chromalink", false);
        request.setRequestHeader("content-type", "application/json");
        request.send(jsonObj);
        return JSON.parse(request.responseText)['id'];
    },
    setEffect: function (id) {
        var jsonObj = JSON.stringify({ "id": id });
        var request = new XMLHttpRequest();
        request.open("PUT", razerAPI + "/effect", false);
        request.setRequestHeader("content-type", "application/json");
        request.send(jsonObj);
    },
    deleteEffect: function (id) {
        var jsonObj = JSON.stringify({ "id": id });
        var request = new XMLHttpRequest();
        request.open("DELETE", razerAPI + "/effect", false);
        request.setRequestHeader("content-type", "application/json");
        request.send(jsonObj);
    },
    deleteEffectGroup: function (ids) {
        var jsonObj = ids;
        var request = new XMLHttpRequest();
        request.open("DELETE", razerAPI + "/effect", false);
        request.setRequestHeader("content-type", "application/json");
        request.send(jsonObj);
    }
}

window.razer = new ChromaSDK();
window.razer.init();

// SteelSeries GameSense™ SDK (https://github.com/SteelSeries/gamesense-sdk)
window.baseGameSense = '';

async function gamesenseColor(r, g, b) {
    const response = await fetch(baseGameSense + 'game_event', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            "game": "NDEVTK",
            "event": "HEALTH",
            "data": {
                "frame": {
                    "zone-one-color": {
                        "red": r,
                        "green": g,
                        "blue": b
                    }
                }
            }
        })
    });
}

async function gamesense(port) {
    const base = 'http://127.0.0.1:' + port + '/';
    baseGameSense = base;
    setInterval(() => {
        fetch(base + 'game_heartbeat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                "game": "NDEVTK"
            })
        });
    }, 5000);

    const response = await fetch(base + 'bind_game_event', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            "game": "NDEVTK",
            "event": "HEALTH",
            "handlers": [{
                "device-type": "keyboard",
                "zone": "main-keyboard",
                "mode": "context-color",
                "context-frame-key": "zone-one-color"
            }]
        })
    });
    changeColor(256,0,0);
}


// Detects gamesense
shouldScan = true;
const thread = (start, stop, callback) => {
    const loop = port => {
        if (port < stop) {
            if (!shouldScan) return
            fetch('http://127.0.0.1:' + port + '/game_heartbeat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    "game": "NDEVTK"
                })
            }).then(async resp => {
                let result = await resp.text();
                if (result.includes('game_heartbeat')) {
                    shouldScan = false;
                    callback(port);
                }
                loop(port + 1);
            }).catch(err => {
                loop(port + 1);
            });
        }
    };
    setTimeout(() => loop(start), 0);
};

const scanRange = (start, stop, thread_count) => {
    const port_range = stop - start;
    const thread_range = port_range / thread_count;
    for (let i = 0; i < thread_count; i++) {
        const _start = 0 | start + thread_range * i;
        const _stop = 0 | start + thread_range * (i + 1);
        thread(_start, _stop, port => {
            console.log(port)
        });
    }
}

onload = () => { scanRange(50000, 60000, 1000); };
