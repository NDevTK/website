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


// JavaScript source code

function ChromaSDK() {
    var uri;
    var timerId;
}

function onTimer() {
    var request = new XMLHttpRequest();

    request.open("PUT", uri + "/heartbeat", true);

    request.setRequestHeader("content-type", "application/json");

    request.send(null);

    request.onreadystatechange = function () {
        if ((request.readyState == 4) && (request.status == 200)){
            console.log(request.responseText);
        }
    }
}

ChromaSDK.prototype = {
    init: function () {
        var request = new XMLHttpRequest();

        request.open("POST", "http://localhost:54235/razer/chromasdk", true);

        request.setRequestHeader("content-type", "application/json");

        var data = JSON.stringify({
            "title": "Razer Chroma SDK Sample Application",
            "description": "Razer Chroma SDK Sample Application",
            "author": {
                "name": "Chroma Developer",
                "contact": "www.razerzone.com"
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
            if (request.readyState == 4) {
                uri = JSON.parse(request.responseText)["uri"];
                console.log(uri);
                timerId = setInterval(onTimer, 10000);
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

        clearInterval(timerId);
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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("PUT", uri + "/keyboard", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('createKeyboardEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);
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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("POST", uri + "/keyboard", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log(request.responseText);

        console.log('preCreateKeyboardEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);

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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("PUT", uri + "/mousepad", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('createMousematEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);
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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("POST", uri + "/mousepad", false);

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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("PUT", uri + "/mouse", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('createMouseEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);
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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("POST", uri + "/mouse", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('preCreateMouseEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);

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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("PUT", uri + "/headset", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('createHeadsetEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);
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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("POST", uri + "/headset", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('preCreateHeadsetEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);

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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("PUT", uri + "/keypad", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('createKeypadEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);
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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("POST", uri + "/keypad", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('preCreateKeypadEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);

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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("PUT", uri + "/chromalink", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('createChromaLinkEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);
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

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("POST", uri + "/chromalink", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('preCreateChromaLinkEffect(' + effect + ', ' + data + ') returns ' + JSON.parse(request.responseText)['Result']);

        return JSON.parse(request.responseText)['id'];
    },
    setEffect: function (id) {
        var jsonObj = JSON.stringify({ "id": id });

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("PUT", uri + "/effect", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('setEffect(' + id + ') returns ' + JSON.parse(request.responseText)['Result']);
    },
    deleteEffect: function (id) {
        var jsonObj = JSON.stringify({ "id": id });

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("DELETE", uri + "/effect", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('deleteEffect(' + id + ') returns ' + JSON.parse(request.responseText)['Result']);
    },
    deleteEffectGroup: function (ids) {
        var jsonObj = ids;

        console.log(jsonObj);

        var request = new XMLHttpRequest();

        request.open("DELETE", uri + "/effect", false);

        request.setRequestHeader("content-type", "application/json");

        request.send(jsonObj);

        console.log('deleteEffectGroup() returns ' + JSON.parse(request.responseText));
    }
}
