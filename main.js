/*jshint esversion: 8 */

// NDev 2020 https://github.com/NDevTK/website

console.log('%c ', 'color: red; font-size: 1000rem; background-image:url("https://ndev.tk/Discord.webp")');

if (window.origin !== "null") {
  navigator.serviceWorker.register("https://ndev.tk/sw.js").then(_ => {
    location.reload(true);
  });
  throw "Added protection"
}

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

window.onload = e => {
  document.getElementById("rickroll").onclick = e => {
    e.preventDefault();
    googleAnimation();
  }
};

function googleAnimation() {
let w = open("https://www.google.com/");
const NGGYU = "We're no strangers to love You know the rules and so do I A full commitment's what I'm thinking of You wouldn't get this from any other guy I just wanna tell you how I'm feeling Gotta make you understand Never gonna give you up Never gonna let you down Never gonna run around and desert you Never gonna make you cry Never gonna say goodbye Never gonna tell a lie and hurt you We've known each other for so long Your heart's been aching but you're too shy to say it Inside we both know what's been going on We know the game and we're gonna play it And if you ask me how I'm feeling Don't tell me you're too blind to see Never gonna give you up Never gonna let you down Never gonna run around and desert you Never gonna make you cry Never gonna say goodbye Never gonna tell a lie and hurt you Never gonna give you up Never gonna let you down Never gonna run around and desert you Never gonna make you cry Never gonna say goodbye Never gonna tell a lie and hurt you Never gonna give, never gonna give (Give you up) (Ooh) Never gonna give, never gonna give (Give you up) We've known each other for so long Your heart's been aching but you're too shy to say it Inside we both know what's been going on We know the game and we're gonna play it I just wanna tell you how I'm feeling Gotta make you understand Never gonna give you up Never gonna let you down Never gonna run around and desert you Never gonna make you cry Never gonna say goodbye Never gonna tell a lie and hurt you Never gonna give you up Never gonna let you down Never gonna run around and desert you Never gonna make you cry Never gonna say goodbye Never gonna tell a lie and hurt you Never gonna give you up Never gonna let you down Never gonna run around and desert you Never gonna make you cry".split(" ");
let counter = 0;
let loop = setInterval(_ => {
  w.location = "https://www.google.com/maps/vt/icon/name=assets/icons/spotlight/spotlight_pin_v3_shadow-1-small.png&color=ffffdc00&psize=50&scale=4&text="+encodeURIComponent(NGGYU[counter]);
  counter += 1;
  if (w.closed) clearInterval(loop);
  if (counter === NGGYU.length) counter = 0;
}, 1000);
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
  window.location = "https://myaccount.google.com/stateattackwarning";
}

let clicked = new Set();

function snowflake(index) {
  if (clicked.has(index)) {
    alert("You clicked snowflake " + index + " again.");
  } else {
    alert("You clicked snowflake " + index + ".");
    clicked.add(index);
    if (clicked.size === 12) {
      alert("You clicked all the snowflakes.");
      clicked.clear();
    }
  }
}
