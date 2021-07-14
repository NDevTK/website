/*jshint esversion: 8 */

// NDev 2020 https://github.com/NDevTK/website

var tab = false;

const agent = new Map(navigator.userAgentData?.brands.map(brand => [brand.brand, brand.version]));

async function InviteSpam(mousedown) {
  // User input
  const server = "https://discord.gg/tkaBujU";
  // Spam Client
  var discord = await popunder(server);
  setInterval(function(){
    discord.location.href = server;
  }, 0);
}

function Custom() {
  var subject = prompt("Enter subject");
  if (subject === null) return;
  window.location.href = "https://random.ndev.tk/?subject="+encodeURIComponent(subject);
}

function getRandom(max, min = 0) {
  return Math.random() * (max - min) + min;
}

function create(url = "https://ndev.tk/Discord.webp") {
  if(tab) {
    tab.close();
    tab = false;
    return false;
  }
  tab = open(url, "", "width=1,height=1");
  setInterval(_ => {
    try {
    tab.moveTo(getRandom(window.screen.availHeight), getRandom(window.screen.availWidth));
    tab.resizeTo(getRandom(1000), getRandom(1000));
    } catch (err) {
    return;
  }}, 500);
}

function googleAnimation(e) {
e.preventDefault();
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
