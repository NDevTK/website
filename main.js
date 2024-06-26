/*jshint esversion: 8 */
// NDev 2023 https://github.com/NDevTK/website
"use strict";

if (window.trustedTypes && trustedTypes.createPolicy) { // I will be lazy!
  trustedTypes.createPolicy('default', {
    createHTML: (string, sink) => DOMPurify.sanitize(string, {RETURN_TRUSTED_TYPE: false, ALLOWED_TAGS: ["iframe"]})
  });
}

let userInfo = {
    loggedIn: false,
    hasCard: false,
    hadTroll: false,
    changedSnowflake: false,
    clickedDucks: false,
    referrerSnowflake: false,
    secretMode: false
}

secret(location.search);

const icon = document.getElementById('icon');
const about = document.getElementById('about');

async function secret(key) {
    const hash = await sha256(key);
    if (hash !== '2fff00e853dbebb282fb9f4b33c7102167bad6edbad080c4f3cd5383e2dedc87') return;
    history.replaceState({}, '', location.origin);
    userInfo.secretMode = true;
    
    // The user got here by finding the value of hash or cheated.
    changeSnowflake('🐈');
    icon.src = 'https://ndev.tk/icon.png';
    about.innerText = 'Still ' + about.innerText;
}

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);                    
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));             
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}



let isCooldown = false;

function cooldown() {
    if (isCooldown) return true
    isCooldown = true;
    setTimeout(() => {
        isCooldown = false;
    }, 30000);
    return false
}

cooldown();

const month = new Date().getMonth() + 1;


let season = '';

// probbaly not going to be correct :/
if ([12, 1, 2].includes(month)) {
    season = 'winter';
    changeSnowflake('❄️');
}
if ([3, 4, 5].includes(month)) {
    season = 'spring';
}
if ([6, 7, 8].includes(month)) {
    season = 'summer';
}
if ([9, 10, 11].includes(month)) {
    season = 'autumn';
    changeSnowflake('🍂');
}

// Lets be social
if (window.opener) opener.postMessage('Did you know its ' + season, '*');

function referrerSnowflake() {
    if (getRandom(5) === 1 && document.referrer !== '') {
        userInfo.referrerSnowflake = true;
        changeSnowflake(document.referrer);
    }
}

function troll() {
    if (getRandom(20) === 1) {
        //if (localStorage.getItem('troll') === '1' || window.name === 'notroll') return;
        //userInfo.hadTroll = true;
        //localStorage.setItem('troll','1');
        //location = 'https://myaccount.google.com/stateattackwarning';
    }
}

function TypoSTR(str) {
    let words = str.split(' ');
    words.forEach((word, index) => {
        if(word.length === 0) return;
        if (getRandom(2)) words[index] = Typo(word);
    });
    return words.join(" ");
}

function getRandom(max) {
    return Math.floor((Math.random() * 10) % max);
}

function AtPos(str, position, newStr) {
    return str.slice(0, position) + newStr + str.slice(position);
}

function Typo(word) {
    let index = getRandom(word.length);
    let letter = word[index];
    let newString = AtPos(word, index, letter);
    if (getRandom(2)) newString = AtPos(newString, index, letter);
    return newString;
}

function typoAbout() {
    if (localStorage.getItem('fixedTypo') === '1' || window.name === 'notroll') return;
    userInfo.hadTroll = true;
    const about = document.getElementById('about');
    const original = about.innerText;
    about.innerText = TypoSTR(original);
    about.oninput = () => {
        if (about.innerText !== original) return;
        localStorage.setItem('fixedTypo', '1');
        alert('Thanks!')
    };
}

function userIcon() {
    const hi = document.getElementById('hi');
    const terms = document.createElement('iframe');
    terms.height = 52;
    terms.width = 50;
    terms.frameborder = '0';
    terms.scrolling = 'no';
    terms.onload = () => {
        terms.contentWindow.scrollTo(240,5);
        setTimeout(() => {
            if (terms.contentWindow[0].length > 0) {
                // User is logged in
                userInfo.loggedIn = true;
                troll();
                return;
            }
            hi.removeChild(terms);
        }, 1000);
    }
    terms.srcdoc='<iframe frameborder="0" scrolling="no" src="https://policies.google.com/terms"></iframe>';
    hi.appendChild(terms);
}

function Custom() {
  var subject = prompt("Enter subject");
  if (subject === null) return;
  location = "https://random.ndev.tk/?subject="+encodeURIComponent(subject);
}

let clicked = new Set();

function snowflake(index) {
  if (clicked.has(index)) {
    alert("You clicked snowflake " + index + " again.");
  } else {
    alert("You clicked snowflake " + index + ".");
    clicked.add(index);
    if (clicked.size === 12) {
      userInfo.clickedDucks = true;
      background.src = "https://random.ndev.tk/?subject=duck";
      alert("You clicked all the snowflakes.");
      clicked.clear();
    }
  }
}

function changeSnowflake(userSnowflake = '🦆') {
    if (userSnowflake === null) return;
    userInfo.changedSnowflake = true;
    const snowflakes = document.getElementsByClassName('snowflake');
    for (const snowflake of snowflakes) {
        snowflake.innerText = userSnowflake;
    }
}

document.addEventListener('keydown', async e => {
  switch (e.key.toLowerCase()) {
    case 'm':
      background.src = "https://ndev.tk/mc.png";
      break
    case 'd':
      if (!userInfo.clickedDucks) {
          if (cooldown()) return;
          setTimeout(() => {
              background.src = "about:blank";
              alert('Duck background has not been unlocked... removing');
              cooldown();
              return
          }, 5000)
      }
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
      const userSnowflake = prompt('What should be used as the snowflake?');
      changeSnowflake(userSnowflake);
      break
  }
});

userIcon();
typoAbout();
referrerSnowflake();
