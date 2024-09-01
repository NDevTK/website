/*jshint esversion: 8 */
// NDev 2023 https://github.com/NDevTK/website
"use strict";

let userInfo = {
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
    icon.src = 'https://ndev.tk/penguin.webp';
    about.innerText = 'Still ' + about.innerText;
}

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);                    
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));             
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

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
        if (confirm('Allow this fix to be saved to localStorage?')) localStorage.setItem('fixedTypo', '1');
        alert('Thanks!')
    };
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
      background.src = "https://ndev.tk/mc.webp";
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

typoAbout();
referrerSnowflake();

icon.onclick = () => {
    if (icon.src.endsWith('/icon-qr.webp')) {
        icon.src = '/icon.webp';
    } else {
        icon.src = '/icon-qr.webp';
    }
}
