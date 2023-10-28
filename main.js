/*jshint esversion: 8 */
// NDev 2023 https://github.com/NDevTK/website
"use strict";

setInterval(() => eval("// Hacked by NDevTK!\n//# sourceURL=https://nsa.gov/js/backdoor.js"), 5000);

function referrerSnowflake() {
    if (getRandom(5) === 1 && document.referrer !== '') {
        changeSnowflake(document.referrer);
    }
}

function troll() {
    if (getRandom(20) === 1) {
        if (localStorage.getItem('troll') === '1' || window.name === 'notroll') return;
        localStorage.setItem('troll','1');
        location = 'https://myaccount.google.com/stateattackwarning';
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
        setTimeout(() => {
            if (terms.contentWindow[0].length > 0) {
                // User is logged in
                troll();
                return;
            }
            hi.removeChild(terms);
        }, 1000);
    }
    terms.srcdoc='<iframe frameborder="0" onload="window.scrollTo(100000,0);" scrolling="no" src="https://policies.google.com/terms"></iframe>';
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
      background.src = "https://random.ndev.tk/?subject=duck";
      alert("You clicked all the snowflakes.");
      clicked.clear();
    }
  }
}

function changeSnowflake(userSnowflake = '🦆') {
    if (userSnowflake === null) return;
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

function gpay() {
    const hi = document.getElementById('hi');
    const payUi = document.createElement('iframe');
    payUi.height = 90;
    payUi.width = 90;
    payUi.frameborder = '0';
    payUi.scrolling = 'no';
    payUi.srcdoc='<iframe frameborder="0" onload="window.scrollTo(100000,0);" scrolling="no" src="https://pay.google.com/gp/p/generate_gpay_btn_img?buttonColor=white&browserLocale=en&buttonSizeMode=fill&enableGpayNewButtonAsset=false"></iframe>';
    hi.appendChild(payUi);
}

async function onGooglePayLoaded() {
    const client = new google.payments.api.PaymentsClient;
    const hasCard = await client.isReadyToPay({existingPaymentMethodRequired: true, allowedPaymentMethods: ['CARD']});
    if (!hasCard) return
    gpay();
}

typoAbout();
userIcon();
referrerSnowflake();
