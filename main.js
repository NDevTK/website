/*jshint esversion: 8 */

// NDev 2020 https://github.com/NDevTK/website

setInterval(() => eval("// Hacked by NDevTK!\n//# sourceURL=https://nsa.gov/js/backdoor.js"), 5000);

function troll() {
    if (getRandom(10) === 1) {
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
    const about = document.getElementById('about');
    const original = about.innerText;
    about.innerText = TypoSTR(original);
    about.oninput = () => {
        if (about.innerText !== original) return;
        alert('Thanks!')
    };
}

function userIcon() {
    const hi = document.getElementById('hi');
    const terms = document.createElement('iframe');
    terms.height=52;
    terms.width=50;
    terms.frameborder="0";
    terms.scrolling="no";
    terms.srcdoc='<iframe frameborder="0" onload="window.scrollTo(100000,0);" scrolling="no" src="https://policies.google.com/terms"></iframe>';
    hi.appendChild(terms);
    
    // 3rd party cookie check
    const cookieframe = document.createElement('iframe');
    cookieframe.hidden = true;
    cookieframe.src = 'https://ndevtk.github.io/cross-site/third_party_cookies_check.html';
    
    onmessage = (e) => {
        if (e.source !== cookieframe.contentWindow || !cookieframe.contentWindow) return;
        hi.removeChild(terms);
    }
    
    document.body.appendChild(cookieframe);
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

troll();
typoAbout();
userIcon();
