/*jshint esversion: 8 */

// NDev 2020 https://github.com/NDevTK/website

var tab = false;

function InviteSpam() {
  // User input
  var server = prompt("Enter Discord ID ", "tkaBujU");
  if (server === null) return;
  server = "https://discord.gg/"+server;
  // Spam Client
  var discord = open(server);
  setInterval(function(){
    discord.location.href = server;
  }, 0);
}

function Custom() {
  var subject = prompt("Enter subject");
  if (subject === null) return;
  window.location.href = "https://random.ndev.tk/?subject="+encodeURI(subject);
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

//art();
async function art() {
        var response = await fetch('https://api.github.com/repos/NDevTK/NDevTK/contents/');
        var data = await response.json();
        var images = document.createElement("div");
        images.id = "images";
        document.body.appendChild(images);
        for (let file of data) {
          if(!file.name.endsWith(".png") || !file.name.startsWith("art_")) continue;
          var img = document.createElement("img");
          img.setAttribute("src", "https://raw.githubusercontent.com/NDevTK/NDevTK/master/"+encodeURI(file.name));
          img.setAttribute("height", "200rem");
          img.setAttribute("width", "300rem");
          img.setAttribute("alt", "Automatic art");
          images.appendChild(img);
        }
}
