"use strict";

const urls = ["https://ndev.tk/visted/", 'https://notvisited' + ((Math.random()*100000000)|0)+'.foo', 'https://www.facebook.com', 'https://www.google.com', 'https://www.google.co.uk', 'https://www.youtube.com', 'https://www.twitter.com', 'https://www.linkedin.com', 'https://www.craigslist.org', 'https://stackoverflow.com', 'https://www.bing.com', 'https://www.bbc.co.uk', 'https://www.microsoft.com', 'https://www.amazon.com', 'https://www.amazon.co.uk', 'https://www.mozilla.org', 'https://www.contextis.co.uk/', 'https://www.theregister.co.uk', 'https://www.reddit.com', 'https://news.ycombinator.com','https://www.ebay.co.uk','https://www.ebay.com','https://www.ask.com','https://www.msn.com', 'https://www.wordpress.com', 'https://pinterest.com','https://instagram.com','https://www.apple.com','https://www.live.com','https://en.wikipedia.org','https://www.wikileaks.org','https://arstechnica.com', 'https://www.youtube.com/watch?v=dQw4w9WgXcQ', 'https://www.youtube.com/watch?v=x'];

requestAnimationFrame = window.requestAnimationFrame || window.mozRequestAnimationFrame ||  
   window.webkitRequestAnimationFrame || window.msRequestAnimationFrame;  
   
var out = document.getElementById('out');
var currentURLout = document.getElementById('currentURL');

var linkspans = [];
var timespans = [];
var counter = 0;
var posTimes = [];
var negTimes = [];

var stop = true;
var start;
var currentUrl = 0;
var calibIters = 10;

var textLines;
var textLen;

var threshold;
var timeStart;


document.addEventListener("keypress", e => {
    if (e.key === "Enter") updateParams();
});

function initStats() {
  currentUrl = 0;
  start = NaN;
  counter = 0;
  posTimes = [];
  negTimes = [];
  if (stop) {
    stop = false;
    loop();
  }
}

function updateParams() {
  document.getElementById('nums').innerText = "Loading...";
  out.onclick = e => e.preventDefault();
  out.oncontextmenu = e => e.preventDefault();
  out.onselectionchange = e => e.preventDefault();
  out.style.textShadow = document.getElementById('text-shadow').value;
  out.style.opacity = parseFloat(document.getElementById('opacity').value);
  out.style.fontSize = document.getElementById('font-size').value + 'px';
  textLines = parseInt(document.getElementById('textlines').value);
  textLen = parseInt(document.getElementById('textlen').value);
  setTimeout(_ => write(), 5);
  resetLinks();
  initStats();
}
function write() {
  var s = '';
  var url = urls[currentUrl];
  var text ='';
  while (text.length < textLen)
    text += '#';
    
  for (var i=0; i<textLines; i++) {
    s += "<a href="+url;
    s += ">"+text;
    s += "</a> ";
  }
  out.innerHTML = s;
}

function updateLinks() {
  var url = urls[currentUrl];
  for (var i=0; i<out.children.length; i++) {
    out.children[i].href = url;
    out.children[i].style.color='red';
    out.children[i].style.color='';
  }
}

function resetLinks() {
  for (var i=0; i<out.children.length; i++) {
    out.children[i].href = 'https://' + Math.random() + '.asd';
    out.children[i].style.color='red';
    out.children[i].style.color='';
  }
}

function median(list){
	list.sort(function(a,b){return a-b});
	if (list.length % 2){
		var odd = list.length / 2 - 0.5;
		return list[odd];
	}else{
		var even = list[list.length / 2 - 1];
		even += list[list.length / 2];
		even = even / 2;
		return even;
	}
}

function loop(timestamp) {
  if (stop) return;
  


  var diff = (timestamp - start) | 0;
  start = timestamp;

  if (!isNaN(diff)) {
    counter++;
    if (counter%2 == 0) {
      resetLinks();
      if (counter > 4) {
        if (currentUrl == 0) { // calibrating visited
          document.getElementById('nums').textContent = 'Calibrating...';
          posTimes.push(diff);
          timespans[currentUrl].textContent = posTimes.join(', ');
        }
          
        if (currentUrl == 1) { // calibrating unvisited
          negTimes.push(diff);
          timespans[currentUrl].textContent = negTimes.join(', ');
          if (negTimes.length >= calibIters) {
            var medianPos = median(posTimes);
            var medianNeg = median(negTimes);
            
            // if calibration didn't find a big enough difference between pos and neg, 
            // increase number of links and try again
            if (medianPos - medianNeg < 30) {
              document.getElementById('textlines').value = textLines + 50;
              document.getElementById('textlen').value = textLen + 1;
              stop = true;
              updateParams();
              return;
            }
            
            threshold = medianNeg + (medianPos - medianNeg)*.75;
            document.getElementById('nums').textContent = 'Median Visited: ' + medianPos + 'ms  / Median Unvisited: ' + medianNeg + 'ms / Threshold: ' + threshold + 'ms';
            timeStart = performance.now();
          }
        }
        
        if (currentUrl >= 2) {
            timespans[currentUrl].textContent = diff;
            linkspans[currentUrl].className = (diff >= threshold)? 'visited yes' : 'visited';
        }
        
        currentUrl++;
        
        // keep testing first two links until calibration is completed
        if (currentUrl == 2 && (negTimes.length < calibIters || posTimes.length < calibIters))
          currentUrl = 0;
         
        if (currentUrl == urls.length) {
          let timeElapsed = (performance.now() - timeStart) / 1000;
          document.getElementById('nums').innerHTML += "<br>Time elapsed: " + timeElapsed + "s, tested " + (((urls.length -2)/timeElapsed)|0) + " URLs/sec"; 
          stop = true;
          out.innerText = "";
       }
          
        currentURLout.textContent = urls[currentUrl];
        
      }
    } else {
      updateLinks();
    }
  }
  requestAnimationFrame(loop);
}

function setupLinks() {
  var table = document.createElement('table');
  table.innerHTML = '<tr><th></th><th>URL</th><th>Times (ms)</th></tr>';
  table.className = 'linklist';
  for (var i=0; i < urls.length; i++) {
    var a = document.createElement('a');
    a.href = urls[i];
    a.textContent = urls[i];
    var times = document.createElement('span');
    times.className = 'timings';
    var tick = document.createElement('span');
    tick.textContent = '\u2713';
    tick.className = 'visited';
    var tr = document.createElement('tr');
    for (var j=0; j<3; j++) 
      tr.appendChild(document.createElement('td'));
    tr.cells[0].appendChild(tick);
    tr.cells[1].appendChild(a);
    tr.cells[2].appendChild(times);
    table.appendChild(tr);
    
    timespans[i] = times;
    linkspans[i] = tick;
 
  }
  document.getElementById('log').appendChild(table);
}

setupLinks();

document.getElementById('startButton').onclick = updateParams;
document.getElementById('stopButton').onclick = () => {
  stop = true;
}
