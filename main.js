function Custom(){
subject = prompt("Enter subject");
if (subject === null) return;
window.location.href = "https://random.ndev.tk/?subject="+encodeURI(subject);
}

function getRandom(max, min = 0) {
    return Math.random() * (max - min) + min;
}

function create(url = "https://ndev.tk/Discord.webp") {
    if(window.hasOwnProperty("tab")) return tab.close();
    tab = open(url, "", "width=1,height=1");
    setInterval(_ => {
        try {
            tab.moveTo(getRandom(window.screen.availHeight), getRandom(window.screen.availWidth));
            tab.resizeTo(getRandom(1000), getRandom(1000));
        } catch (err) {
            return
        }
    }, 500)
}
