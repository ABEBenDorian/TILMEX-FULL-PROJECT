const fs=require('fs'),assert=require('assert');
const game=fs.readFileSync('offline-pool.html','utf8'),sw=fs.readFileSync('service-worker.js','utf8'),html=fs.readFileSync('index.html','utf8'),js=fs.readFileSync('script.js','utf8');
assert(game.includes('function init()'));assert(game.includes('requestAnimationFrame(frame)'));assert(!/https?:\/\//.test(game),'Pool game must be self-contained and offline');
assert(sw.includes("'/offline-pool.html'"));assert(html.includes('name="displayName"'));assert(!html.includes('name="email"'));assert(!html.includes('name="username" autocomplete="username" placeholder="3'));assert(js.includes('JSON.stringify({displayName,password})'));console.log('Offline billiards asset checks passed.');
