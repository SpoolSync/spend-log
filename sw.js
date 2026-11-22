/* Tally: keeps the app's own files on the phone so it opens offline. No user data passes through here. */
var CACHE="spendlog-v16";
var SHELL=["./","index.html","app.js","subs.js","subs-view.js","cloud.js","pixora-summary.js","pixora-usage.js","firebase-app-compat.js","firebase-auth-compat.js","firebase-firestore-compat.js","ocr.html","ocr-frame.js","manifest.webmanifest","icon-180.png","icon-192.png","icon-512.png"];
var BIG=/ppocr\.js|ort-wasm|pp-det|pp-rec|pp-keys/;
self.addEventListener("install",function(e){e.waitUntil(caches.open(CACHE).then(function(c){return c.addAll(SHELL.map(function(u){return new Request(u,{cache:"reload"});}));}).then(function(){return self.skipWaiting();}));});
self.addEventListener("activate",function(e){e.waitUntil(caches.keys().then(function(ks){return Promise.all(ks.filter(function(k){return k.indexOf("spendlog-")===0&&k!==CACHE;}).map(function(k){return caches.delete(k);}));}).then(function(){return self.clients.claim();}));});
function store(req,res){if(res&&res.ok){var copy=res.clone();caches.open(CACHE).then(function(c){c.put(req,copy);});}return res;}
self.addEventListener("fetch",function(e){
  var u=new URL(e.request.url);
  if(e.request.method!=="GET"||u.origin!==location.origin)return;
  if(BIG.test(u.pathname)){ /* text-recognition files are large and never change: use the saved copy first */
    e.respondWith(caches.match(e.request).then(function(m){return m||fetch(e.request).then(function(r){return store(e.request,r);});}));return;
  }
  /* always ask the server (a cheap 304 when nothing changed), so a new release never mixes with old files */
  e.respondWith(fetch(e.request,{cache:"no-cache"}).then(function(r){return store(e.request,r);}).catch(function(){
    return caches.match(e.request,{ignoreSearch:true}).then(function(m){return m||(e.request.mode==="navigate"?caches.match("./"):Response.error());});
  }));
});
