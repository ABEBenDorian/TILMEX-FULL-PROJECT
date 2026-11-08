const CACHE='tilmex-pwa-v2';
const FILES=['/','/index.html','/style.css','/script.js','/social-api.js','/icon.svg','/manifest.webmanifest','/offline-pool.html'];
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(FILES)).then(()=>self.skipWaiting())));
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{
 const r=e.request,u=new URL(r.url);if(u.origin!==self.location.origin||r.method!=='GET')return;
 if(u.pathname.startsWith('/api/')||u.pathname.startsWith('/socket.io/'))return;
 if(r.mode==='navigate'){e.respondWith(fetch(r).catch(async()=>{const c=await caches.open(CACHE);return (await c.match('/offline-pool.html'))||Response.error();}));return;}
 e.respondWith(caches.match(r).then(hit=>hit||fetch(r).then(res=>{if(res.ok){const copy=res.clone();caches.open(CACHE).then(c=>c.put(r,copy));}return res;})));
});
