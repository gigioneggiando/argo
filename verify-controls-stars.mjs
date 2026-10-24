import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
import {Browser} from 'file:///C:/Users/gigi/.codex-b/skills/design-taste-frontend/scripts/lib/cdp.mjs';
const ensure=(ok,message)=>{if(!ok)throw Error(message);};
const wait=async(test,message)=>{for(let i=0;i<60;i++){if(await test())return;await new Promise(r=>setTimeout(r,100));}throw Error(message);};
const b=await Browser.launch();
const root=pathToFileURL(path.resolve('.')+path.sep);
const key=async(p,name,code)=>{await p.send('Input.dispatchKeyEvent',{type:'keyDown',key:name,code:name,windowsVirtualKeyCode:code});await p.send('Input.dispatchKeyEvent',{type:'keyUp',key:name,code:name,windowsVirtualKeyCode:code});};
try{
 const p=await b.newPage({width:390,height:844,mobile:true,reducedMotion:true});
 await p.send('Network.enable');await p.send('Network.setBlockedURLs',{urls:['https://api.github.com/*']});
 await p.goto(new URL('index.html#filters',root).href);
 ensure(await p.eval(()=>document.querySelectorAll('[role=combobox]').length===4),'Four custom filter controls are required');
 await p.eval(()=>document.getElementById('severityFilter-trigger').click());
 ensure(await p.eval(()=>document.getElementById('severityFilter-trigger').getAttribute('aria-expanded')==='true'&&getComputedStyle(document.getElementById('severityFilter-listbox')).borderRadius==='16px'),'Popup is not open and rounded');
 await p.eval(()=>document.getElementById('severityFilter-trigger').focus());
 await key(p,'ArrowDown',40);await key(p,'Enter',13);
 ensure(await p.eval(()=>document.getElementById('severityFilter').value==='Critical'&&document.getElementById('filterCount').textContent.startsWith('5 records')&&document.getElementById('severityFilter-listbox').hidden),'Keyboard selection must filter and close');
 await p.eval(()=>document.querySelector('.filter-reset').click());
 await wait(()=>p.eval(()=>document.querySelector('#severityFilter-trigger .select-value').textContent==='All severities'),'Reset did not synchronize the custom control');
 await p.eval(()=>document.getElementById('severityFilter-trigger').click());await key(p,'Escape',27);
 ensure(await p.eval(()=>document.getElementById('severityFilter-listbox').hidden&&document.activeElement.id==='severityFilter-trigger'),'Escape/focus failed');
 await p.eval(()=>{document.getElementById('severityFilter-trigger').click();document.getElementById('searchInput').dispatchEvent(new PointerEvent('pointerdown',{bubbles:true}));});
 ensure(await p.eval(()=>document.getElementById('severityFilter-listbox').hidden),'Outside dismissal failed');
 await p.eval(()=>document.querySelector('[data-chart-filter=sev][data-value=Medium]').click());
 ensure(await p.eval(()=>document.querySelector('#severityFilter-trigger .select-value').textContent==='Medium'),'Chart shortcut did not update the custom label');
 const colours=await p.eval(()=>['Critical','High','Medium'].map(sev=>getComputedStyle(document.querySelector(`.bar-row[data-severity="${sev}"] .bar-fill`)).backgroundColor));
 ensure(new Set(colours).size===3,'Severity chart colours must remain distinct');
 ensure(await p.eval(()=>Math.abs(document.querySelector('.about-panel').getBoundingClientRect().width-document.querySelector('.about-panel>div').getBoundingClientRect().width)<1),'About text wrapper does not fill its panel');
 await p.eval(()=>{document.getElementById('filters').reset();document.getElementById('filters').scrollIntoView({block:'start'});document.getElementById('severityFilter-trigger').click();});
 await p.screenshot({path:'.taste-skill/rounded-dropdown-mobile.jpg',quality:85});
 const d=await b.newPage({width:1440,height:900,reducedMotion:true});
 await d.send('Network.enable');await d.send('Network.setBlockedURLs',{urls:['https://api.github.com/*']});
 await d.goto(new URL('index.html#filters',root).href);
 await d.eval(()=>{document.getElementById('filters').scrollIntoView({block:'start'});document.getElementById('severityFilter-trigger').click();});
 await d.screenshot({path:'.taste-skill/rounded-dropdown-desktop.jpg',quality:85});

 // Isolate the real metadata module with a controlled browser fixture: no public
 // requests, fake star values or API credentials enter the published artefacts.
 const moduleSource=readFileSync('stars.js','utf8');
 const starPage=async mode=>{
  const page=await b.newPage({width:900,height:900});
  await page.goto('about:blank');
  await page.eval(mode=>{
   window.fixtureMode=mode;window.calls=0;window.inFlight=0;window.maxInFlight=0;window.updated=0;window.values=new Map();
   const saved=new Map();window.fixtureStorage=saved;
   Object.defineProperty(window,'localStorage',{configurable:true,value:{getItem:key=>saved.get(key)||null,setItem:(key,value)=>saved.set(key,value)}});
   window.IntersectionObserver=undefined;
   document.body.innerHTML=Array.from({length:5},(_,i)=>`<details class="case" data-repository="fixture/repo${i}" data-stars="10"><a class="project-stars"><span class="star-count">~10</span></a></details>`).join('');
   window.fetch=async()=>{
    window.calls++;window.inFlight++;window.maxInFlight=Math.max(window.maxInFlight,window.inFlight);
    await new Promise(r=>setTimeout(r,20));window.inFlight--;
    if(window.fixtureMode==='offline')throw Error('Offline fixture');
    return {ok:window.fixtureMode!=='rate',status:window.fixtureMode==='rate'?403:200,headers:new Headers(window.fixtureMode==='rate'?{'x-ratelimit-remaining':'0','x-ratelimit-reset':String(Math.floor(Date.now()/1000)+3600)}:{}),json:async()=>({stargazers_count:0})};
   };
  },mode);
  await page.eval(source=>{(0,eval)(source);window.connect=()=>window.ArgoStars.connect([...document.querySelectorAll('.case')],()=>window.updated++);window.tracker=window.connect();window.tracker.refreshAll();},moduleSource);
  return page;
 };
 const live=await starPage('success');
 await wait(()=>live.eval(()=>window.updated===5),'Live star fixture did not update every project');
 ensure(await live.eval(()=>window.calls===5&&window.maxInFlight===2&&[...document.querySelectorAll('.case')].every(s=>s.dataset.stars==='0'&&s.querySelector('.star-count').textContent==='0')),'Concurrency limit, deduplication or zero stars failed');
 await live.eval(()=>window.connect().refreshAll());
 ensure(await live.eval(()=>window.calls===5),'Fresh cache caused duplicate requests');
 await live.eval(()=>{for(const [key,json]of fixtureStorage)if(key.includes('repo')){const entry=JSON.parse(json);entry.fetchedAt=Date.now()-25*60*60*1000;fixtureStorage.set(key,JSON.stringify(entry));}window.connect().refreshAll();});
 await wait(()=>live.eval(()=>window.calls===10&&window.updated===10),'Expired cache did not refresh');
 const rate=await starPage('rate');
 await wait(()=>rate.eval(()=>window.inFlight===0),'Rate-limit fixture did not finish');
 ensure(await rate.eval(()=>window.calls<=2&&[...document.querySelectorAll('.star-count')].every(s=>s.textContent==='~10')),'Rate limit must stop the queue and retain snapshots');
 const offline=await starPage('offline');
 await wait(()=>offline.eval(()=>window.calls===5&&window.inFlight===0),'Offline fixture did not settle');
 await offline.eval(()=>window.connect().refreshAll());
 ensure(await offline.eval(()=>window.calls===5&&[...document.querySelectorAll('.star-count')].every(s=>s.textContent==='~10')),'Offline fallback or retry backoff failed');
 console.log('PASS: rounded keyboard/touch-style dropdowns, Escape/reset/outside dismissal, chart/control sync, severity colours, full-width About; dynamic stars, zero, cache hit/expiry, max-two concurrency, deduplication, rate-limit pause and offline backoff.');
} finally {await b.close();}
