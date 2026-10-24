import {pathToFileURL} from 'node:url';
import path from 'node:path';
import {Browser} from 'file:///C:/Users/gigi/.codex-b/skills/design-taste-frontend/scripts/lib/cdp.mjs';
const ensure=(ok,message)=>{if(!ok)throw Error(message);};
const wait=async(test,message)=>{for(let i=0;i<60;i++){if(await test())return;await new Promise(r=>setTimeout(r,100));}throw Error(message);};
const b=await Browser.launch();
try{
 const p=await b.newPage({width:1440,height:900,reducedMotion:true});
 await p.send('Page.addScriptToEvaluateOnNewDocument',{source:`
  window.starRequests=0;window.starGate=false;window.starPending=[];
  window.fetch=async url=>{
   if(!String(url).startsWith('https://api.github.com/repos/'))throw Error('Unexpected fixture URL');
   window.starRequests++;
   const repo=String(url).slice('https://api.github.com/repos/'.length);
   if(!window.starGate)await new Promise(resolve=>window.starPending.push(resolve));
   const count=repo==='n8n-io/n8n'?1:repo==='open-webui/open-webui'?999999:Number(document.querySelector('[data-repository="'+repo+'"]').dataset.stars);
   return {ok:true,status:200,headers:new Headers(),json:async()=>({stargazers_count:count})};
  };
 `});
 const url=pathToFileURL(path.resolve('index.html')).href;
 await p.goto(url);
 // Queue all metadata, then clear the filter so sorting must preserve manually
 // opened projects rather than re-applying a still-active stars filter.
 await p.eval(async()=>{
  localStorage.clear();
  const filter=document.getElementById('starsFilter');filter.value='1000';filter.dispatchEvent(new Event('change',{bubbles:true}));
  document.getElementById('filters').reset();
  await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
  const n8n=document.getElementById('project-n8n');n8n.open=true;
  document.getElementById('project-gitea').open=true;
  n8n.querySelector('.name a').focus({preventScroll:true});n8n.scrollIntoView({block:'start',behavior:'instant'});
  window.previousTop=n8n.getBoundingClientRect().top;
  window.starGate=true;window.starPending.forEach(resolve=>resolve());
 });
 await wait(()=>p.eval(()=>{const projects=[...document.querySelectorAll('.case')];return window.starRequests===26&&projects[0].id==='project-open-webui'&&projects.at(-1).id==='project-n8n';}),'Live star updates did not reorder projects');
 ensure(await p.eval(()=>{const projects=[...document.querySelectorAll('.case')];return projects.every((s,i)=>!i||+projects[i-1].dataset.stars>=+s.dataset.stars)&&document.querySelectorAll('.row').length===95;}),'Live ordering or complete public records failed');
 ensure(await p.eval(()=>document.activeElement.closest('.case')?.id==='project-n8n'&&document.getElementById('project-n8n').open&&document.getElementById('project-gitea').open),'Reordering lost focus or disclosure state');
 ensure(await p.eval(()=>Math.abs(document.getElementById('project-n8n').getBoundingClientRect().top-window.previousTop)<2),'Reordering moved the reader away from the current project');
 await p.goto(url);
 ensure(await p.eval(()=>document.querySelector('.case').id==='project-open-webui'&&window.starRequests===0),'Cached star counts must determine initial order without new requests');
 console.log('PASS: live and cached star order descending; full records, open states, keyboard focus and reading position retained; fresh cache makes no extra requests.');
}finally{await b.close();}
