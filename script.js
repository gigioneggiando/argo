(() => {
  const themeButton=document.getElementById('themeToggle');
  if(themeButton)themeButton.hidden=false;
  const theme=()=>document.documentElement.dataset.theme||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');
  const describeTheme=()=>{const label=`Switch to ${theme()==='dark'?'light':'dark'} theme`;themeButton?.setAttribute('aria-label',label);themeButton?.setAttribute('title',label);};
  describeTheme();
  themeButton?.addEventListener('click',()=>{const next=theme()==='dark'?'light':'dark';document.documentElement.dataset.theme=next;try{localStorage.setItem('argo-theme',next);}catch{}describeTheme();});
  const reduce=matchMedia('(prefers-reduced-motion:reduce)');
  if(!reduce.matches&&'IntersectionObserver' in window){
    const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.remove('waiting');observer.unobserve(entry.target);}}),{threshold:.05});
    document.querySelectorAll('[data-enter]').forEach(el=>{if(el.getBoundingClientRect().top<innerHeight)el.classList.add('opening');else{el.classList.add('waiting');observer.observe(el);}});
    document.documentElement.classList.add('motion-ready');
    reduce.addEventListener('change',()=>{if(reduce.matches)document.querySelectorAll('.waiting').forEach(el=>el.classList.remove('waiting'));});
  }
  // Old public archive fragments still reach the archive after the split.
  if(document.body.classList.contains('overview-page')&&['#cases','#filters','#disclosures'].includes(location.hash)){location.replace('findings.html'+(location.hash==='#filters'?'#filters':''));return;}
  const form=document.getElementById('filters');
  if(!form)return;
  const cases=[...document.querySelectorAll('#cases .case')];
  const count=document.getElementById('filterCount'),empty=document.getElementById('noResults'),toggle=document.getElementById('toggleCases'),search=document.getElementById('searchInput');
  const statuses=['merged','advisory','fixed','open','issue','closed'];
  const state={sev:'',status:'',lang:'',stars:0,q:''};
  const counts={severity:new Map(),status:new Map(),projects:new Map()},languages=new Set();
  cases.forEach(sec=>{
    sec.dataset.lang=sec.querySelector('.chip-lang')?.textContent.trim()||'';
    languages.add(sec.dataset.lang);
    const name=sec.querySelector('.name a').textContent.trim();
    sec._rows=[...sec.querySelectorAll('.row')];
    sec._rows.forEach(row=>{
      row.dataset.status=statuses.find(s=>row.classList.contains(s))||'open';
      row._search=(name+' '+sec.dataset.lang+' '+sec.querySelector('.blurb').textContent+' '+row.textContent).toLowerCase().replace(/\s+/g,' ');
      for(const [key,value] of [['severity',row.dataset.sev||'Unspecified'],['status',row.dataset.status],['projects',name]])counts[key].set(value,(counts[key].get(value)||0)+1);
    });
  });
  const option=(parent,value,label)=>{const el=document.createElement('option');el.value=value;el.textContent=label;parent.append(el);};
  statuses.filter(s=>counts.status.has(s)).forEach(s=>option(document.getElementById('statusFilter'),s,s==='advisory'?'Published advisory':s[0].toUpperCase()+s.slice(1)));
  [...languages].filter(Boolean).sort().forEach(lang=>option(document.getElementById('languageFilter'),lang,lang));
  const active=()=>!!(state.sev||state.status||state.lang||state.stars||state.q);
  const visibleCases=()=>cases.filter(sec=>!sec.hidden);
  function apply(){
    let records=0,projects=0;
    for(const sec of cases){
      const projectMatches=(+sec.dataset.stars>=state.stars)&&(!state.lang||sec.dataset.lang===state.lang);
      let matches=0;
      sec._rows.forEach(row=>{
        const show=projectMatches&&(!state.sev||row.dataset.sev===state.sev)&&(!state.status||row.dataset.status===state.status)&&(!state.q||row._search.includes(state.q));
        row.closest('li').hidden=!show;
        if(show)matches++;
      });
      sec.hidden=!matches;
      if(matches){records+=matches;projects++;sec.open=active()||sec===cases[0]||location.hash===`#${sec.id}`;}
    }
    count.textContent=`${records} ${records===1?'record':'records'} across ${projects} ${projects===1?'project':'projects'}`;
    empty.hidden=records!==0;
    toggle.hidden=!projects;
    toggle.textContent=visibleCases().every(sec=>sec.open)?'Collapse all projects':'Expand all projects';
  }
  form.hidden=false;
  toggle.hidden=false;
  form.addEventListener('submit',e=>e.preventDefault());
  form.addEventListener('change',e=>{const key=e.target.dataset.filter;if(key){state[key]=key==='stars'?+e.target.value:e.target.value;apply();}});
  let timer;
  search.addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(()=>{state.q=search.value.trim().toLowerCase();apply();},120);});
  const reset=()=>{clearTimeout(timer);Object.assign(state,{sev:'',status:'',lang:'',stars:0,q:''});form.reset();apply();};
  // Native reset event must not call reset() recursively.
  form.addEventListener('reset',()=>{clearTimeout(timer);Object.assign(state,{sev:'',status:'',lang:'',stars:0,q:''});requestAnimationFrame(apply);});
  document.getElementById('resetFilters').addEventListener('click',reset);
  toggle.addEventListener('click',()=>{const visible=visibleCases(),open=!visible.every(sec=>sec.open);visible.forEach(sec=>{sec.open=open;});toggle.textContent=open?'Collapse all projects':'Expand all projects';});
  const openFragment=()=>{const sec=cases.find(sec=>`#${sec.id}`===location.hash);if(sec){if(sec.hidden)reset();sec.open=true;requestAnimationFrame(()=>sec.scrollIntoView({block:'start'}));}};
  window.addEventListener('hashchange',openFragment);
  apply();openFragment();
  const distribution=document.getElementById('distribution');distribution.hidden=false;
  const strip=document.getElementById('chartsStrip');
  for(const [key,title] of [['severity','By severity'],['status','By status'],['projects','Projects with most records']]){
    const panel=document.createElement('section');panel.className='chart-panel';
    const h=document.createElement('h2');h.textContent=title;panel.append(h);
    let entries=[...counts[key]].sort((a,b)=>b[1]-a[1]);if(key==='projects')entries=entries.slice(0,6);
    const max=Math.max(1,...entries.map(([,n])=>n));
    for(const [label,n]of entries){const row=document.createElement('div');row.className='bar-row';const name=document.createElement('span');name.textContent=label;const track=document.createElement('span');track.className='bar-track';track.setAttribute('aria-hidden','true');const fill=document.createElement('span');fill.className='bar-fill';fill.style.setProperty('--bar',`${n/max*100}%`);track.append(fill);const number=document.createElement('span');number.className='bar-value';number.textContent=String(n);row.append(name,track,number);panel.append(row);}strip.append(panel);
  }
})();
