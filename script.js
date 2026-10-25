(() => {
  const themeButton=document.getElementById('themeToggle');
  if(themeButton)themeButton.hidden=false;
  const theme=()=>document.documentElement.dataset.theme||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');
  const describeTheme=()=>{const dark=theme()==='dark';const label=`Switch to ${dark?'light':'dark'} theme`;themeButton?.setAttribute('aria-label',label);themeButton?.setAttribute('title',label);themeButton?.setAttribute('aria-pressed',String(dark));if(themeButton){themeButton.querySelector('.theme-sun').toggleAttribute('hidden',!dark);themeButton.querySelector('.theme-moon').toggleAttribute('hidden',dark);}};
  describeTheme();
  themeButton?.addEventListener('click',()=>{const next=theme()==='dark'?'light':'dark';document.documentElement.dataset.theme=next;try{localStorage.setItem('argo-theme',next);}catch{}describeTheme();});
  matchMedia('(prefers-color-scheme:dark)').addEventListener('change',describeTheme);
  const reduce=matchMedia('(prefers-reduced-motion:reduce)');
  if(!reduce.matches&&'IntersectionObserver' in window){
    const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{if(entry.isIntersecting){entry.target.classList.remove('waiting');observer.unobserve(entry.target);}}),{threshold:.05});
    document.querySelectorAll('[data-enter]').forEach(el=>{if(el.getBoundingClientRect().top<innerHeight)el.classList.add('opening');else{el.classList.add('waiting');observer.observe(el);}});
    document.documentElement.classList.add('motion-ready');
    reduce.addEventListener('change',()=>{if(reduce.matches)document.querySelectorAll('.waiting').forEach(el=>el.classList.remove('waiting'));});
  }
  // Former archive fragments remain useful now that the archive is on home too.
  if(location.hash==='#disclosures')location.hash='#findings';
  const form=document.getElementById('filters');
  if(!form)return;
  const cases=[...document.querySelectorAll('#cases .case')];
  const count=document.getElementById('filterCount'),empty=document.getElementById('noResults'),toggle=document.getElementById('toggleCases'),search=document.getElementById('searchInput');
  const statuses=['merged','advisory','fixed','open','issue','closed'];
  const state={sev:'',status:'',lang:'',stars:0,q:''};
  const severityGroup=label=>label==='Moderate'?'Medium':label;
  const counts={severity:new Map(),status:new Map(),projects:new Map()},languages=new Set();
  cases.forEach(sec=>{
    sec.dataset.lang=sec.querySelector('.chip-lang')?.textContent.trim()||'';
    languages.add(sec.dataset.lang);
    const name=sec.querySelector('.name a').textContent.trim();
    sec._rows=[...sec.querySelectorAll('.row')];
    sec._rows.forEach(row=>{
      row.dataset.status=statuses.find(s=>row.classList.contains(s))||'open';
      row._search=(name+' '+sec.dataset.lang+' '+sec.querySelector('.blurb').textContent+' '+row.textContent).toLowerCase().replace(/\s+/g,' ');
      for(const [key,value] of [['severity',severityGroup(row.dataset.sev||'Unspecified')],['status',row.dataset.status],['projects',name]])counts[key].set(value,(counts[key].get(value)||0)+1);
    });
  });
  const option=(parent,value,label)=>{const el=document.createElement('option');el.value=value;el.textContent=label;parent.append(el);};
  statuses.filter(s=>counts.status.has(s)).forEach(s=>option(document.getElementById('statusFilter'),s,s==='advisory'?'Published advisory':s[0].toUpperCase()+s.slice(1)));
  [...languages].filter(Boolean).sort().forEach(lang=>option(document.getElementById('languageFilter'),lang,lang));
  for(const severity of counts.severity.keys())if(!['Critical','High','Medium','Low'].includes(severity))option(document.getElementById('severityFilter'),severity,severity);
  const controls=window.ArgoControls.enhance(form);
  const active=()=>!!(state.sev||state.status||state.lang||state.stars||state.q);
  const visibleCases=()=>cases.filter(sec=>!sec.hidden);
  function sortProjects(){
    const container=document.getElementById('cases');
    const current=[...container.children];
    const visible=visibleCases();
    const anchor=visible.find(sec=>{const rect=sec.getBoundingClientRect();return rect.bottom>0&&rect.top<innerHeight;});
    const anchorTop=anchor?.getBoundingClientRect().top;
    const reading=window.scrollY>0&&container.getBoundingClientRect().top<innerHeight/2;
    const focused=container.contains(document.activeElement)?document.activeElement:null;
    cases.sort((a,b)=>+b.dataset.stars-+a.dataset.stars||a.querySelector('.name a').textContent.trim().localeCompare(b.querySelector('.name a').textContent.trim(),'en'));
    if(cases.some((sec,i)=>sec!==current[i])){
      container.append(...cases);
      focused?.focus({preventScroll:true});
      if(reading&&anchor)window.scrollBy({top:anchor.getBoundingClientRect().top-anchorTop,behavior:'instant'});
    }
  }
  let sortTimer;
  const scheduleSort=()=>{clearTimeout(sortTimer);sortTimer=setTimeout(()=>{sortProjects();if(state.stars)apply();},150);};
  function apply(){
    let records=0,projects=0;
    for(const sec of cases){
      const projectMatches=(+sec.dataset.stars>=state.stars)&&(!state.lang||sec.dataset.lang===state.lang);
      let matches=0;
      sec._rows.forEach(row=>{
        const show=projectMatches&&(!state.sev||severityGroup(row.dataset.sev||'Unspecified')===state.sev)&&(!state.status||row.dataset.status===state.status)&&(!state.q||row._search.includes(state.q));
        row.closest('li').hidden=!show;
        if(show)matches++;
      });
      sec.hidden=!matches;
      if(matches){records+=matches;projects++;sec.open=active()||sec===cases[0]||location.hash===`#${sec.id}`;}
    }
    count.textContent=`${records} ${records===1?'record':'records'} across ${projects} ${projects===1?'project':'projects'} · Most starred first`;
    empty.hidden=records!==0;
    toggle.hidden=!projects;
    toggle.textContent=visibleCases().every(sec=>sec.open)?'Collapse all projects':'Expand all projects';
    controls.sync();
  }
  form.hidden=false;
  toggle.hidden=false;
  form.addEventListener('submit',e=>e.preventDefault());
  form.addEventListener('change',e=>{const key=e.target.dataset.filter;if(key){state[key]=key==='stars'?+e.target.value:e.target.value;apply();if(key==='stars'&&state.stars)starTracker.refreshAll();}});
  let timer;
  search.addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(()=>{state.q=search.value.trim().toLowerCase();apply();},120);});
  const reset=()=>{clearTimeout(timer);Object.assign(state,{sev:'',status:'',lang:'',stars:0,q:''});form.reset();apply();};
  // Native reset event must not call reset() recursively.
  form.addEventListener('reset',()=>{clearTimeout(timer);Object.assign(state,{sev:'',status:'',lang:'',stars:0,q:''});requestAnimationFrame(apply);});
  document.getElementById('resetFilters').addEventListener('click',reset);
  toggle.addEventListener('click',()=>{const visible=visibleCases(),open=!visible.every(sec=>sec.open);visible.forEach(sec=>{sec.open=open;});toggle.textContent=open?'Collapse all projects':'Expand all projects';});
  const openFragment=()=>{const sec=cases.find(sec=>`#${sec.id}`===location.hash);if(sec){if(sec.hidden)reset();sec.open=true;requestAnimationFrame(()=>sec.scrollIntoView({block:'start'}));}};
  window.addEventListener('hashchange',openFragment);
  const starTracker=window.ArgoStars.connect(cases,scheduleSort);
  sortProjects();apply();openFragment();
  document.querySelectorAll('[data-chart-filter]').forEach(button=>{
    button.disabled=false;
    button.addEventListener('click',()=>{
      reset();
      const key=button.dataset.chartFilter,value=button.dataset.value;
      state[key]=key==='q'?value.toLowerCase():value;
      if(key==='q')search.value=value;
      else document.getElementById('severityFilter').value=value;
      apply();
      document.getElementById('findings').scrollIntoView({block:'start',behavior:reduce.matches?'instant':'smooth'});
      search.focus({preventScroll:true});
    });
  });
})();
