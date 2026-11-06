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
  const researchForm=document.getElementById('researchFilters');
  if(researchForm){
    const index=document.getElementById('researchIndex');
    const entries=[...index.querySelectorAll('.research-entry')];
    const count=document.getElementById('researchCount');
    const empty=document.getElementById('researchNoResults');
    const search=document.getElementById('researchSearch');
    const severity=document.getElementById('researchSeverity');
    const sort=document.getElementById('researchSort');
    const severityRank={Critical:5,High:4,Medium:3,Low:2,Info:1};
    const label={resolved:'recently fixed first',published:'newly published first',stars:'most starred project first',severity:'highest severity first'};
    const compare={
      resolved:(a,b)=>b.dataset.resolved.localeCompare(a.dataset.resolved)||b.dataset.published.localeCompare(a.dataset.published),
      published:(a,b)=>b.dataset.published.localeCompare(a.dataset.published)||b.dataset.resolved.localeCompare(a.dataset.resolved),
      stars:(a,b)=>+b.dataset.stars-+a.dataset.stars||b.dataset.resolved.localeCompare(a.dataset.resolved),
      severity:(a,b)=>(severityRank[b.dataset.severity]||0)-(severityRank[a.dataset.severity]||0)||b.dataset.resolved.localeCompare(a.dataset.resolved),
    };
    const apply=()=>{
      const term=search.value.trim().toLowerCase();
      const selectedSeverity=severity.value;
      let visible=0;
      for(const entry of entries){
        const show=(!term||entry.dataset.search.includes(term))&&(!selectedSeverity||entry.dataset.severity===selectedSeverity);
        entry.hidden=!show;
        if(show)visible++;
      }
      entries.sort(compare[sort.value]||compare.resolved);
      index.append(...entries);
      count.textContent=`${visible} ${visible===1?'article':'articles'} · ${label[sort.value]}`;
      empty.hidden=visible!==0;
    };
    let timer;
    search.addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(apply,100);});
    researchForm.addEventListener('change',apply);
    researchForm.addEventListener('submit',event=>event.preventDefault());
    researchForm.addEventListener('reset',()=>{clearTimeout(timer);requestAnimationFrame(apply);});
    researchForm.hidden=false;
    apply();
  }
  const form=document.getElementById('filters');
  if(!form)return;
  const cases=[...document.querySelectorAll('#cases .case')];
  const count=document.getElementById('filterCount'),empty=document.getElementById('noResults'),toggle=document.getElementById('toggleCases'),search=document.getElementById('searchInput');
  const statuses=['merged','advisory','fixed','open','issue','closed'];
  // Status describes the OUTCOME only; the record type has its own filter. Each record gets one
  // outcome from its type, its row class and (for advisories) its fixed/unpatched label.
  const outcomeOf=(kind,row)=>{
    const cls=statuses.find(s=>row.classList.contains(s))||'open';
    if(kind==='pr')return cls==='merged'?'merged':cls==='fixed'?'fixed-other':cls==='closed'?'closed':'open';
    if(kind==='advisory')return /unpatched/i.test(row.querySelector('.status')?.textContent||'')?'unpatched':'fixed';
    return cls==='fixed'||cls==='merged'?'fixed':cls==='closed'?'closed':'open';
  };
  const resolvedOutcomes=new Set(['merged','fixed-other','fixed']);
  // Options per Type: generic resolved/unresolved for all types, precise outcomes per type.
  const statusChoices={
    '':[['done','Fixed'],['pending','Not fixed yet']],
    pr:[['merged','Merged'],['fixed-other','Fixed upstream'],['open','Open'],['closed','Closed']],
    advisory:[['fixed','Fixed'],['unpatched','Unpatched']],
    issue:[['fixed','Fixed'],['open','Open'],['closed','Closed']],
    other:[['done','Fixed'],['pending','Not fixed yet']],
  };
  const statusMatches=(row,value)=>!value||(value==='done'?resolvedOutcomes.has(row.dataset.outcome):value==='pending'?!resolvedOutcomes.has(row.dataset.outcome):row.dataset.outcome===value);
  // Record type from the row's primary upstream link (the record's own evidence), not its status.
  const kinds=[['pr','Pull requests'],['advisory','Advisories (GHSA)'],['issue','Issues']];
  const kindOf=href=>/\/pull\/\d+|\/merge_requests\/\d+/.test(href)?'pr':/\/security\/advisories\/|GHSA-/i.test(href)?'advisory':/\/issues\/\d+/.test(href)?'issue':'other';
  const state={kind:'',sev:'',status:'',lang:'',stars:0,q:''};
  const severityGroup=label=>label==='Moderate'?'Medium':label;
  const counts={severity:new Map(),status:new Map(),projects:new Map(),kind:new Map()},languages=new Set();
  cases.forEach(sec=>{
    sec.dataset.lang=sec.querySelector('.chip-lang')?.textContent.trim()||'';
    languages.add(sec.dataset.lang);
    const name=sec.querySelector('.name a').textContent.trim();
    sec._rows=[...sec.querySelectorAll('.row')];
    sec._rows.forEach(row=>{
      row.dataset.status=statuses.find(s=>row.classList.contains(s))||'open';
      row.dataset.kind=kindOf(row.getAttribute('href')||row.querySelector('a[href]')?.getAttribute('href')||'');
      row._search=(name+' '+sec.dataset.lang+' '+sec.querySelector('.blurb').textContent+' '+row.textContent).toLowerCase().replace(/\s+/g,' ');
      for(const [key,value] of [['severity',severityGroup(row.dataset.sev||'Unspecified')],['status',row.dataset.status],['projects',name],['kind',row.dataset.kind]])counts[key].set(value,(counts[key].get(value)||0)+1);
      row.dataset.outcome=outcomeOf(row.dataset.kind,row);
    });
  });
  const option=(parent,value,label)=>{const el=document.createElement('option');el.value=value;el.textContent=label;parent.append(el);};
  kinds.filter(([k])=>counts.kind.has(k)).forEach(([k,label])=>option(document.getElementById('typeFilter'),k,label));
  if(counts.kind.has('other'))option(document.getElementById('typeFilter'),'other','Other');
  const allRows=cases.flatMap(sec=>sec._rows);
  const statusSelect=document.getElementById('statusFilter');
  // Rebuild Status for the chosen Type, listing only outcomes that occur for it; a now-invalid
  // selection falls back to "All statuses". controls.js re-renders the popup on the next sync.
  const fillStatus=kind=>{
    const rows=kind?allRows.filter(r=>r.dataset.kind===kind):allRows;
    const keep=state.status;
    while(statusSelect.options.length>1)statusSelect.remove(1);
    for(const [value,label] of statusChoices[kind]||statusChoices[''])if(rows.some(r=>statusMatches(r,value)))option(statusSelect,value,label);
    const valid=[...statusSelect.options].some(o=>o.value===keep);
    statusSelect.value=valid?keep:'';
    state.status=statusSelect.value;
  };
  fillStatus('');
  [...languages].filter(Boolean).sort().forEach(lang=>option(document.getElementById('languageFilter'),lang,lang));
  for(const severity of counts.severity.keys())if(!['Critical','High','Medium','Low'].includes(severity))option(document.getElementById('severityFilter'),severity,severity);
  const controls=window.ArgoControls.enhance(form);
  const active=()=>!!(state.kind||state.sev||state.status||state.lang||state.stars||state.q);
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
        const show=projectMatches&&(!state.kind||row.dataset.kind===state.kind)&&(!state.sev||severityGroup(row.dataset.sev||'Unspecified')===state.sev)&&statusMatches(row,state.status)&&(!state.q||row._search.includes(state.q));
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
  form.addEventListener('change',e=>{const key=e.target.dataset.filter;if(key){state[key]=key==='stars'?+e.target.value:e.target.value;if(key==='kind')fillStatus(state.kind);apply();if(key==='stars'&&state.stars)starTracker.refreshAll();}});
  let timer;
  search.addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(()=>{state.q=search.value.trim().toLowerCase();apply();},120);});
  const reset=()=>{clearTimeout(timer);Object.assign(state,{kind:'',sev:'',status:'',lang:'',stars:0,q:''});form.reset();fillStatus('');apply();};
  // Native reset event must not call reset() recursively.
  form.addEventListener('reset',()=>{clearTimeout(timer);Object.assign(state,{kind:'',sev:'',status:'',lang:'',stars:0,q:''});requestAnimationFrame(()=>{fillStatus('');apply();});});
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
