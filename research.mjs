import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import {createHash} from 'node:crypto';
import path from 'node:path';

const SITE_ORIGIN='https://gigioneggiando.com/argo';
const SOURCE_ROOT=path.join('content','research');
const OUTPUT_ROOT='research';
const allowedCategories=new Set(['Disclosure','Engineering note','Method']);
const allowedSeverities=new Set(['Critical','High','Medium','Low','Info']);
const allowedStatuses=new Set(['Fixed','Mitigated','Published','Open']);
const datePattern=/^\d{4}-\d{2}-\d{2}$/;
const slugPattern=/^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const ensure=(ok,message)=>{if(!ok)throw Error(`Research build: ${message}`);};
const html=s=>String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const xml=s=>html(s).replace(/'/g,'&apos;');
const plain=s=>String(s).replace(/<pre[\s\S]*?<\/pre>/gi,' ').replace(/<[^>]+>/g,' ').replace(/&[a-z0-9#]+;/gi,' ').replace(/\s+/g,' ').trim();
const words=s=>plain(s).split(/\s+/).filter(Boolean).length;
const formatDate=value=>new Intl.DateTimeFormat('en-GB',{dateStyle:'long',timeZone:'UTC'}).format(new Date(`${value}T00:00:00Z`));
const formatIndexDate=value=>new Intl.DateTimeFormat('en-GB',{day:'numeric',month:'short',year:'numeric',timeZone:'UTC'}).format(new Date(`${value}T00:00:00Z`));
const hash=file=>createHash('sha256').update(readFileSync(file)).digest('hex').slice(0,12);
const canonicalFor=slug=>`${SITE_ORIGIN}/research/${slug?`${slug}/`:''}`;

function validDate(value,label){
  ensure(datePattern.test(value||''),`${label} must use YYYY-MM-DD`);
  ensure(!Number.isNaN(Date.parse(`${value}T00:00:00Z`)),`${label} is not a real date`);
}

function validateBody(body,slug){
  const forbidden=[
    [/(?:C:\\Users|[A-Z]:\\|\/Users\/|\/home\/)/i,'a local filesystem path'],
    [/\b(?:Fleece|outbox|\.codex|TUNNEL_TOKEN)\b/i,'a private workspace marker'],
    [/\b(?:ghp_|github_pat_|sk-[A-Za-z0-9])\w*/,'a credential-like token'],
    [/-----BEGIN [A-Z ]*PRIVATE KEY-----/,'a private key'],
    [/<\/?(?:script|iframe|object|embed|form)\b/i,'an unsafe HTML element'],
    [/\son[a-z]+\s*=/i,'an inline event handler'],
    [/javascript\s*:/i,'a javascript URL'],
  ];
  for(const [pattern,label] of forbidden)ensure(!pattern.test(body),`${slug}/body.html contains ${label}`);
  ensure(!/<h1\b/i.test(body),`${slug}/body.html must not contain an h1`);
  for(const id of ['what-went-wrong','why-it-mattered','how-it-was-fixed','after-the-patch']){
    ensure(new RegExp(`<h2[^>]+id=["']${id}["']`,'i').test(body),`${slug}/body.html is missing #${id}`);
  }
  const count=words(body);
  ensure(count>=250&&count<=1200,`${slug}/body.html must contain 250–1200 words; found ${count}`);
  for(const block of body.matchAll(/<pre\b[^>]*>([\s\S]*?)<\/pre>/gi)){
    const code=block[1].replace(/<[^>]+>/g,'').trim();
    ensure(code.split(/\r?\n/).length<=40,`${slug}/body.html has a code block longer than 40 lines`);
  }
  return count;
}

export function validateResearchArticle(meta,body,expectedSlug=meta?.slug,{requireApproval=true}={}){
  ensure(meta&&typeof meta==='object'&&!Array.isArray(meta),`${expectedSlug} metadata must be an object`);
  for(const key of ['slug','title','description','project','author','published','updated','category','status']){
    ensure(typeof meta[key]==='string'&&meta[key].trim(),`${expectedSlug} is missing ${key}`);
  }
  ensure(meta.slug===expectedSlug,`${expectedSlug} metadata slug does not match its folder`);
  ensure(slugPattern.test(meta.slug),`${meta.slug} is not a stable lowercase slug`);
  ensure(meta.title.length<=100,`${meta.slug} title must be 100 characters or fewer`);
  ensure(meta.description.length>=60&&meta.description.length<=260,`${meta.slug} description must be 60–260 characters`);
  validDate(meta.published,`${meta.slug} published`);
  validDate(meta.updated,`${meta.slug} updated`);
  ensure(meta.updated>=meta.published,`${meta.slug} updated date predates publication`);
  ensure(allowedCategories.has(meta.category),`${meta.slug} category must be Disclosure, Engineering note, or Method`);
  ensure(allowedStatuses.has(meta.status),`${meta.slug} has unsupported status ${meta.status}`);
  if(meta.resolved!==undefined)validDate(meta.resolved,`${meta.slug} resolved`);
  if(meta.status==='Fixed'||meta.status==='Mitigated')ensure(meta.resolved,`${meta.slug} needs the public upstream resolution date`);
  if(meta.severity!==undefined)ensure(allowedSeverities.has(meta.severity),`${meta.slug} severity must use Argo's grouped labels; use Medium for GitHub Moderate`);
  ensure(Array.isArray(meta.tags)&&meta.tags.length>=1&&meta.tags.length<=5,`${meta.slug} needs 1–5 tags`);
  ensure(meta.tags.every(tag=>typeof tag==='string'&&tag.trim()&&tag.length<=32),`${meta.slug} has an invalid tag`);
  ensure(Array.isArray(meta.identifiers),`${meta.slug} identifiers must be an array`);
  ensure(meta.identifiers.every(id=>/^(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})$/i.test(id)),`${meta.slug} has an invalid public identifier`);
  ensure(Array.isArray(meta.publicEvidence)&&meta.publicEvidence.length>=1,`${meta.slug} needs at least one public evidence link`);
  for(const evidence of meta.publicEvidence){
    ensure(typeof evidence?.label==='string'&&evidence.label.trim(),`${meta.slug} has evidence without a label`);
    let url;
    try{url=new URL(evidence.url);}catch{throw Error(`Research build: ${meta.slug} has an invalid evidence URL`);}
    ensure(url.protocol==='https:',`${meta.slug} evidence URLs must use HTTPS`);
    ensure(!/(?:localhost|127\.0\.0\.1|\.local)$/i.test(url.hostname),`${meta.slug} evidence URL is not public`);
  }
  if(requireApproval){
    ensure(meta.approval?.decision==='approved',`${meta.slug} lacks the manual approved decision`);
    ensure(meta.approval?.approvedBy==='Luigi Colluto',`${meta.slug} must be approved by Luigi Colluto`);
    validDate(meta.approval?.approvedOn,`${meta.slug} approval date`);
    validDate(meta.approval?.publicEvidenceCheckedOn,`${meta.slug} public-evidence check date`);
  }else{
    ensure(meta.approval?.decision==='draft'||meta.approval?.decision==='approved',`${meta.slug} preview must be marked draft or approved`);
  }
  const wordCount=validateBody(body,meta.slug);
  return {...meta,body,wordCount,readMinutes:Math.max(1,Math.ceil(wordCount/220))};
}

export function loadResearchArticles({sourceRoot=SOURCE_ROOT}={}){
  const manifestPath=path.join(sourceRoot,'manifest.json');
  ensure(existsSync(manifestPath),'content/research/manifest.json is missing');
  const manifest=JSON.parse(readFileSync(manifestPath,'utf8'));
  ensure(manifest.schemaVersion===1,'unsupported manifest schema');
  ensure(Array.isArray(manifest.approvedArticles),'manifest approvedArticles must be an array');
  ensure(new Set(manifest.approvedArticles).size===manifest.approvedArticles.length,'manifest contains duplicate slugs');
  return manifest.approvedArticles.map(slug=>{
    ensure(typeof slug==='string'&&slugPattern.test(slug),`manifest has invalid slug ${slug}`);
    const folder=path.join(sourceRoot,'articles',slug);
    const metaPath=path.join(folder,'article.json');
    const bodyPath=path.join(folder,'body.html');
    ensure(existsSync(metaPath)&&existsSync(bodyPath),`${slug} is allow-listed but its source files are missing`);
    const meta=JSON.parse(readFileSync(metaPath,'utf8'));
    return validateResearchArticle(meta,readFileSync(bodyPath,'utf8'),slug);
  }).sort((a,b)=>(b.resolved||b.published).localeCompare(a.resolved||a.published)||a.title.localeCompare(b.title,'en'));
}

function metadata(meta){
  const facts=[
    ['Project',meta.project],
    ...(meta.severity?[['Severity',meta.severity]]:[]),
    ['Status',meta.status],
    ...(meta.resolved?[['Resolved upstream',formatDate(meta.resolved)]]:[]),
    ...(meta.identifiers.length?[['Identifiers',meta.identifiers.join(', ')]]:[]),
  ];
  return `<dl class="article-facts">${facts.map(([label,value])=>`<div><dt>${html(label)}</dt><dd>${html(value)}</dd></div>`).join('')}</dl>`;
}

function evidenceList(meta){
  return `<section class="public-record" aria-labelledby="public-record"><h2 id="public-record">Public record</h2><ul>${meta.publicEvidence.map(item=>`<li><a href="${html(item.url)}" target="_blank" rel="noopener">${html(item.label)}</a></li>`).join('')}</ul></section>`;
}

function articleJsonLd(meta){
  return JSON.stringify({
    '@context':'https://schema.org',
    '@type':'TechArticle',
    headline:meta.title,
    description:meta.description,
    datePublished:meta.published,
    dateModified:meta.updated,
    author:{'@type':'Person',name:meta.author,url:'https://gigioneggiando.com/about.html'},
    about:meta.project,
    keywords:meta.tags.join(', '),
    mainEntityOfPage:canonicalFor(meta.slug),
  }).replace(/</g,'\\u003c');
}

function shell({title,description,canonical,type='website',prefix,body,header,footer,jsonLd=''}){
  const styleVersion=hash('style.css');
  const scriptVersion=hash('script.js');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="description" content="${html(description)}"><link rel="canonical" href="${html(canonical)}"><meta property="og:title" content="${html(title)} · Argo"><meta property="og:description" content="${html(description)}"><meta property="og:type" content="${type}"><meta property="og:url" content="${html(canonical)}"><meta name="theme-color" content="#121419"><title>${html(title)} · Argo</title><link rel="icon" href="${prefix}assets/eye.svg" type="image/svg+xml"><link rel="preload" href="${prefix}assets/fonts/fraunces-var.woff2" as="font" type="font/woff2" crossorigin><link rel="alternate" type="application/atom+xml" title="Argo Research" href="/argo/research/feed.xml"><link rel="stylesheet" href="${prefix}style.css?v=${styleVersion}"><script>try{const t=localStorage.getItem('argo-theme');if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;}catch{}</script>${jsonLd?`<script type="application/ld+json">${jsonLd}</script>`:''}<script src="${prefix}script.js?v=${scriptVersion}" defer></script></head><body class="research-reading-page">${header}<main id="main">${body}</main>${footer}</body></html>
`;
}

function buildIndex(articles,{renderHeader,renderFooter}){
  const cards=articles.map((article,index)=>{
    const date=article.resolved||article.published;
    const dateLabel=article.resolved?'Resolved upstream':'Published';
    return `<li class="research-entry"><article><a class="research-entry-link" href="./${article.slug}/"><div class="research-entry-index"><span class="research-entry-number">${String(index+1).padStart(2,'0')}</span><span>${dateLabel}</span><time datetime="${date}">${html(formatIndexDate(date))}</time></div><div class="research-entry-copy"><div class="research-entry-meta"><span>${html(article.category)}</span><span>${html(article.project)}</span>${article.identifiers[0]?`<span>${html(article.identifiers[0])}</span>`:''}</div><h2>${html(article.title)}</h2><p>${html(article.description)}</p></div><div class="research-entry-side"><span class="sev ${article.severity?html(article.severity.toLowerCase()):''}">${html(article.severity||article.status)}</span><span>${article.readMinutes} min read</span><svg class="research-entry-arrow" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 18 18 6M6 6h12v12"/></svg></div></a></article></li>`;
  }).join('');
  const body=`<div class="research-shell"><section class="research-intro" aria-labelledby="research-title"><h1 id="research-title">Notes from looking closely.</h1><p>Short accounts of what broke, why it mattered, and how maintainers repaired it.</p><a href="feed.xml">Follow the Atom feed</a></section><ol class="research-index" aria-label="Research articles">${cards}</ol></div>`;
  return shell({title:'Research',description:'Short, evidence-backed accounts of public Argo findings: what broke, why it mattered, and how it was repaired.',canonical:canonicalFor(),prefix:'../',body,header:renderHeader('research',1),footer:renderFooter(1)});
}

function buildArticle(meta,{renderHeader,renderFooter}){
  const dates=meta.updated===meta.published?`Published ${formatDate(meta.published)}`:`Published ${formatDate(meta.published)} · Updated ${formatDate(meta.updated)}`;
  const displayedDates=meta.approval?.decision==='draft'?`Draft dated ${formatDate(meta.updated)}`:dates;
  const resolution=meta.resolved?`Resolved upstream ${formatDate(meta.resolved)} · `:'';
  const body=`<div class="article-shell"><a class="article-back" href="../">Back to Research</a><header class="article-header"><div class="article-kicker"><span>${html(meta.category)}</span><span>${html(meta.project)}</span></div><h1>${html(meta.title)}</h1><p class="article-dek">${html(meta.description)}</p><p class="article-byline">By ${html(meta.author)} · ${html(resolution+displayedDates)} · ${meta.readMinutes} min read</p></header><div class="article-layout"><aside aria-label="Article facts">${metadata(meta)}</aside><article class="article-body">${meta.body}${evidenceList(meta)}</article></div></div>`;
  return shell({title:meta.title,description:meta.description,canonical:canonicalFor(meta.slug),type:'article',prefix:'../../',body,header:renderHeader('research',2),footer:renderFooter(2),jsonLd:articleJsonLd(meta)});
}

function atom(articles){
  const updated=articles.map(a=>a.updated).sort().at(-1);
  return `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Argo Research</title>
  <id>${SITE_ORIGIN}/research/</id>
  <link href="${SITE_ORIGIN}/research/"/>
  <link href="${SITE_ORIGIN}/research/feed.xml" rel="self" type="application/atom+xml"/>
  <updated>${updated}T00:00:00Z</updated>
  <author><name>Luigi Colluto</name><uri>https://gigioneggiando.com/</uri></author>
${articles.map(a=>`  <entry>
    <title>${xml(a.title)}</title>
    <id>${canonicalFor(a.slug)}</id>
    <link href="${canonicalFor(a.slug)}"/>
    <published>${a.published}T00:00:00Z</published>
    <updated>${a.updated}T00:00:00Z</updated>
    <summary>${xml(a.description)}</summary>
${a.tags.map(tag=>`    <category term="${xml(tag)}"/>`).join('\n')}
  </entry>`).join('\n')}
</feed>
`;
}

export function writeResearchSite(articles,{outputRoot=OUTPUT_ROOT,renderHeader,renderFooter}={}){
  ensure(typeof renderHeader==='function'&&typeof renderFooter==='function','shared header/footer renderers are required');
  if(existsSync(outputRoot))rmSync(outputRoot,{recursive:true,force:true});
  if(!articles.length)return {articles:0,files:0};
  mkdirSync(outputRoot,{recursive:true});
  writeFileSync(path.join(outputRoot,'index.html'),buildIndex(articles,{renderHeader,renderFooter}));
  writeFileSync(path.join(outputRoot,'feed.xml'),atom(articles));
  for(const article of articles){
    const folder=path.join(outputRoot,article.slug);
    mkdirSync(folder,{recursive:true});
    writeFileSync(path.join(folder,'index.html'),buildArticle(article,{renderHeader,renderFooter}));
  }
  return {articles:articles.length,files:articles.length+2};
}
