import {mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {loadResearchArticles,validateResearchArticle,writeResearchSite} from './research.mjs';

const ensure=(ok,message)=>{if(!ok)throw Error(message);};
const root=mkdtempSync(path.join(tmpdir(),'argo-research-'));
const source=path.join(root,'source');
const output=path.join(root,'research');
const slug='example-broken-invariant';
const articleFolder=path.join(source,'articles',slug);
mkdirSync(articleFolder,{recursive:true});

const paragraph='The public code accepted a value without preserving the identity that should have constrained it. The explanation distinguishes the observed behaviour from broader impact, states the conditions needed to reach it, and follows the public repair rather than turning the finding into a claim about every deployment. ';
const body=`<section aria-labelledby="what-went-wrong"><h2 id="what-went-wrong">What went wrong</h2><p>${paragraph.repeat(3)}</p></section><section aria-labelledby="why-it-mattered"><h2 id="why-it-mattered">Why it mattered</h2><p>${paragraph.repeat(3)}</p></section><section aria-labelledby="how-it-was-fixed"><h2 id="how-it-was-fixed">How it was fixed</h2><p>${paragraph.repeat(3)}</p></section><section aria-labelledby="after-the-patch"><h2 id="after-the-patch">After the patch</h2><p>${paragraph.repeat(3)}</p></section>`;
const meta={
  slug,
  title:'A test invariant that lost its identity',
  description:'A fixture that proves the explicit allow-list, publication metadata, stable paths, feed, and private-data checks work together.',
  project:'Example',
  author:'Luigi Colluto',
  published:'2026-10-26',
  updated:'2026-10-27',
  resolved:'2026-10-25',
  category:'Disclosure',
  tags:['access control'],
  severity:'Medium',
  status:'Fixed',
  identifiers:['CVE-2026-12345'],
  publicEvidence:[{label:'Published advisory',url:'https://example.com/advisory'}],
  approval:{decision:'approved',approvedBy:'Luigi Colluto',approvedOn:'2026-10-27',publicEvidenceCheckedOn:'2026-10-27'},
};

try{
  writeFileSync(path.join(source,'manifest.json'),JSON.stringify({schemaVersion:1,approvedArticles:[slug]}));
  writeFileSync(path.join(articleFolder,'article.json'),JSON.stringify(meta));
  writeFileSync(path.join(articleFolder,'body.html'),body);
  const articles=loadResearchArticles({sourceRoot:source});
  ensure(articles.length===1&&articles[0].readMinutes>=1,'Approved fixture did not load');
  const result=writeResearchSite(articles,{outputRoot:output,renderHeader:(current,depth)=>`<header data-current="${current}" data-depth="${depth}"></header>`,renderFooter:depth=>`<footer data-depth="${depth}"></footer>`,projectStars:new Map([['example',4242]])});
  ensure(result.articles===1&&result.files===3,'Unexpected generated file count');
  const index=readFileSync(path.join(output,'index.html'),'utf8');
  const article=readFileSync(path.join(output,slug,'index.html'),'utf8');
  const feed=readFileSync(path.join(output,'feed.xml'),'utf8');
  ensure(index.includes(`./${slug}/`)&&index.includes('Notes from looking closely.'),'Research index is incomplete');
  ensure(index.includes('Resolved upstream')&&index.includes('25 Oct 2026')&&!index.includes('research-entry-number'),'Research index does not expose the upstream chronology cleanly');
  ensure(index.includes('id="researchFilters"')&&index.includes('id="researchSearch"')&&index.includes('id="researchSeverity"')&&index.includes('id="researchSort"'),'Research exploration controls are incomplete');
  ensure(index.includes('data-stars="4242"')&&index.includes('~4.2K stars'),'Research project reach is missing from the index or its project lookup is case-sensitive');
  ensure(index.includes('research-process')&&index.includes('<span>close review</span>'),'Research index is missing its source-to-repair diagram');
  ensure(index.includes('rel="alternate" type="application/atom+xml" title="Argo Research" href="/argo/research/feed.xml"'),'Research index does not expose the stable public feed path');
  ensure(index.includes('rel="describedby" href="https://gigioneggiando.com/argo/llms.txt"'),'Research index does not link to the agent guide');
  ensure(article.includes(`https://gigioneggiando.com/argo/research/${slug}/`)&&article.includes('application/ld+json')&&article.includes('Public record'),'Article metadata or evidence is incomplete');
  ensure(article.includes('rel="describedby" href="https://gigioneggiando.com/argo/llms.txt"'),'Research article does not link to the agent guide');
  ensure(feed.includes('<feed xmlns="http://www.w3.org/2005/Atom">')&&feed.includes(meta.title),'Atom feed is incomplete');
  let rejectedPrivate=false;
  try{validateResearchArticle(meta,`${body}<p>C:\\Users\\private\\draft.txt</p>`,slug);}catch{rejectedPrivate=true;}
  ensure(rejectedPrivate,'Private-path fixture was not rejected');
  let rejectedApproval=false;
  try{validateResearchArticle({...meta,approval:{...meta.approval,decision:'draft'}},body,slug);}catch{rejectedApproval=true;}
  ensure(rejectedApproval,'Unapproved fixture was not rejected');
  const preview=validateResearchArticle({...meta,approval:{decision:'draft'}},body,slug,{requireApproval:false});
  ensure(preview.slug===slug,'Draft preview validation failed');
  console.log('PASS: explicit allow-list, metadata, short-form structure, canonical/JSON-LD, Atom feed, draft preview, and fail-closed private-data/approval checks.');
}finally{
  rmSync(root,{recursive:true,force:true});
}
