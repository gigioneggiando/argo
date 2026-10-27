import {existsSync,readFileSync} from 'node:fs';
import path from 'node:path';
import {validateResearchArticle,writeResearchSite} from './research.mjs';
import {renderFooter,renderHeader} from './site-chrome.mjs';

const source=process.argv[2];
const outputRoot=process.argv[3]||'.research-preview';
if(!source){
  throw Error('Usage: node preview-research.mjs <draft-folder> [output-folder]');
}

const metaPath=path.join(source,'article.json');
const bodyPath=path.join(source,'body.html');
if(!existsSync(metaPath)||!existsSync(bodyPath)){
  throw Error('Draft folder must contain article.json and body.html');
}

const meta=JSON.parse(readFileSync(metaPath,'utf8'));
const article=validateResearchArticle(meta,readFileSync(bodyPath,'utf8'),meta.slug,{requireApproval:false});
const header=(current,depth=0)=>renderHeader({current,depth,hasResearch:true});
const footer=(depth=0)=>renderFooter({depth,hasResearch:true});
const result=writeResearchSite([article],{outputRoot,renderHeader:header,renderFooter:footer});
console.log(`Rendered draft ${article.slug} to ${path.resolve(outputRoot)} (${result.files} files). Nothing was added to the publication manifest.`);
