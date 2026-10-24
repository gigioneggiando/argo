// Extract complete native record elements, including div rows with multiple
// evidence links. The older archive contains both anchor and div records.
export function extractRecords(html) {
  const records=[];
  const start=/<(a|div)\b[^>]*\bclass="row(?:\s+[^"]*)?"[^>]*>/g;
  let match;
  while((match=start.exec(html))) {
    const tag=match[1];
    const tokens=new RegExp(`<\\/?${tag}\\b[^>]*>`,'g');
    tokens.lastIndex=start.lastIndex;
    let depth=1,end;
    while((end=tokens.exec(html))) {
      if(end[0].startsWith('</'))depth--;else if(!end[0].endsWith('/>'))depth++;
      if(depth===0)break;
    }
    if(depth!==0)throw Error('Unclosed public record');
    records.push(html.slice(match.index,tokens.lastIndex));
    start.lastIndex=tokens.lastIndex;
  }
  return records;
}
