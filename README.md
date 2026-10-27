# Argo public site

Projects appear from most to least starred, using the archive snapshot without
JS and cached/live GitHub counts when available. Equal counts sort by project
name. Live updates preserve open disclosures, keyboard focus and the reader's
scroll anchor where the available page height permits it. The ranked chart
still explicitly compares record counts, a separate metric.

`node verify-sorting.mjs` checks live/cache ordering and reading/focus state with
controlled metadata, without spending public GitHub API quota.

This is the `gh-pages` worktree of `gigioneggiando/argo`.
For the complete finding-to-publication procedure, including the separate
personal-site deployment, see [AGENTS.md](AGENTS.md).

- `index.html`: project introduction, totals, visible charts and searchable archive.
- `findings.html`: static, searchable public archive.
- `content/disclosures.html`: the authoritative public record source.
- `content/research/manifest.json`: explicit allow-list for approved Research articles.
- `content/research/articles/<slug>/`: approved article metadata and body source.
- `research/`: generated editorial index, stable article paths and Atom feed; absent until the first approved article.
- `build.mjs`: shared shell, counts, project disclosures and page generation.
- `research.mjs`: fail-closed article validation and Research page/feed generation.
- `style.css` / `script.js`: shared presentation and progressive enhancement.
- `controls.js`: rounded, keyboard-accessible filter popups over native selects.
- `stars.js`: optional public GitHub star metadata, cached in the visitor's browser.

Edit the source chapters and run `node build.mjs`. Do not hand-edit generated
HTML, Research output or headline totals. Totals derive from the public rows; one row can be a
backport, a public issue or an advisory, so records are not distinct vulnerabilities.

Every row must already have a public upstream URL. An unpublished/private
advisory must remain outside this site. Preserve distinctions between merged,
fixed upstream, open, issue and advisory; published can still mean unpatched.
Private Fleece records are not a build input. The archive needs no client-side
fetch or GitHub token. All public records and real totals are present without JS;
scripts add filters, chart-to-filter shortcuts, native disclosure controls and
theme choice. Charts are static HTML/SVG generated from the public source, not
hidden behind a disclosure. GitHub's Moderate rows are grouped with Medium in
charts and filters; Info remains a separate label. Every public row is included.

Star badges initially show the archive snapshot (`~` means approximate; a dash
means unavailable). `stars.js` refreshes a repository's public star count as its
project approaches the viewport. It uses GitHub's unauthenticated repository
endpoint, two requests concurrently, a 24-hour browser cache, a five-second
timeout and one-hour retry backoff. Rate limits pause the queue; errors preserve
the cached/snapshot count. Activating the stars filter also queues hidden
projects so live metadata can update matches. No finding outcome or archive
total is changed by repository metadata. No GitHub token is exposed.

GitHub documents a 60-request/hour/IP anonymous REST limit:
https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
Counts use `stargazers_count` from GET /repos/{owner}/{repo}:
https://docs.github.com/en/rest/repos/repos#get-a-repository

The standalone GitHub Pages site links Luigi's name to his public GitHub
profile. The separately deployed copy under the personal site's `/argo/` uses
`../index.html` for that backlink. All project-local links and asset paths are
relative. Pushing `gh-pages` does not update the personal-site snapshot.

Check with `node verify.mjs` (Node 22+ and `CHROME_PATH` pointing to Chromium).
Run `node verify-research.mjs` as well; it exercises the explicit allow-list,
metadata/approval rules, stable canonical path, structured data, Atom output and
private-data rejection without publishing a real article.
`node verify-controls-stars.mjs` additionally checks keyboard/dropdown behaviour,
semantic colours, the full-width context panel and deterministic cache/rate-limit/
offline metadata fixtures. Tests block public API requests, so repeated local
checks do not spend visitors' or the developer's anonymous GitHub quota.
Design decisions and visual results are in DESIGN.md and REVIEW.md. GitHub Pages
deployment is a normal push to `gh-pages`; do not force-push for routine site
updates. Then refresh the personal-site repository as described in AGENTS.md.
