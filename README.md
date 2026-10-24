# Argo public site

This is the `gh-pages` worktree of `gigioneggiando/argo`.

- `index.html`: project introduction, totals, visible charts and searchable archive.
- `findings.html`: static, searchable public archive.
- `content/disclosures.html`: the authoritative public record source.
- `build.mjs`: shared shell, counts, project disclosures and page generation.
- `style.css` / `script.js`: shared presentation and progressive enhancement.

Edit the source chapters and run `node build.mjs`. Do not hand-edit generated
HTML or headline totals. Totals derive from the public rows; one row can be a
backport, a public issue or an advisory, so records are not distinct vulnerabilities.

Every row must already have a public upstream URL. An unpublished/private
advisory must remain outside this site. Preserve distinctions between merged,
fixed upstream, open, issue and advisory; published can still mean unpatched.
Private Fleece records are not a build input. No client-side fetch or GitHub
token is needed. All public records and real totals are present without JS;
scripts add filters, chart-to-filter shortcuts, native disclosure controls and
theme choice. Charts are static HTML/SVG generated from the public source, not
hidden behind a disclosure. Severity labels such as Moderate and Info remain
distinct and are included in chart totals and filters.

The standalone site links Luigi's name to his public GitHub profile. The copy
under the personal site's `/argo/` uses `../index.html` for that backlink. All
project-local links and asset paths are relative, supporting both GitHub Pages
and a future `gigioneggiando.com/argo/` deployment. The custom domain is not
configured by this presentation change.

Check with `node verify.mjs` (Node 22+ and `CHROME_PATH` pointing to Chromium).
Design decisions and visual results are in DESIGN.md and REVIEW.md. Deployment
is a normal push to `gh-pages`; do not force-push for routine site updates.
