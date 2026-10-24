# Argo site revision, 24 October 2026

## Current direction: an approachable public findings dashboard

This supersedes the editorial split described in the historical notes below.
Luigi found that revision cold and too formal. His explicit preferences are
rounded panels, a distinct project identity, charts visible immediately, and
search on the entry page. Those preferences take priority over the page skill's
generic restrictions on repeated cards. Treat this as a real archive dashboard,
not a marketing page. App direction: true-black-flat, seed 294134855, keeping
Argo's established neutral dark/light palette, amber data and Fraunces/Inter.
Rounded 16–20px panels and the existing brand colours follow the user's brief.

The first desktop screen answers: what is Argo, what became public, and where
can I search? A compact, personal introduction leads into five source-derived
totals, a thin outcome ring, severity bars, project ranking and the search field.
Both index.html and findings.html include the complete archive; entering the
project no longer requires another page before using search. Existing public
findings URLs still work. Charts show the full archive while filter counts state
the matching subset. Chart labels filter by severity or project; no invented
dates, growth figures or vulnerability totals. Moderate and Info are real source
labels, included separately so every severity adds to 95.

The circular theme button shows a sun or crescent for its next action, updates
its accessible name and retains the chosen theme. No constant eye movement,
count-up or row entrances: motion is feedback on controls, with reduced-motion
support. No new images or pipeline/flow changes; research diagrams and wiki
architecture remain applicable. The parent site's Projects menu is unchanged.

## Historical editorial revision

The public project keeps its dark/light neutral palette, amber accent and eye
mark. It shares the personal site's Fraunces/Inter pair, 16px body, 1.65 leading,
20px mobile gutters, fluid desktop gutters and calm spacing. No stock imagery.

Inventory: Luigi's independent Argo project; code audits coordinated through
language models; human-reviewed reports; actual public upstream links; native
static HTML; published-only security advisories; an eye identity; self-hosted
fonts; dark/light choice; searchable severity/status/language/star metadata;
distinct merged/fixed/open/unpatched outcomes; public contribution routes.

Argument and copy deck:
- Overview: From code to evidence. Argo coordinates language models to audit
  source code. Each public finding links to an upstream PR or advisory.
- Proof: static totals derived from the public archive, with a direct path into
  the records. No count-up or new reliability/performance claim.
- Process: A finding is a starting point. Models propose, human review checks,
  upstream evidence records the outcome. The archive is not an exhaustive audit
  of all findings or a benchmark.
- Contribution: question a result, improve a prompt or report a missed bug;
  actual repository, wiki, contribution guide and discussion destinations.
- Findings: search the public record, filter it, and open the relevant project.
  Data is present in raw HTML. No private Fleece records are an input.

Page direction: type-only-statement, seed 20522412, keeping palette/type.
On this page, Argo's public evidence becomes a typographic field notebook and
a searchable archive. The eye remains a small identity mark; its constant gaze
and breathing, glow, count-up effects and row-by-row reveal are removed.
Short opening entrances remain on Overview only; reduced motion shows the final
state immediately. Findings is a reading/lookup screen and keeps its rows still.

The shared family navigation replaces the dealt isolated corner links because
the user explicitly wants projects connected to the personal site. The archive
uses flat native project disclosures and filter controls, not promotional cards.
No pipeline stage, research result or vulnerability verdict is changed.

The source snapshot has 26 actual project sections and 95 public rows, including
ten native div records with multiple evidence links. The old manual headline
counted 27 projects, 61 PRs and 73 resolved results. The complete public rows now
derive 66 distinct primary PR links, 24 advisory records, 83 resolved record rows
and seven distinct CVE identifiers. Grouped projects and record rows are counted
as such; this is not a count of distinct vulnerabilities or a new upstream audit.
The original was preserved in content/disclosures.html before the split. One
pre-existing broken antirez/ds4/pull/? placeholder now points to the already
linked elkaix/ds4 PR #1, verified merged through GitHub's API. Its title and outcome
remain unchanged. All other record links, severities, outcomes and notes remain.

Standalone deployment links back to Luigi's public GitHub profile until the
personal domain is live. The personal-site copy uses ../index.html instead,
with relative project-local links so /argo/ works under a future shared domain.
