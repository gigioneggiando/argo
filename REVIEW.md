# Visual and functional review

## Current welcoming dashboard revision, 24 October 2026

ROUND 1
Seen in one second: a rounded, compact Argo dashboard with actual public results.
Idea (one sentence): Argo's public disclosure trail becomes an approachable,
searchable overview rather than an editorial front door.
Live thing: search and filtering on home; chart labels take visitors into results.
Layout words by section: intro=compact welcome / totals=rounded figures /
charts=outcome ring and two bar lists / archive=search and grouped evidence /
about=readable context and contribution links.
Scores: design 7.5 · usability 7.8 · creativity 7.1 · content 8.2 → overall 7.58.
Caps applied: intermediate covered-text failure, overall capped at 6.0.
Top three problems (most visible first), each with screenshot and fix:
1. The initial desktop-fold showed both theme glyphs. SVG icons now use real
   hidden attributes, and browser checks assert exactly one visible sun/moon.
2. The initial severity chart omitted two uncommon labels. The public source
   includes Moderate and Info; both now appear as distinct chart/filter values.
   Build and browser checks require the complete 95-record sum.
3. The phone inspector measured hidden headings inside the closed About panel
   under its summary. Context now stays in a normal readable section below the
   archive; no content is concealed to satisfy the inspector.

ROUND 2 — final
Seen in one second: introduction, five totals, all three charts and search on
the first 1440×900 desktop screen. Rounded panels retain Argo's own identity.
Idea (one sentence): follow the public work from a quick overview to its evidence.
Live thing: all archive filters, chart shortcuts, disclosures, theme choice.
Layout words by section: welcome / totals / ring-and-bars / searchable archive /
context / links back to Luigi.
Scores: design 7.7 · usability 8.4 · creativity 7.3 · content 8.5 → overall 7.92.
Self-assessment, not an external rating. App-screen rules apply; a public archive
has no need for stock pictures or promotional scroll animations.
Caps applied: none; final inspections report 0 FAIL, 3 WARN on both pages.
Top three remaining notes, with screenshots and reasons:
1. desktop-fold: two shorter chart panels retain 50–56px below their content to
   align the three comparisons; equal panel edges make the overview easier to scan.
2. mobile-fold: the 30px two-line greeting is deliberately more welcoming than a
   dense admin title and remains smaller than the former editorial hero.
3. page sheets: the full 26-project archive continues below the fold. All three
   requested charts and desktop search appear first; native groups keep the
   complete evidence available rather than replacing it with sample records.

Final browser verification passes: unchanged 95 titles/statuses/severities and
all primary/auxiliary evidence links, text search, empty/reset, native reset,
status/language/star intersections, all-project controls, deep links, full chart
totals, chart shortcuts, round theme control, icon change, persistence, first-fold
visibility, mobile width and no-JS charts plus complete records on both pages.
Opened all 18 final inspector images in welcoming-home-final and
welcoming-findings-final (desktop/tablet/mobile folds and page sheets).
No private registry inputs, new security verdicts or upstream-state claims.
The CLI, pipeline, research diagrams and wiki architecture are unchanged.

## Historical editorial revision

Before: one page combined presentation, always-visible chart/filter chrome and
the complete archive. Inspector: 6 FAIL / 4 WARN at 1440/768/390; the title took
3 desktop lines and 4 phone lines, with tiny uppercase labels, a glow and mixed
card radii. The full page measured 16.8 desktop screens.

ROUND 1
Seen in one second: a large serif statement in Argo's own dark/amber palette,
with the personal identity and a direct route into public evidence.
Idea: Argo's public records become an editorial introduction and a searchable
field notebook, connected to Luigi's larger personal site.
Live thing: archive search, severity/status/language/star filters, native project
disclosures, distribution summaries and theme choice.
Layout: overview=type / totals=plain figures / proof=project names /
process=wide paragraph beside a title / contribution=links /
archive=filters and native grouped records.
Scores: design 7.4, usability 7.3, creativity 7.2, content 8; overall 7.39.
Cap: intermediate failures, overall capped at 6.
Three observations and fixes:
1. Snapshot labels above numeric values were detected as kickers. Values now lead
   their labels; the small real archive-summary fragment is marked data-ui.
2. The original source has ten div records with auxiliary evidence links, not
   only anchor records. A complete element parser preserves them and valid li
   wrappers keep filtering reliable. A browser comparison checks all 95 records.
3. Whole-page data-ui was too broad. Findings uses app-screen rules directly;
   no page-level wrapper is treated as a cropped interface.

ROUND 2 — archive
Seen: readable search controls and the first public record; other projects can
be opened when wanted. Empty/filter/reset/theme states work.
The native grouped archive is now about 6 desktop screens in its default state.
No row fades, observer-based hiding, count-up or constant eye animation remain.
An observed singular label was changed from 1 records to 1 record.

ROUND 3 — final
Seen in one second: Argo remains its own technical project, with the same reading
scale and spatial rhythm as the personal site.
Idea: a visitor moves from Luigi's work into a project, then into its actual
upstream evidence, without an unrelated navigation system or a huge front page.
Live thing: search/filter intersections, direct project fragments, native open/
close controls, distribution bars and a persistent dark/light theme.
Layout: typographic overview / public project sentence / process note /
contribution / compact close; separate searchable archive.
Scores: design 7.7, usability 8.2, creativity 7.3, content 8.4; overall 7.84.
Self-assessment, not an external rating. The intentional type-only overview uses
the documented no-photography allowance; no unrelated decorative assets added.

Final QA: Overview 0 FAIL / 2 WARN; Findings 0 FAIL / 3 WARN, all at 1440, 768 and
390. Warnings: responsive type variation/no footage for the editorial page;
archive title scale, grouped records beyond the fold and charts behind a native
disclosure for the archive. Colours on actual severity/status data remain clear.
The title's 48px desktop / 36px phone size deliberately connects to the family
site while leaving search and filters on the first screen.

Screenshots opened: all six overview-final sheets and all eight findings-final
sheets (fold and page sheets for desktop/tablet/mobile), plus the light-theme
mobile screenshot. Parent-site menu screenshots were also reviewed on desktop
and phone. No placeholder photography or generated screenshots were used.

Functional verification: all original 95 titles, severities and outcomes match
the pre-change browser snapshot. Every primary and auxiliary evidence link is
preserved except one repaired /pull/? placeholder, which now uses the already
linked, API-verified merged fork PR. Search, no-results reset, native form reset,
filter intersections, expand/collapse, deep links, distribution totals, theme
persistence, mobile width and the complete no-JS archive pass.

Counts derive from the same public records: 26 grouped projects, 66 distinct
primary public PR URLs, 24 advisory rows, 83 resolved record rows, 7 CVE IDs.
These are not unique-vulnerability counts or new benchmark measurements.
The main Argo tool, pipeline diagrams and wiki functionality are unaffected.
