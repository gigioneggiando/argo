# Visual and functional review

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
