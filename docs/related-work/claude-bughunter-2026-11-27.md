# Claude-BugHunter: fit for Argo (2026-11-27)

Read-only review of `elementalsouls/Claude-BugHunter` at commit `9b7fc8dcf599a48f5f986971fdc62146a7f5a431`. This is a decision note, not evidence that its techniques improve Argo.

## Assessment

The repository has a real CLI, deterministic scope checks, resumable engagement state, tests, a report-pattern curation pipeline, and a closure ledger. Its main job is authorized live web/enterprise testing. Argo's core job is source-first OSS auditing; its existing audit checklists, variant census, adversarial validation, evidence contract, benchmark harness and opt-in live gate cover much of the analogous workflow.

The public ablation in `eval/BASELINE.md` tests only three OWASP Juice Shop challenges. Skills-on and skills-off each solve 3/3; skills-on costs more and takes more turns. The authors correctly call this a ceiling-effect harness check, not proof that the skills improve bug finding. Redacted engagement summaries and pattern counts cannot establish general detection quality. `cbh triage` is a keyword/regex screen of finding prose: its `PASS` can be satisfied by words that mention impact, scope and proof without verifying them. Do not use it as Argo's final evidence gate.

## Useful ideas and order

1. **First: safe benchmark controls.** Argo's roadmap already calls for private `kind: "safe"` cases alongside its 19 positive corpus cases. Add a small, independently reviewed set of source-static safe/near-miss controls and measure false-positive rate with pinned model, commit and budget. This is a prerequisite for claiming that any imported pattern helps.
2. **Then: cited pattern intake pilot.** Borrow the *process* from `research/reports/`: public primary report -> human verification -> generic failure mode -> source entry/sink/precondition -> negative control -> benchmark case or narrowly scoped audit lens. Pilot a few underrepresented classes, such as injection and path handling, and retain only changes that improve held-out recall without worsening precision or cost. Do not import all 681 patterns or copy skill prose wholesale.
3. **Later: report coverage caveats.** Claude-BugHunter's `engine/closure.py` derives "not tested" caveats from explicit item verdicts. Argo already has focus state, mandatory coverage prompts and variant logs. Check whether its report makes incomplete focus coverage and blocked proof obligations visible; if not, render a small deterministic caveat section from existing state rather than adding another agent stage.
4. **Only for a separate live-testing track:** evaluate its fail-closed scope importer/allowlist concepts against Argo's existing explicit live authorization gate. Do not move network reconnaissance into the default source audit.

Avoid cross-target "negative memory" skip rules, headline counts as a quality metric, and automatic report approval from lexical triage. The next concrete action is the safe-control corpus; pattern intake is an experiment after that baseline exists.

Sources: [repository](https://github.com/elementalsouls/Claude-BugHunter/tree/9b7fc8dcf599a48f5f986971fdc62146a7f5a431), [evaluation](https://github.com/elementalsouls/Claude-BugHunter/blob/9b7fc8dcf599a48f5f986971fdc62146a7f5a431/eval/BASELINE.md), [report intake](https://github.com/elementalsouls/Claude-BugHunter/blob/9b7fc8dcf599a48f5f986971fdc62146a7f5a431/research/reports/README.md), [closure ledger](https://github.com/elementalsouls/Claude-BugHunter/blob/9b7fc8dcf599a48f5f986971fdc62146a7f5a431/engine/closure.py), [CLI triage](https://github.com/elementalsouls/Claude-BugHunter/blob/9b7fc8dcf599a48f5f986971fdc62146a7f5a431/cbh/cli.py), [Argo roadmap](../roadmap.md).
