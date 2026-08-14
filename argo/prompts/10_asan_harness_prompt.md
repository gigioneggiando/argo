# ASAN PROOF-OF-CONCEPT HARNESS PROMPT

> Pipeline stage: **ASan PoC generation**, opt-in, run AFTER a finding has already survived
> validation (and corroboration/deep-verify if enabled) — you are not re-judging whether this is a
> real bug, you are turning an already-confirmed memory-safety finding into a REAL crash trace, the
> single most credibility-boosting artifact a disclosure can carry. Run once per finding, fresh
> isolated context, full read-only repo access, no turn/excerpt budget pressure.

---

## INJECTED CONTEXT

FINDING TO REPRODUCE (already confirmed; do not re-litigate whether it is real):
```json
{{FINDING_JSON}}
```

CODE EXCERPTS (a starting point only — the full repo is mounted read-only; open the actual current
file, its headers, and anything it `#include`s that you need):
```
{{CODE_EXCERPTS}}
```

REPOSITORY ROOT (read-only, use Read/Grep/Glob freely): {{REPO_PATH}}

PROHIBITED TECHNIQUES (hard limits — never violate these even while constructing a PoC):
{{PROHIBITED_TECHNIQUES}}

---

## YOUR JOB

Write a **minimal, single translation unit** C/C++ harness that reproduces this finding under
AddressSanitizer, and a short notes file explaining exactly what you did and why you believe it is
faithful. Nothing else compiles or runs this code for you to check first — write it carefully.

## HARD CONSTRAINTS (read before writing anything)

1. **One file, one `#include` of the real vulnerable source — never reimplement the vulnerable
   function.** `harness.c` (or `.cpp` if the target is C++) must `#include` the actual target
   source/header file(s) that contain the vulnerable function directly (e.g.
   `#include "../src/parser.c"` at a relative path resolvable from where the harness is compiled,
   or copy just the minimal struct/prototype declarations needed to call it — but the FUNCTION BODY
   itself must be the real one, compiled from the real file, never hand-copied or paraphrased).
2. **No project build system.** Do not assume `cmake`/`make`/`configure`/`autoreconf` are run for
   you — none of that happens. The harness must compile with a single flat command:
   `clang -fsanitize=address,undefined -g -O0 harness.c -o poc` (or the `.cpp` / `clang++` variant).
   If the vulnerable function has too many transitive dependencies to isolate this way (needs a
   whole subsystem initialized, a network stack, a full parser state machine you cannot construct
   standalone), **say so explicitly in NOTES.md and do not force it** — an honest "could not isolate"
   is far more valuable than a harness that doesn't actually exercise the real bug.
3. **The malicious input is embedded in the harness, not supplied at runtime.** Construct the exact
   input described in the finding's `exploit_scenario` as a `static` buffer/struct literal inside
   `main()` (or equivalent), then call the real vulnerable function with it directly. The compiled
   `poc` binary must reproduce the crash with **no command-line arguments, no stdin, no files, no
   network** — it runs once, standalone, and either crashes under ASan or it doesn't.
4. **No network, no filesystem writes outside the current directory, no destructive behavior.**
   This runs in a sandboxed, network-disabled container, but the harness itself must not attempt
   anything beyond calling the target function — no `system()`, no `exec*()`, no spawning
   subprocesses, nothing outside straight-line C/C++ calling into the real vulnerable code.
5. **Do not patch, weaken, or "fix" anything.** You are reproducing the bug exactly as it exists in
   the pinned source, not demonstrating a fix.

## WHAT TO DO

1. Open the actual current file(s) at the cited `affected` locations. Confirm the function
   signature, the exact struct/type definitions it needs, and every header it transitively requires
   for just THAT function to compile standalone (not the whole project).
2. Decide: can this function be isolated into one translation unit? If the function has few enough
   dependencies (typical for a parser/decoder/buffer-handling routine — usually the actual case for
   memory-safety bugs), write the harness. If it genuinely cannot be isolated (deeply coupled to
   global state, a whole VM/interpreter, a live socket/event loop with no straightforward standalone
   entry point), stop and write that assessment in NOTES.md instead of forcing a broken harness.
3. Write `harness.c`/`harness.cpp`: `#include` the real source, declare/construct the malicious
   input from the finding's `exploit_scenario`, call the real function, `return 0` if it somehow
   doesn't crash (ASan/the sanitizer runtime handles crash reporting — you do not need to catch
   signals or print anything about the crash yourself).
4. Write `NOTES.md`: which real file(s) you pulled the vulnerable code from, what you needed to
   stub/declare vs. what is the real unmodified function body, why you believe the embedded input
   faithfully matches the finding's described trigger, and any caveat about fidelity (e.g. "this
   reproduces the same code path but the real-world trigger would arrive over the network parser
   rather than this synthetic buffer — the memory-unsafe operation itself is identical").

## REQUIRED DELIVERABLES

- `harness.c` (or `harness.cpp`) — the single-file, single-translation-unit PoC described above. If
  you determined the finding cannot be isolated this way, write a `harness.c` containing only a
  comment explaining why, so the deliverable still exists but is clearly a non-attempt, not a
  silently broken one.
- `NOTES.md` — the audit trail described in step 4 above.
