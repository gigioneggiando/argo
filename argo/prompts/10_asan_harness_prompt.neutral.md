# ASAN REGRESSION TEST HARNESS PROMPT (neutral-register variant)

> Pipeline stage: **ASan PoC generation**, opt-in, run AFTER a finding has already survived
> validation (and corroboration/deep-verify if enabled) — you are not re-judging whether the report
> is correct, you are writing a small regression test that checks whether the memory-safety
> contract described in the report actually holds in the current code, using AddressSanitizer as
> the instrumented test oracle. Run once per finding, fresh isolated context, full read-only repo
> access, no turn/excerpt budget pressure.

---

## INJECTED CONTEXT

REPORT TO TURN INTO A REGRESSION TEST (already confirmed by earlier review stages; you are not
re-litigating whether it holds — you are checking it mechanically):
```json
{{FINDING_JSON}}
```

CODE EXCERPTS (a starting point only — the full repo is mounted read-only; open the actual current
file, its headers, and anything it `#include`s that you need):
```
{{CODE_EXCERPTS}}
```

REPOSITORY ROOT (read-only, use Read/Grep/Glob freely): {{REPO_PATH}}

CONSTRAINTS (hard limits — never violate these even while constructing the test):
{{PROHIBITED_TECHNIQUES}}

---

## YOUR JOB

Write a **minimal, single translation unit** C/C++ regression test that checks the documented
memory-safety contract for the function under test, run under AddressSanitizer instrumentation,
plus a short notes file explaining exactly what you did and why you believe it is a faithful
check. Nothing else compiles or runs this code for you first — write it carefully.

## HARD CONSTRAINTS (read before writing anything)

1. **One file, one `#include` of the real source under test — never reimplement the function.**
   `harness.c` (or `.cpp` if the target is C++) must `#include` the actual target source/header
   file(s) that contain the function directly (e.g. `#include "../src/parser.c"` at a relative
   path resolvable from where the test is compiled, or declare just the minimal struct/prototype
   needed to call it — but the FUNCTION BODY itself must be the real one, compiled from the real
   file, never hand-copied or paraphrased).
2. **No project build system.** Do not assume `cmake`/`make`/`configure`/`autoreconf` are run for
   you — none of that happens. The test must compile with a single flat command:
   `clang -fsanitize=address,undefined -g -O0 harness.c -o poc` (or the `.cpp` / `clang++`
   variant). If the function under test has too many transitive dependencies to isolate this way
   (needs a whole subsystem initialized, a network stack, a full parser state machine you cannot
   construct standalone), **say so explicitly in NOTES.md and do not force it** — an honest "could
   not isolate" is far more valuable than a test that doesn't actually exercise the real code path.
3. **The boundary-condition input is embedded in the test, not supplied at runtime.** Construct the
   exact input described in the report's `exploit_scenario` field as a `static` buffer/struct
   literal inside `main()` (or equivalent), then call the function under test with it directly. The
   compiled `poc` binary must run the check with **no command-line arguments, no stdin, no files,
   no network** — it runs once, standalone, and either the sanitizer flags something or it doesn't.
4. **No network, no filesystem writes outside the current directory, no destructive behavior.**
   This runs in a sandboxed, network-disabled container, but the test itself must not attempt
   anything beyond calling the function under test — no `system()`, no `exec*()`, no spawning
   subprocesses, nothing outside straight-line C/C++ calling into the real code.
5. **Do not patch, weaken, or otherwise modify the code under test.** You are checking the contract
   exactly as it stands in the pinned source, not demonstrating or applying a fix.

## WHAT TO DO

1. Open the actual current file(s) at the cited `affected` locations. Confirm the function
   signature, the exact struct/type definitions it needs, and every header it transitively requires
   for just THAT function to compile standalone (not the whole project).
2. Decide: can this function be isolated into one translation unit? If it has few enough
   dependencies (typical for a parser/decoder/buffer-handling routine), write the test. If it
   genuinely cannot be isolated (deeply coupled to global state, a whole VM/interpreter, a live
   socket/event loop with no straightforward standalone entry point), stop and write that
   assessment in NOTES.md instead of forcing a broken test.
3. Write `harness.c`/`harness.cpp`: `#include` the real source, declare/construct the
   boundary-condition input from the report's `exploit_scenario`, call the real function, `return
   0` if the sanitizer doesn't flag anything (the sanitizer runtime handles its own reporting — you
   do not need to catch signals or print anything about it yourself).
4. Write `NOTES.md`: which real file(s) you pulled the code under test from, what you needed to
   stub/declare vs. what is the real unmodified function body, why you believe the embedded input
   faithfully matches the report's described trigger, and any caveat about fidelity (e.g. "this
   exercises the same code path but the real-world input would arrive over the network parser
   rather than this synthetic buffer — the underlying memory-safety operation is identical").

## REQUIRED DELIVERABLES

- `harness.c` (or `harness.cpp`) — the single-file, single-translation-unit regression test
  described above. If you determined the function cannot be isolated this way, write a `harness.c`
  containing only a comment explaining why, so the deliverable still exists but is clearly a
  non-attempt, not a silently broken one.
- `NOTES.md` — the audit trail described in step 4 above.
