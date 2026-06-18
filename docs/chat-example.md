# Chat / false-negative interrogation — worked example 💬

The chat layer (Phase 3, the **Chat** results tab) turns a one-shot report into a conversation that
attacks the dominant bug-bounty failure mode — **false negatives**. It is seeded with the run's full
context (scope, repo profile, **synthesis notes** = what was deprioritized and why, validated
findings) plus **read-only** repo access, so it can re-investigate the code and answer with evidence.

This page is a **real, unedited transcript** (lightly trimmed for length) from a validation run on a
tiny synthetic vulnerable repo, audited with Claude. It demonstrates the three behaviours that make
the layer useful for a research dataset: **grounded explanation**, **false-positive self-correction**,
and **honest handling of false negatives**. Three turns cost **$0.40** total (Sonnet).

The demo repo had three planted bugs (SQLi in `search.py`, SSRF in `fetch.py`, IDOR in `orders.py`),
one deliberately **safe** parameterized query (`safe.py`), and **no XSS**.

## 1. Grounded explanation ✅

> **Q:** Explain ARCH-001 (the SQL injection) concretely: the tainted data flow from input to sink,
> and a one-line exploit. Cite file:line.

> **A (excerpt):** `q` arrives from the caller, is concatenated into a string literal at
> `search.py:5`, and hits the `sqlite3` execution sink at `search.py:6` with no sanitization …
> exploit `q = "' UNION SELECT id,email,password_hash,NULL FROM users--"` … *"read-only within the
> single `sqlite3.execute()` call (stacked writes via `;` are blocked by the stdlib's single-statement
> executor), but UNION-based read of every table … is fully achievable."*

Exact source→sink with line numbers, a working exploit, **and** a correct technical nuance about
sqlite3's single-statement executor — grounded in the actual code, not generic.

## 2. False-positive self-correction ✅

> **Q:** Your ARCH-001 finding lists `app/safe.py:4` in its affected list. Is `safe.py` actually
> vulnerable, or is it safe?

> **A (excerpt):** *"`app/safe.py:4` is **not vulnerable**. It is the safe reference implementation …
> the `?` is a `sqlite3` bind parameter … never interpolated into the SQL text … It was listed as a
> **cross-reference**, not a vulnerable site … It should not be treated as a finding."*

The audit had over-included `safe.py` in the finding's `affected` list (a minor false positive). The
chat **caught and corrected it**, explained why the parameterized query is safe, and cited the
synthesis notes that already excluded it.

## 3. Honest false negatives ✅

> **Q:** Did you report any XSS? If not — genuinely none, or did you miss it? Answer honestly.

> **A (excerpt):** *"No XSS was reported, and the honest answer is: **it could not be confirmed or
> ruled out** — not 'genuinely absent.' … there is **no** `render_template`, `Markup`, Jinja …
> anywhere … the rendering layer … is **completely absent** from the provided repo … If the router
> renders results into `render_template_string(user_data)` → reflected/stored XSS and SSTI would both
> be present … It was correctly flagged as a **residual unknown** … deprioritized rather than
> fabricated."*

This is the key behaviour for a study: the model does **not** falsely reassure ("no XSS, all clear")
**nor** fabricate. It frames XSS as a **residual unknown** (the rendering layer isn't in scope of the
source), lays out the conditional risk, and defers to a human — exactly how `needs_runtime_verification`
and the synthesis notes' residual-unknowns are meant to surface gaps honestly in the data.

## Limits (kept honest)

- **Advisory only.** A genuine miss surfaced in chat does **not** auto-become a candidate finding that
  re-runs validation and flows into the registry — that feedback loop is future work (see
  [roadmap.md](roadmap.md) Phase 3 _Later_).
- **No token streaming**; one model call per turn (history re-sent each turn, capped).
- **Quality tracks the model.** Strong models (the transcript above is Sonnet) answer well; small
  local models less so — which is exactly what the benchmark measures across backends.
