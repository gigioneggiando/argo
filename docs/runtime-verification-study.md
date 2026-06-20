# Study: safe, optional runtime verification

> Status: **R1 + R2 done** (validated live against Umbraco). Runtime verification is **opt-in**
> (`--runtime`, default off) and **best-effort** (graceful skip when it cannot provision a runnable
> instance). It never blocks a run and never weakens the static pipeline.

## 1. Value
Turn `needs_runtime_verification` findings (and re-test `confirmed` ones) into **HTTP-level
confirmed / refuted with a real PoC** — the class of evidence that separated the reference Umbraco
audit (5 live confirmations: `/backofficeHub/negotiate` → 200 anon; `?take=2147483647` past model
binding; `swagger.json` served to anon) from a pure-static tool. It catches guards that exist in
code but aren't wired at runtime, and it *raises precision* — a finding that won't reproduce live is
honestly downgraded.

## 2. The safety crux — why runtime does NOT break the core guardrail
Argo's hardest guardrail is **"no stage ever contacts, scans, or exercises a live in-scope host."**
Runtime verification preserves it, by construction:

> It never touches the program's real hosts. It **builds the open-source target from the
> already-cloned source into an ephemeral, network-sealed, local instance** and probes **only that
> loopback instance** — the same trust model a researcher uses (build the OSS app, test your own
> copy), and the same model [`verify.py`](architecture.md#remediation--verification-phase-6-opt-in)
> already uses for Docker builds (`--network=none`).

New explicit invariant: *probe targets are loopback-only; the sandbox has no egress; the real
in-scope / out-of-scope hosts are never resolved or contacted.*

## 3. Threat model — prevented structurally, not by prompt
| Risk | Structural prevention |
|---|---|
| Sandbox reaches the internet / the program's prod hosts | container runs **egress-blocked** (`--network=none`); probes run **inside** the container against `127.0.0.1`, so no host networking is needed at all |
| A probe aimed at a real host (typo / model error) | deterministic `assert_loopback_only(plan, scope)` — every target must be loopback; abort if any matches a scope host or resolves off-127.0.0.1 |
| DoS vs the local instance (violates `prohibited_techniques`) | `validate_probe_plan` caps request count, RPS, payload size, timeout; rejects fuzz/flood shapes |
| Model runs arbitrary shell | the model **never gets a shell or network** — it emits a constrained probe plan; a **fixed executor** runs the validated plan |
| Malicious target source executes locally | build+run **inside the sealed container, non-root, `--rm`**, no host mounts beyond the source copy + a result file, no egress |
| Persistent side effects | throwaway `copytree` + `--rm` container + ephemeral in-container DB — nothing survives |

## 4. Architecture — one sealed container does everything
```
orchestrator (host)                    sealed container (--network=none, --rm, non-root)
  isolated copy   ──mount ro──►  /src  ─► build ─► run app on 127.0.0.1:PORT (in-container)
  probe_plan.json ──mount────►  /work  ─► fixed probe-runner curls localhost per the plan
  results.json    ◄──mount────  /work  ◄─ writes {finding_id, request, status, observation}
```
The orchestrator only ever **reads a result file**; no port is exposed to the host. Reuses
`verify.py` (`_copy_repo`, Docker invocation, timeouts).

## 5. The LLM's constrained role: propose → validate → execute → interpret
1. **Propose** (`04_runtime_probe_prompt.md`) — per finding, a `runtime_probe_plan`: HTTP requests
   against `localhost:PORT` + an expected observation. No shell, no non-loopback hosts.
2. **Validate** (deterministic, `guardrails.py`) — loopback-only, safe method set, payload/rate/
   count/timeout caps. Reject → finding keeps `needs_runtime_verification`.
3. **Execute** (fixed in-container runner) — runs the validated requests, records status + body snippet.
4. **Interpret** (model, read-only) — returns `runtime: {confirmed|refuted|inconclusive, evidence}`,
   merged into the verdict (the `verify.py` `on_patched` pattern).

## 6. Pipeline integration
An **optional** `runtime` stage after `validate` (mirrors SCA's opt-out wiring), `--runtime`
(default off). Per kept finding with a probe plan: build-once → probe → attach a `runtime` evidence
block; `report.py` surfaces "✅ runtime-confirmed (HTTP PoC)"; `benchmark.py` folds in
`runtime_confirmed_rate` (like `re_audit_confirmed_rate`).

## 7. The real blocker is *provisioning*, not safety
Getting a complex app to actually run is the hard part (Umbraco = .NET 10 SDK + Node 22 + unattended
DB). A generic "boot any repo" is **not** feasible. Pluggable launcher, in priority order:
1. **User recipe** — `--runtime-image IMG` / `--runtime-run-cmd "..."` / a repo `Dockerfile` /
   `docker-compose.yml`. Most reliable for real apps.
2. **Auto-detect** simple stacks (single Flask/Express/FastAPI, static server).
3. **Graceful skip** — no runnable instance ⇒ the stage no-ops; findings keep their static verdict.

## 8. Decisions (current defaults)
1. **Provisioning:** user-recipe-first + graceful skip (reliable, honest) — not magical auto-boot.
2. **Docker:** required; skip with a clear message if absent.
3. **Probe scope:** read-only by default (GET/HEAD/negotiate, take-overflow); state-changing PoCs
   only behind an extra opt-in.

## 9. Phased plan
- **R1 — safe harness, no LLM:** sealed-container build+run+probe + `assert_loopback_only` +
  `validate_probe_plan` + a hand-written probe plan. ✅ **DONE** — reproduced the reference's
  `/server/status` + `/server/configuration` anonymous confirmations against a sealed Umbraco.
- **R2 — LLM probe plans + interpretation** ✅ **DONE** — `04_runtime_probe_prompt.md` (propose,
  offline, read-only repo) generates `runtime_probe_plan.json` from the validated findings (gated by
  the R1 validators); `05_runtime_interpret_prompt.md` (interpret) turns the observations into
  per-finding `runtime_confirmed/refuted/inconclusive` verdicts merged into `validated_findings.json`.
  A hand-written plan still overrides generation.
- **R3 — launcher auto-detection** (Dockerfile/compose/simple stacks) + recipe schema.
- **R4 — verdicts + report + benchmark** (`runtime_confirmed_rate`), docs/diagrams.

## 10. Files
`config.py` (runtime flags/caps) · `guardrails.py` (`assert_loopback_only`, `validate_probe_plan`) ·
`argo/runtime.py` (+ reuse `verify.py`) · `argo/prompts/04_runtime_probe_prompt.md` · `models.py`
(`RuntimeEvidence`) · `orchestrator.py` + `cli.py` (optional stage, `--runtime`, `argo runtime`) ·
`report.py`, `benchmark.py`, **`guardrails.md`** (mandatory safety section), both SVGs.
