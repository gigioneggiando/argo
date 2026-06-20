# Umbraco-CMS runtime-verification recipe

A working launcher recipe for Argo's **opt-in, sandboxed runtime verification**
(see [../../../runtime-verification-study.md](../../../runtime-verification-study.md)). It builds
Umbraco-CMS from source into a self-contained image, then Argo runs it in an **egress-blocked,
loopback-only** container (`--network=none`) and probes only that local instance.

This recipe was validated live: it reproduced the reference audit's anonymous confirmations
**`GET /server/status` → 200** and **`GET /server/configuration` → 200** (the latter leaking
`allowPasswordReset` / `allowLocalLogin` to an anonymous caller).

## 1. Build the image (network on)

```bash
# <repo> = a clone of https://github.com/umbraco/Umbraco-CMS (Argo's runs/<id>/repo works)
docker build -f Dockerfile -t argo-umbraco-rt <repo>
```

The `Dockerfile` documents the three non-obvious build blockers (shallow-clone gitversioning, the
two npm targets, and the SQLite `Foreground` keyword). Build is ~10–15 min; the SPA is skipped
(`UmbracoBuild=true`) because the probes hit the API surface.

## 2. Run Argo's runtime stage (sealed)

The image is self-contained (the app is built into `/src`), so pass `--no-mount-source`. Umbraco's
first boot runs an unattended SQLite install (~1–2 min), so raise the boot timeout.

```bash
# R1 (hand-written plan): drop probe_plan.example.json at runs/<id>/runtime_probe_plan.json first
python -m argo.cli runtime --run <id> \
  --runtime-image argo-umbraco-rt \
  --runtime-run-cmd "cd src/Umbraco.Web.UI && dotnet bin/Release/net10.0/Umbraco.Web.UI.dll --urls http://127.0.0.1:8080" \
  --runtime-port 8080 --runtime-boot-timeout 300 --no-mount-source
```

For **R2** (the LLM generates the probe plan from the validated findings), just omit the
hand-written `runtime_probe_plan.json` — the stage proposes one, the loopback/anti-DoS validators
gate it, and an interpret pass writes per-finding verdicts.

## Notes

- The probes here are anonymous GETs. Authenticated findings (most authz bugs) need a session the
  R1/R2 read-only flow does not set up — they correctly come back `runtime_inconclusive`.
- To exercise the headless **Delivery API** (e.g. an unbounded-`take` probe), add
  `Umbraco__CMS__DeliveryApi__Enabled=true` to the image `ENV` and seed content — a fresh
  unattended install has none.
