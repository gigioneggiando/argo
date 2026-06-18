# Synthesis notes (fixture)

Split into two complementary audit prompts:
- **P1 — full-scope, architecture-led**: whole-system view, storage/rendering/config, injection sinks.
- **P2 — identity / authorization / API exposure**: authn/authz, IDOR/BOLA, endpoint exposure.

Deprioritized: `/legacy/` (out of scope) and `third_party/` (out of scope). Both are excluded
from scope and must not be reported against.

Top residual unknowns for a human to resolve:
1. Is `/api/*` gated by auth middleware / WAF in production? Not visible from source.
2. Is the SSRF allow-list enforced via deploy-time config? Affects exploitability.
