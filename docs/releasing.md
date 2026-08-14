# Releasing

Argo follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — `MAJOR.MINOR.PATCH`.

While the version stays `0.y.z` ("initial development", per the spec), anything may change between
minor versions without a major bump: the CLI flags, config fields, JSON schemas, and HTTP API are
not yet considered stable. Reaching `1.0.0` will be a deliberate signal that they are — not a
default to reach for once the feature list looks big enough.

## What bumps what

- **PATCH** (`0.2.0` → `0.2.1`) — a bug fix, no CLI/config/schema/API change.
- **MINOR** (`0.2.0` → `0.3.0`) — a new capability, flag, stage, or endpoint that's additive;
  existing usage keeps working unchanged. Most releases land here.
- **A breaking change** (renaming/removing a CLI flag, an incompatible JSON schema change, a
  breaking HTTP API change) — normally MAJOR, but while pre-1.0 SemVer allows folding this into a
  MINOR bump instead (the public surface isn't stable yet). Call it out clearly under its own
  `### Changed` / `### Removed` heading in the changelog either way, so it's easy to scan for.

## Cutting a release

1. Update the version in the two places it's declared by hand (no build-time templating, kept in
   sync manually — small enough surface that automating this isn't worth it yet):
   - `pyproject.toml` → `[project] version`
   - `argo/__init__.py` → `__version__`
2. Move `CHANGELOG.md`'s `[Unreleased]` section into a new `## [X.Y.Z] - YYYY-MM-DD` section, with
   real content (don't ship an empty release).
3. Commit: `git commit -m "release: vX.Y.Z"`, through the normal PR flow like any other change.
4. After merge, tag the merge commit on `main` and push the tag:
   `git tag vX.Y.Z && git push origin vX.Y.Z`.
5. Publish a GitHub Release from the tag, reusing that same changelog section as the release notes:
   `gh release create vX.Y.Z --title vX.Y.Z --notes-file path/to/notes.md` (paste the section's body
   into a scratch file first — trying to slice it out of `CHANGELOG.md` with a one-liner isn't worth
   the fragility for something this infrequent).

There's no PyPI publish yet — `pip install` today means `pip install -e .` from a checkout (see the
top-level [README.md](../README.md)). An automated publish-on-tag workflow is a reasonable next
step once that's actually wanted; it isn't part of this process yet, so don't build it preemptively.

## Why the version number isn't cosmetic

Every report Argo produces carries `v{__version__}` in its footer (`argo/branding.py`) — it's
already live in real disclosure reports sent to real maintainers. Bump it because something
actually changed, not on a schedule, and not to make the project look more mature than the CLI/API
surface actually is.
