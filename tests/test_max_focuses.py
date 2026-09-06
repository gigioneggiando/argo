"""`--max-focuses` — holding the audited surface constant across targets.

Recon decides how many focus areas a repository is split into, and across 108 real runs it chose
anywhere from 1 to 7 (mode 3). That makes a raw finding count non-comparable between targets: a
repository audited on five focuses is not measured on the same surface as one audited on two, so a
difference in counts is partly a property of how recon happened to decompose it.

`max_focuses` existed as a config field but was reachable only through `--smoke` (which pins it to
1). These tests cover the flag that exposes it, and the two properties that make the cap usable as
a study control rather than a convenience:

* **Content-blind.** Focuses are kept in slug order, decided before any of them runs. Which focus
  survives cannot depend on what any focus found.
* **Loud.** The skipped focuses are named in the log. A cap that silently shrank the audit would be
  indistinguishable from the coverage loss the retry work exists to prevent.
"""

import pytest
import typer

from argo import cli
from argo.orchestrator import do_audit, do_ingest, do_recon

from conftest import BRIEF, REPO


def _prepare(env, **cfg):
    ctx = env(**cfg)
    do_ingest(ctx, BRIEF, str(REPO))
    do_recon(ctx)
    return ctx


def _planned(ctx):
    return sorted(p.stem for p in ctx.prompts_out_dir.glob("audit_*.md"))


def _produced(ctx):
    return sorted(p.stem.replace(".findings", "") for p in ctx.findings_dir.glob("audit_*.json"))


def test_cap_truncates_to_the_first_n_focuses_in_slug_order(env):
    ctx = _prepare(env, max_focuses=1)
    planned = _planned(ctx)
    assert len(planned) > 1, "fixture must plan more than one focus for this test to mean anything"

    do_audit(ctx)

    produced = _produced(ctx)
    assert len(produced) == 1
    # slug order, fixed before any focus runs -- not "whichever finished first"
    assert produced == planned[:1]


def test_cap_above_the_planned_count_is_a_no_op(env):
    ctx = _prepare(env, max_focuses=99)
    do_audit(ctx)
    assert _produced(ctx) == _planned(ctx)


def test_no_cap_audits_every_planned_focus(env):
    ctx = _prepare(env)
    assert ctx.config.max_focuses is None
    do_audit(ctx)
    assert _produced(ctx) == _planned(ctx)


def test_truncation_names_the_skipped_focuses(env, capsys):
    ctx = _prepare(env, max_focuses=1)
    planned = _planned(ctx)
    do_audit(ctx)

    err = capsys.readouterr().err
    assert "max_focuses=1" in err
    for skipped in planned[1:]:
        assert skipped in err


def test_cli_passes_the_flag_through_to_the_config(tmp_path):
    cfg = cli._build_config("mock", None, False, None, 1, tmp_path, "happy", max_focuses=3)
    assert cfg.max_focuses == 3


def test_cli_default_leaves_the_cap_unset(tmp_path):
    cfg = cli._build_config("mock", None, False, None, 1, tmp_path, "happy")
    assert cfg.max_focuses is None


@pytest.mark.parametrize("bad", [0, -1])
def test_cli_rejects_a_cap_below_one(tmp_path, bad):
    """A cap of 0 would audit nothing and still exit 0 -- exactly the silent-degradation shape the
    coverage checks exist to catch. Reject it at parse time instead."""
    with pytest.raises(typer.BadParameter):
        cli._build_config("mock", None, False, None, 1, tmp_path, "happy", max_focuses=bad)
