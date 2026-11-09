"""Configuration contracts shared by runner, CLI, HTTP and resume (no model calls)."""
from argo.config import PipelineConfig, pipeline_config_from_dict, pipeline_config_to_dict
import pytest


def test_old_config_keeps_explicit_key_auth_default():
    assert pipeline_config_from_dict({'runner': 'mistral-vibe'}).mistral_vibe_auth == 'key'


@pytest.mark.parametrize('mode', ['auto', 'login', '', None, ['stored']])
def test_invalid_vibe_auth_fails_during_configuration(mode):
    with pytest.raises(ValueError, match='mistral_vibe_auth must be key or stored'):
        PipelineConfig(mistral_vibe_auth=mode)


def test_stored_auth_rejects_explicit_vibe_key_without_echoing_it():
    with pytest.raises(ValueError, match='stored') as exc:
        PipelineConfig(mistral_vibe_auth='stored', mistral_vibe_api_key='SENTINEL_CONFIG_SECRET')
    assert 'SENTINEL_CONFIG_SECRET' not in str(exc.value)


def test_stored_auth_survives_resume_without_exposing_other_backend_key():
    cfg = PipelineConfig(runner='mistral-vibe', mistral_vibe_auth='stored',
                         mistral_api_key='SENTINEL_API_SECRET')
    raw = pipeline_config_to_dict(cfg)
    assert raw['mistral_vibe_auth'] == 'stored'
    assert raw['mistral_api_key'] == '<redacted>'
    resumed = pipeline_config_from_dict(raw)
    assert resumed.mistral_vibe_auth == 'stored' and resumed.mistral_api_key is None
    with pytest.raises(ValueError, match='key or stored'):
        resumed.with_overrides(mistral_vibe_auth='auto')


def test_smoke_never_relaxes_tighter_explicit_caps_or_auth():
    smoke = PipelineConfig(
        mistral_vibe_auth='stored', session_timeout_s=180, session_max_turns=5,
        budget_usd=0.5, session_max_cost_usd=0.1,
        stage_timeouts={'audit': 30, 'recon': 2400},
    ).for_smoke()
    assert smoke.session_timeout_s == 180
    assert smoke.timeout_for('audit') == 30
    assert smoke.timeout_for('recon') <= 180
    assert smoke.session_max_turns == 5
    assert smoke.budget_usd == 0.5
    assert smoke.session_max_cost_usd == 0.1
    assert smoke.mistral_vibe_auth == 'stored'


@pytest.mark.parametrize('turns, price', [(None, None), (0, 0), (-1, -1), (600, 5)])
def test_smoke_always_has_positive_bounded_session_caps(turns, price):
    smoke = PipelineConfig(session_max_turns=turns, session_max_cost_usd=price).for_smoke()
    assert smoke.session_max_turns == 60
    assert smoke.session_max_cost_usd == 0.75
    assert smoke.session_timeout_s == 600
    assert smoke.budget_usd == 2.0


def test_smoke_preserves_zero_run_budget_as_a_launch_stop():
    assert PipelineConfig(budget_usd=0).for_smoke().budget_usd == 0
