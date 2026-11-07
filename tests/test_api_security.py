"""Local HTTP API hardening: access token, no CORS, loopback Host only, run-id containment, no
HTTP-chosen build command, CSP on the UI, and model text escaped in REPORT.md. Mock runner, zero
tokens, everything in-process."""

from __future__ import annotations

from fastapi.testclient import TestClient

from server.app import create_app
from test_api import TEST_TOKEN, _client, _start, _wait

EVIL = {"Origin": "https://evil.example"}


def _bare(app, host="127.0.0.1:8000"):
    return TestClient(app, base_url=f"http://{host}")


def test_api_requires_the_token(tmp_path):
    app, client = _client(tmp_path)
    bare = _bare(app)
    assert bare.get("/runs").status_code == 401
    assert bare.get("/runs", headers={"X-Argo-Token": "wrong"}).status_code == 401
    assert bare.get("/health").status_code == 200                 # liveness stays public
    assert bare.get("/app/").status_code == 200                   # static UI shell (no data)
    assert client.get("/runs").status_code == 200                 # header works


def test_token_link_sets_a_strict_cookie(tmp_path):
    app, _ = _client(tmp_path)
    bare = _bare(app)
    r = bare.get(f"/?token={TEST_TOKEN}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/app/"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert bare.get("/runs").status_code == 200                   # cookie now carried
    assert _bare(app).get("/?token=nope", follow_redirects=False).status_code == 401


def test_no_cors_for_foreign_origins(tmp_path):
    _app, client = _client(tmp_path)
    pre = client.options("/runs", headers={**EVIL, "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in pre.headers
    r = client.get("/runs", headers=EVIL)
    assert "access-control-allow-origin" not in r.headers


def test_foreign_host_header_is_rejected(tmp_path):
    app, _ = _client(tmp_path)
    for host in ("evil.example", "evil.example:8000", "192.168.1.5:8000"):
        r = _bare(app, host).get("/runs", headers={"X-Argo-Token": TEST_TOKEN})
        assert r.status_code == 403, host
    assert _bare(app, "localhost:8000").get(
        "/runs", headers={"X-Argo-Token": TEST_TOKEN}).status_code == 200
    extra = create_app(app.state.config, token="t", allowed_hosts={"myhost.lan"})
    assert _bare(extra, "myhost.lan:8000").get("/runs", headers={"X-Argo-Token": "t"}).status_code == 200


def test_run_id_cannot_escape_runs_dir(tmp_path):
    _app, client = _client(tmp_path)
    (tmp_path / "brief.txt").write_text("PARENT-DIR SECRET", encoding="utf-8")   # runs_dir's parent
    for rid in ("%2E%2E", "..", "%2E", "..%5C..%5Cx", "C:%5Cx", "a%2F..%2F.."):
        r = client.get(f"/runs/{rid}/artifacts/brief")
        assert r.status_code == 404, rid
        assert "PARENT-DIR SECRET" not in r.text


def test_fix_request_cannot_choose_a_build_command(tmp_path):
    _app, client = _client(tmp_path)
    run_id = _start(client)
    assert _wait(client, run_id)["state"] == "completed"
    marker = tmp_path / "pwned"
    for extra in ({"build_cmd": f"touch {marker}"}, {"docker": "evil/image"}):
        r = client.post(f"/runs/{run_id}/fixes", json={"verify": True, **extra})
        assert r.status_code == 422, extra
    assert not marker.exists()


def test_ui_is_served_with_a_csp(tmp_path):
    _app, client = _client(tmp_path)
    r = client.get("/app/")
    csp = r.headers.get("content-security-policy", "")
    assert "script-src 'self'" in csp and "object-src 'none'" in csp
    assert "<script>" not in r.text                               # no inline script to allow
    assert 'src="vendor/purify.min.js"' in r.text


def test_report_escapes_model_html(tmp_path):
    from argo.stages.report import _escape_tree
    f = {"id": "X-1", "title": '<img src=x onerror="alert(1)">', "affected": ["a/<b>.py:1"],
         "validation": {"rationale": "<script>x</script> -> ok"}}
    e = _escape_tree(f)
    assert e["title"].startswith("&lt;img") and "<" not in e["title"]
    assert e["validation"]["rationale"] == "&lt;script>x&lt;/script> -> ok"
    assert e["affected"] == ["a/<b>.py:1"] and e["id"] == "X-1"   # identifiers/paths untouched
    assert f["title"].startswith("<img")                          # input not mutated
