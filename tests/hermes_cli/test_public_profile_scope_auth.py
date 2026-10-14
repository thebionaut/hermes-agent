"""OBS-VULN-005 / OBS-VULN-006.

* Public ``/api/status`` and ``/api/model/info`` must not enter a profile scope for an anonymous caller.
* ``is_safe_next_path`` must judge the value the way a browser reads it (backslash, tab/CR/LF, %5c).
"""
from types import SimpleNamespace

import pytest

from hermes_cli.dashboard_auth.request_utils import is_safe_next_path


@pytest.mark.parametrize("path", [
    "/\\evil.com", "/\\\\evil.com", "/\t/evil.com", "/\n/evil.com", "/\r/evil.com",
    "/%5cevil.com", "/%5Cevil.com", "/%2Fevil.com", "//evil.com", "https://evil.com", "evil.com", "",
])
def test_unsafe_next_values_are_rejected(path):
    assert is_safe_next_path(path) is False


@pytest.mark.parametrize("path", ["/", "/chat", "/sessions/abc?tab=2", "/config#models"])
def test_ordinary_same_origin_targets_still_pass(path):
    assert is_safe_next_path(path) is True


@pytest.fixture
def client(monkeypatch, _isolate_hermes_home):
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi/starlette not installed")
    from hermes_cli.web_server import app
    return TestClient(app)


def test_helper_loopback_mode_requires_the_session_token(client):
    from hermes_cli.web_server import (_SESSION_HEADER_NAME, _SESSION_TOKEN, _request_is_authenticated, app)

    def fake(headers):
        return SimpleNamespace(headers=headers, query_params={}, state=SimpleNamespace(),
                               app=app, url=SimpleNamespace(path="/api/status"))

    assert _request_is_authenticated(fake({})) is False
    assert _request_is_authenticated(fake({_SESSION_HEADER_NAME: "wrong"})) is False
    assert _request_is_authenticated(fake({_SESSION_HEADER_NAME: _SESSION_TOKEN})) is True


def test_helper_gated_mode_verifies_credentials_on_public_paths(monkeypatch):
    """Public paths skip the gate's verification, so request.state.session is None even for a
    logged-in caller; the helper must verify the credentials itself, and fail closed."""
    from hermes_cli import web_server
    from hermes_cli.dashboard_auth import middleware

    gated_app = SimpleNamespace(state=SimpleNamespace(auth_required=True))
    req = SimpleNamespace(headers={}, state=SimpleNamespace(), app=gated_app)

    monkeypatch.setattr(middleware, "resolve_optional_session", lambda r: None)
    assert web_server._request_is_authenticated(req) is False
    monkeypatch.setattr(middleware, "resolve_optional_session", lambda r: object())
    assert web_server._request_is_authenticated(req) is True


def test_status_ignores_profile_for_anonymous_callers(client):
    """An unknown profile 404s inside profile scope (existence oracle). Anonymous => never gets there."""
    anon = client.get("/api/status", params={"profile": "no-such-profile-xyz"})
    assert anon.status_code == 200, anon.text

    from hermes_cli.web_server import _SESSION_HEADER_NAME, _SESSION_TOKEN
    authed = client.get("/api/status", params={"profile": "no-such-profile-xyz"},
                        headers={_SESSION_HEADER_NAME: _SESSION_TOKEN})
    assert authed.status_code == 404


def test_model_info_ignores_profile_for_anonymous_callers(client):
    anon = client.get("/api/model/info", params={"profile": "no-such-profile-xyz"})
    assert anon.status_code != 404, anon.text
