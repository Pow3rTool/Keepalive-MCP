"""Authorization-claim checks around the Entra token validation boundary."""
import types

import jwt
import pytest

import server


CLIENT = server.ALLOWED_CLIENTS[0]


def _claims(**overrides):
    claims = {
        "iss": f"https://login.microsoftonline.com/{server.TENANT}/v2.0",
        "tid": server.TENANT,
        "scp": server.REQUIRED_SCOPE,
        "azp": CLIENT,
        "oid": "operator-oid",
        "preferred_username": "operator@example.com",
        "roles": ["Keepalive.Read"],
        "exp": 4_000_000_000,
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def decoded_token(monkeypatch):
    signing_key = types.SimpleNamespace(key=object())
    monkeypatch.setattr(
        server,
        "_jwks",
        lambda: types.SimpleNamespace(
            get_signing_key_from_jwt=lambda _token: signing_key
        ),
    )

    def install(claims):
        monkeypatch.setattr(jwt, "decode", lambda *_args, **_kwargs: claims)

    return install


def test_delegated_identity_accepts_only_the_expected_claims(decoded_token):
    decoded_token(_claims())
    assert server._identity("token") == (
        "operator-oid",
        "operator@example.com",
        ["keepalive.read"],
    )


@pytest.mark.parametrize(
    "claims",
    [
        _claims(iss="https://issuer.invalid/"),
        _claims(tid="wrong-tenant"),
        _claims(scp="wrong.scope"),
        _claims(azp="wrong-client"),
    ],
)
def test_delegated_identity_fails_closed_on_claim_mismatch(
        claims, decoded_token):
    decoded_token(claims)
    assert server._identity("token") is None


def test_management_identity_accepts_app_only_token(decoded_token):
    claims = _claims(
        roles=["Keepalive.Admin"],
        preferred_username=None,
    )
    claims.pop("scp")
    decoded_token(claims)
    oid, upn, roles = server._identity_mgmt("token")
    assert oid == "operator-oid"
    assert upn == f"app:{CLIENT}"
    assert roles == ["keepalive.admin"]


def test_management_identity_rejects_wrong_delegated_scope(decoded_token):
    decoded_token(_claims(scp="wrong.scope", roles=["Keepalive.Admin"]))
    assert server._identity_mgmt("token") is None


def test_request_admin_gate_distinguishes_unauthorized_and_forbidden(monkeypatch):
    request = types.SimpleNamespace(headers={"authorization": "Bearer token"})

    monkeypatch.setattr(server, "_identity_mgmt", lambda _token: None)
    identity, response = server._require_admin_req(request)
    assert identity is None
    assert response.status_code == 401

    monkeypatch.setattr(
        server,
        "_identity_mgmt",
        lambda _token: ("oid", "upn", ["keepalive.read"]),
    )
    identity, response = server._require_admin_req(request)
    assert identity is None
    assert response.status_code == 403

    monkeypatch.setattr(
        server,
        "_identity_mgmt",
        lambda _token: ("oid", "upn", ["keepalive.admin"]),
    )
    identity, response = server._require_admin_req(request)
    assert identity == ("oid", "upn")
    assert response is None
