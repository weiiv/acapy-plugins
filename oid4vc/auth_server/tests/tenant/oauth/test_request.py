import time

import pytest
from authlib.oauth2.rfc9449.errors import InvalidDPopProofError
from starlette.requests import Request

from tenant.oauth.integration.request import to_oauth2_request
from tenant.services import dpop_service
from tests.tenant.services.test_dpop_service import _TOKEN_URL, _proof_request


def _starlette_request(headers: list[tuple[bytes, bytes]]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "server": ("as.example.com", 443),
            "path": "/tenants/t1/token",
            "query_string": b"",
            "headers": headers,
        }
    )


@pytest.mark.asyncio
async def test_repeated_headers_are_combined_not_dropped():
    request = _starlette_request([(b"dpop", b"proof-a"), (b"dpop", b"proof-b")])

    oauth2_req = await to_oauth2_request(request)

    assert oauth2_req.headers["dpop"] == "proof-a, proof-b"


@pytest.mark.asyncio
async def test_two_dpop_headers_are_rejected(monkeypatch):
    """RFC 9449 §4.3 check 1: at most one DPoP header field."""
    monkeypatch.setattr(dpop_service.settings, "DPOP_NONCE_SECRET", "")
    monkeypatch.setattr(dpop_service, "_validator", None)
    proof = _proof_request(iat=int(time.time())).headers["dpop"].encode()
    request = _starlette_request([(b"dpop", proof), (b"dpop", proof)])

    oauth2_req = await to_oauth2_request(request)

    assert str(oauth2_req.uri) == _TOKEN_URL
    with pytest.raises(InvalidDPopProofError):
        await dpop_service.validate_dpop_proof(oauth2_req, db=None)
