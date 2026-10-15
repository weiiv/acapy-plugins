from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.wallet.jwt import dict_to_b64

from oid4vc.public_routes.status_list import get_status_list
from oid4vc.status_handler import StatusHandler


def _jwt(typ: str) -> str:
    return f"{dict_to_b64({'typ': typ, 'alg': 'ES256'})}.e30.c2ln"


@pytest.fixture
def handler(context: AdminRequestContext):
    handler = MagicMock(StatusHandler)
    context.injector.bind_instance(StatusHandler, handler)
    yield handler


def _request(context: AdminRequestContext, accept=None):
    request = MagicMock()
    request.__getitem__ = lambda _, k: {"context": context}[k]
    request.match_info = {"list_number": "1"}
    request.headers = {"Accept": accept} if accept else {}
    return request


@pytest.mark.asyncio
async def test_ietf_jwt_served_as_statuslist_jwt(context, handler):
    token = _jwt("statuslist+jwt")
    handler.get_status_list = AsyncMock(return_value=token)

    response = await get_status_list(_request(context))

    handler.get_status_list.assert_awaited_once_with(context, "1", accept=None)
    assert response.headers["Content-Type"] == "application/statuslist+jwt"
    assert response.body == token.encode()


@pytest.mark.asyncio
async def test_cwt_served_as_statuslist_cwt(context, handler):
    handler.get_status_list = AsyncMock(return_value=b"\xd2\x84")

    response = await get_status_list(
        _request(context, accept="application/statuslist+cwt")
    )

    handler.get_status_list.assert_awaited_once_with(
        context, "1", accept="application/statuslist+cwt"
    )
    assert response.headers["Content-Type"] == "application/statuslist+cwt"
    assert response.body == b"\xd2\x84"


@pytest.mark.asyncio
async def test_other_tokens_served_as_text(context, handler):
    token = _jwt("JWT")
    handler.get_status_list = AsyncMock(return_value=token)

    response = await get_status_list(_request(context))

    assert response.content_type == "text/plain"
    assert response.text == token


@pytest.mark.asyncio
async def test_status_handler_forwards_accept(context):
    status_handler = StatusHandler(context)
    status_handler.handler = MagicMock(get_status_list_token=AsyncMock(return_value="t"))

    assert await status_handler.get_status_list(context, "1", accept="a") == "t"
    status_handler.handler.get_status_list_token.assert_awaited_once_with(
        context, "1", accept="a"
    )
