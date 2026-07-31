"""mso_mdoc trust anchor admin routes.

Provides CRUD endpoints for TrustAnchorRecord: X.509 CA certificates
trusted for mDoc verification.
"""

import logging

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    querystring_schema,
    request_schema,
    response_schema,
)
from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from marshmallow import fields

from .trust_anchor import TrustAnchorRecord, TrustAnchorRecordSchema

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helper schemas
# ---------------------------------------------------------------------------


class TrustAnchorIdMatchSchema(OpenAPISchema):
    """Path parameter schema for trust anchor ID."""

    trust_anchor_id = fields.Str(
        required=True,
        metadata={"description": "Trust anchor record identifier"},
    )


class TrustAnchorQuerySchema(OpenAPISchema):
    """Query string schema for listing trust anchors."""

    doctype = fields.Str(
        required=False,
        metadata={"description": "Filter by doctype", "example": "org.iso.18013.5.1.mDL"},
    )
    purpose = fields.Str(
        required=False,
        metadata={"description": "Filter by purpose: 'iaca' or 'reader_auth'"},
    )


class TrustAnchorListSchema(OpenAPISchema):
    """Response schema for trust anchor list."""

    results = fields.List(fields.Nested(TrustAnchorRecordSchema()))


# ---------------------------------------------------------------------------
# Trust anchor routes
# ---------------------------------------------------------------------------


@docs(tags=["mso-mdoc"], summary="Create a new mDoc trust anchor")
@request_schema(TrustAnchorRecordSchema())
@response_schema(TrustAnchorRecordSchema(), 200)
@tenant_authentication
async def create_trust_anchor(request: web.Request):
    """Create and persist a new TrustAnchorRecord."""
    context: AdminRequestContext = request["context"]
    body = await request.json()

    record = TrustAnchorRecord(
        doctype=body.get("doctype"),
        purpose=body.get("purpose", "iaca"),
        label=body.get("label"),
        certificate_pem=body.get("certificate_pem"),
    )

    try:
        async with context.profile.session() as session:
            await record.save(session, reason="Create trust anchor")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(tags=["mso-mdoc"], summary="List mDoc trust anchors")
@querystring_schema(TrustAnchorQuerySchema())
@response_schema(TrustAnchorListSchema(), 200)
@tenant_authentication
async def list_trust_anchors(request: web.Request):
    """Return all TrustAnchorRecords, optionally filtered."""
    context: AdminRequestContext = request["context"]

    tag_filter = {}
    if "doctype" in request.rel_url.query:
        tag_filter["doctype"] = request.rel_url.query["doctype"]
    if "purpose" in request.rel_url.query:
        tag_filter["purpose"] = request.rel_url.query["purpose"]

    try:
        async with context.profile.session() as session:
            records = await TrustAnchorRecord.query(
                session, tag_filter=tag_filter if tag_filter else None
            )
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({"results": [r.serialize() for r in records]})


@docs(tags=["mso-mdoc"], summary="Get a single mDoc trust anchor by ID")
@match_info_schema(TrustAnchorIdMatchSchema())
@response_schema(TrustAnchorRecordSchema(), 200)
@tenant_authentication
async def get_trust_anchor(request: web.Request):
    """Retrieve a single TrustAnchorRecord by ID."""
    context: AdminRequestContext = request["context"]
    trust_anchor_id = request.match_info["trust_anchor_id"]

    try:
        async with context.profile.session() as session:
            record = await TrustAnchorRecord.retrieve_by_id(session, trust_anchor_id)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response(record.serialize())


@docs(tags=["mso-mdoc"], summary="Delete an mDoc trust anchor")
@match_info_schema(TrustAnchorIdMatchSchema())
@tenant_authentication
async def delete_trust_anchor(request: web.Request):
    """Delete a TrustAnchorRecord by ID."""
    context: AdminRequestContext = request["context"]
    trust_anchor_id = request.match_info["trust_anchor_id"]

    try:
        async with context.profile.session() as session:
            record = await TrustAnchorRecord.retrieve_by_id(session, trust_anchor_id)
            await record.delete_record(session)
    except StorageNotFoundError as err:
        raise web.HTTPNotFound(reason=err.roll_up) from err
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    return web.json_response({})


async def register(app: web.Application):
    """Register mso_mdoc trust anchor routes."""
    app.add_routes(
        [
            web.post("/mso-mdoc/trust-anchors", create_trust_anchor),
            web.get("/mso-mdoc/trust-anchors", list_trust_anchors),
            web.get("/mso-mdoc/trust-anchors/{trust_anchor_id}", get_trust_anchor),
            web.delete("/mso-mdoc/trust-anchors/{trust_anchor_id}", delete_trust_anchor),
        ]
    )
