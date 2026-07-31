"""kmslite admin routes (mounted on ACA-Py's admin API)."""

import json
import logging
from typing import Any, Dict

from aiohttp import web
from aiohttp_apispec import (
    docs,
    match_info_schema,
    request_schema,
    response_schema,
)
from aries_askar import Key, KeyAlg
from cryptography.hazmat.primitives import serialization
from marshmallow import Schema, fields, validate

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_info import DIDInfo
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.did_parameters_validation import DIDParametersValidation
from acapy_agent.wallet.error import WalletError, WalletNotFoundError
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.signer_registry import SignerRegistry
from acapy_agent.wallet.util import b58_to_bytes

from .config import KmsLiteConfig
from .x509 import assert_cert_matches_verkey, build_csr, verkey_to_public_key

LOGGER = logging.getLogger(__name__)

# ACA-Py KeyType.key_type -> aries-askar KeyAlg (for public-only insert_key).
_KEYALG_BY_KEY_TYPE_NAME = {"p256": KeyAlg.P256}


class _CreateDidOptions(OpenAPISchema):
    """`options` block for POST /kmslite/did/create."""

    did = fields.Str(
        required=False,
        metadata={
            "description": "DID (required for web/webvh; omit for key/peer).",
            "example": "did:web:issuer.example.com",
        },
    )
    key_ref = fields.Str(
        required=True,
        metadata={
            "description": "Backend key identifier (PKCS#11 CKA_LABEL).",
            "example": "issuer-p256-2026-01",
        },
    )


class CreateKmsDidRequestSchema(OpenAPISchema):
    """Request body for POST /kmslite/did/create."""

    method = fields.Str(required=True, metadata={"example": "web"})
    key_type = fields.Str(
        required=True,
        validate=validate.OneOf(list(_KEYALG_BY_KEY_TYPE_NAME)),
        metadata={"example": "p256"},
    )
    options = fields.Nested(_CreateDidOptions, required=True)


class DIDInfoResponseSchema(OpenAPISchema):
    """DID create response."""

    did = fields.Str()
    verkey = fields.Str()
    method = fields.Str()
    key_type = fields.Str()
    metadata = fields.Dict()


class _DidMatchInfoSchema(OpenAPISchema):
    """Path-param schema: /kmslite/did/{did}/..."""

    did = fields.Str(required=True, metadata={"description": "DID"})


class _CsrSubjectSchema(Schema):
    """Subject fields for a CSR."""

    country = fields.Str(required=False)
    state = fields.Str(required=False)
    locality = fields.Str(required=False)
    organization = fields.Str(required=False)
    organizational_unit = fields.Str(required=False)
    cn = fields.Str(required=False)
    common_name = fields.Str(required=False)


class CsrRequestSchema(OpenAPISchema):
    """Request body for POST /kmslite/did/{did}/csr."""

    subject = fields.Nested(_CsrSubjectSchema, required=True)


class CsrResponseSchema(OpenAPISchema):
    """CSR response."""

    csr_pem = fields.Str()


class PublicKeyResponseSchema(OpenAPISchema):
    """Public-key response."""

    public_key_pem = fields.Str()


class CertificateRequestSchema(OpenAPISchema):
    """Request body for POST /kmslite/did/{did}/certificate."""

    cert_pem = fields.Str(required=True)


class CertificateResponseSchema(OpenAPISchema):
    """Certificate response."""

    cert_pem = fields.Str()


def _get_config(context: AdminRequestContext) -> KmsLiteConfig:
    cfg = KmsLiteConfig.from_settings(context.profile.settings)
    if cfg is None:
        raise web.HTTPServiceUnavailable(
            reason="kmslite: plugin not configured; external-signer routes unavailable"
        )
    return cfg


def _keyalg_for(key_type_name: str) -> KeyAlg:
    try:
        return _KEYALG_BY_KEY_TYPE_NAME[key_type_name]
    except KeyError:
        raise WalletError(
            f"unsupported key_type {key_type_name!r} "
            f"(supported: {list(_KEYALG_BY_KEY_TYPE_NAME)})"
        )


async def _get_local_did(wallet: BaseWallet, did: str) -> DIDInfo:
    try:
        return await wallet.get_local_did(did)
    except WalletNotFoundError as err:
        raise web.HTTPNotFound(reason=str(err)) from err


async def _fetch_did_info(context: AdminRequestContext, did: str) -> DIDInfo:
    async with context.profile.session() as session:
        return await _get_local_did(session.inject(BaseWallet), did)


@docs(tags=["kmslite"], summary="Create an external-signer-backed DID")
@request_schema(CreateKmsDidRequestSchema())
@response_schema(DIDInfoResponseSchema(), 200)
@tenant_authentication
async def create_kms_did(request: web.BaseRequest):
    context: AdminRequestContext = request["context"]
    cfg = _get_config(context)

    body: Dict[str, Any] = await request.json()
    method = body["method"]
    key_type_name = body["key_type"]
    options = body.get("options") or {}
    key_ref = options.get("key_ref")
    if not key_ref:
        raise web.HTTPBadRequest(reason="options.key_ref is required")

    key_type = context.inject(KeyTypes).from_key_type(key_type_name)
    if key_type is None:
        raise web.HTTPBadRequest(reason=f"Unknown key_type {key_type_name!r}")

    did_methods: DIDMethods = context.inject(DIDMethods)
    did_method = did_methods.from_method(method)
    if did_method is None:
        raise web.HTTPBadRequest(reason=f"Unknown DID method {method!r}")

    signer = context.inject(SignerRegistry).get(cfg.provider)
    if signer is None:
        raise web.HTTPServiceUnavailable(
            reason=f"No signer registered under provider {cfg.provider!r}"
        )

    try:
        verkey: str = await signer.generate_keypair(key_ref, key_type)
        did = DIDParametersValidation(did_methods).validate_or_derive_did(
            did_method, key_type, b58_to_bytes(verkey), options.get("did")
        )
    except WalletError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err
    if not did:
        raise web.HTTPBadRequest(
            reason=f"cannot resolve a DID for method {method!r}"
        )

    metadata = {"signer": cfg.provider, "key_ref": key_ref}
    try:
        askar_key = Key.from_public_bytes(
            _keyalg_for(key_type_name), b58_to_bytes(verkey)
        )
        async with context.profile.session() as session:
            await session.handle.insert_key(
                verkey, askar_key, metadata=json.dumps(metadata)
            )
            wallet = session.inject(BaseWallet)
            did_info = await wallet.store_did(
                DIDInfo(
                    did=did,
                    verkey=verkey,
                    metadata=metadata,
                    method=did_method,
                    key_type=key_type,
                )
            )
    except WalletError as err:
        raise web.HTTPBadRequest(reason=str(err)) from err

    return web.json_response(
        {
            "did": did_info.did,
            "verkey": did_info.verkey,
            "method": did_info.method.method_name,
            "key_type": did_info.key_type.key_type,
            "metadata": did_info.metadata,
        }
    )


@docs(tags=["kmslite"], summary="Export the DID's public key as PEM")
@match_info_schema(_DidMatchInfoSchema())
@response_schema(PublicKeyResponseSchema(), 200)
@tenant_authentication
async def get_kms_did_public_key(request: web.BaseRequest):
    context: AdminRequestContext = request["context"]
    did_info = await _fetch_did_info(context, request.match_info["did"])
    pub = verkey_to_public_key(did_info.verkey, did_info.key_type)
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return web.json_response({"public_key_pem": pem})


@docs(tags=["kmslite"], summary="Build a signed CSR for the DID's key")
@match_info_schema(_DidMatchInfoSchema())
@request_schema(CsrRequestSchema())
@response_schema(CsrResponseSchema(), 200)
@tenant_authentication
async def create_kms_did_csr(request: web.BaseRequest):
    context: AdminRequestContext = request["context"]
    subject = (await request.json()).get("subject") or {}
    if not subject:
        raise web.HTTPBadRequest(reason="subject is required")

    async with context.profile.session() as session:
        wallet = session.inject(BaseWallet)
        did_info = await _get_local_did(wallet, request.match_info["did"])
        try:
            csr_pem = await build_csr(
                wallet, did_info.verkey, did_info.key_type, subject
            )
        except WalletError as err:
            raise web.HTTPBadRequest(reason=str(err)) from err

    return web.json_response({"csr_pem": csr_pem.decode()})


@docs(tags=["kmslite"], summary="Attach an X.509 certificate to the DID")
@match_info_schema(_DidMatchInfoSchema())
@request_schema(CertificateRequestSchema())
@response_schema(CertificateResponseSchema(), 200)
@tenant_authentication
async def bind_kms_did_certificate(request: web.BaseRequest):
    context: AdminRequestContext = request["context"]
    cert_pem_str = (await request.json()).get("cert_pem")
    if not cert_pem_str:
        raise web.HTTPBadRequest(reason="cert_pem is required")

    did = request.match_info["did"]
    async with context.profile.session() as session:
        wallet = session.inject(BaseWallet)
        did_info = await _get_local_did(wallet, did)
        try:
            assert_cert_matches_verkey(
                cert_pem_str.encode(), did_info.verkey, did_info.key_type
            )
        except WalletError as err:
            raise web.HTTPBadRequest(reason=str(err)) from err
        await wallet.replace_local_did_metadata(
            did, {**(did_info.metadata or {}), "x509_certificate_pem": cert_pem_str}
        )

    return web.json_response({"cert_pem": cert_pem_str})


@docs(tags=["kmslite"], summary="Retrieve the DID's stored X.509 certificate")
@match_info_schema(_DidMatchInfoSchema())
@response_schema(CertificateResponseSchema(), 200)
@tenant_authentication
async def get_kms_did_certificate(request: web.BaseRequest):
    context: AdminRequestContext = request["context"]
    did = request.match_info["did"]
    did_info = await _fetch_did_info(context, did)
    cert = (did_info.metadata or {}).get("x509_certificate_pem")
    if not cert:
        raise web.HTTPNotFound(reason=f"No certificate bound to DID {did}")
    return web.json_response({"cert_pem": cert})


async def register(app: web.Application) -> None:
    app.add_routes(
        [
            web.post("/kmslite/did/create", create_kms_did),
            web.get(
                "/kmslite/did/{did}/public-key",
                get_kms_did_public_key,
                allow_head=False,
            ),
            web.post("/kmslite/did/{did}/csr", create_kms_did_csr),
            web.post(
                "/kmslite/did/{did}/certificate", bind_kms_did_certificate
            ),
            web.get(
                "/kmslite/did/{did}/certificate",
                get_kms_did_certificate,
                allow_head=False,
            ),
        ]
    )
