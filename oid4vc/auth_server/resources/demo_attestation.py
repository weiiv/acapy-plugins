"""Demo script: end-to-end attestation flow.

Generates real ES256 keys, creates a wallet provider on the admin API,
issues a pre-auth code, exchanges it for a token with an attestation JWT,
and introspects the resulting access token.

Prerequisites:
  - Admin server running on localhost:9000
  - Tenant server running on localhost:9001
  - A seeded tenant + private_key_jwt client (run dev_seed.py first)

Usage:
  python resources/demo_attestation.py \
    --tenant-uid <TENANT_UID> \
    --client-id <CLIENT_ID> \
    --client-jwk-file <path/to/private_jwk.json>

Or use the built-in key generation (prints everything you need):
  python resources/demo_attestation.py --tenant-uid <TENANT_UID> --generate-all
"""

import argparse
import asyncio
import base64
import hashlib
import json
import time
from typing import Any

import httpx
from joserfc import jwk, jwt as jose_jwt

# ─── Configuration ───────────────────────────────────────────────────
ADMIN_URL = "http://localhost:9000"
TENANT_URL = "http://localhost:9001"
MANAGE_TOKEN = "admin-manage-auth-token"  # matches ADMIN_MANAGE_AUTH_TOKEN in .env.admin


def _gen_ec_key() -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate an ES256 key pair, returning (private_jwk, public_jwk)."""
    key = jwk.generate_key("EC", "P-256")
    private_jwk = key.as_dict(private=True)
    public_jwk = key.as_dict(private=False)
    return private_jwk, public_jwk


def _thumbprint(jwk: dict[str, Any]) -> str:
    """Compute RFC 7638 JWK thumbprint (base64url, no padding)."""
    ordered = {
        "crv": jwk["crv"],
        "kty": jwk["kty"],
        "x": jwk["x"],
        "y": jwk["y"],
    }
    canonical = json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode()
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def _sign_jwt(
    payload: dict[str, Any],
    private_jwk: dict[str, Any],
    header_extra: dict[str, Any] | None = None,
) -> str:
    """Sign a JWT with joserfc."""
    header = {"alg": "ES256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    key = jwk.import_key(private_jwk)
    token = jose_jwt.encode(header, payload, key)
    return token


def _sign_client_assertion(
    client_id: str,
    client_private_jwk: dict[str, Any],
    audience: str,
) -> str:
    """Create a client_assertion JWT for private_key_jwt auth."""
    now = int(time.time())
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 300,
    }
    kid = client_private_jwk.get("kid") or _thumbprint(client_private_jwk)
    return _sign_jwt(payload, client_private_jwk, header_extra={"kid": kid})


def _build_attestation_jwt(
    provider_private_jwk: dict[str, Any],
    provider_kid: str,
    issuer: str,
    subject: str,
    ttl: int = 300,
) -> str:
    """Build a client attestation JWT signed by the wallet provider."""
    now = int(time.time())
    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
    }

    header_extra = {
        "typ": "oauth-client-attestation+jwt",
        "kid": provider_kid,
    }
    return _sign_jwt(payload, provider_private_jwk, header_extra=header_extra)


# ─── API calls ───────────────────────────────────────────────────────


async def step1_register_wallet_provider(
    client: httpx.AsyncClient,
    provider_public_jwk: dict[str, Any],
    provider_kid: str,
    issuer: str,
) -> dict[str, Any]:
    """Step 1: Register the wallet provider on the admin allow list."""
    print("\n" + "=" * 60)
    print("STEP 1: Register wallet provider on admin")
    print("=" * 60)

    body = {
        "iss": issuer,
        "kid": provider_kid,
        "public_key": provider_public_jwk,
        "name": "Demo Wallet Provider",
        "active": True,
    }
    print(f"\nPOST {ADMIN_URL}/admin/wallet-providers")
    print(f"Body: {json.dumps(body, indent=2)}")

    resp = await client.post(
        f"{ADMIN_URL}/admin/wallet-providers",
        json=body,
        headers={"Authorization": f"Bearer {MANAGE_TOKEN}"},
    )
    print(f"\nResponse ({resp.status_code}):")
    result = resp.json()
    print(json.dumps(result, indent=2, default=str))

    if resp.status_code == 409:
        print("(Provider already exists, updating public key...)")
        # List providers to find the existing one, then PATCH its key
        list_resp = await client.get(
            f"{ADMIN_URL}/admin/wallet-providers",
            headers={"Authorization": f"Bearer {MANAGE_TOKEN}"},
        )
        if list_resp.status_code == 200:
            for p in list_resp.json():
                if p.get("iss") == issuer and p.get("kid") == provider_kid:
                    patch_resp = await client.patch(
                        f"{ADMIN_URL}/admin/wallet-providers/{p['id']}",
                        json={"public_key": provider_public_jwk, "active": True},
                        headers={"Authorization": f"Bearer {MANAGE_TOKEN}"},
                    )
                    result = patch_resp.json()
                    print(f"  Updated provider {p['id']}: {patch_resp.status_code}")
                    break
    elif resp.status_code != 201:
        raise RuntimeError(f"Failed to create wallet provider: {resp.status_code}")

    return result


async def step2_create_pre_auth_code(
    client: httpx.AsyncClient,
    tenant_uid: str,
    client_id: str,
    client_private_jwk: dict[str, Any],
) -> dict[str, Any]:
    """Step 2: Issue a pre-authorized code via the tenant grants endpoint."""
    print("\n" + "=" * 60)
    print("STEP 2: Create pre-authorized code")
    print("=" * 60)

    audience = f"{TENANT_URL}/tenants/{tenant_uid}/grants/pre-authorized-code"
    assertion = _sign_client_assertion(client_id, client_private_jwk, audience)

    body = {
        "subject_id": "demo-subject-001",
        "subject_metadata": {
            "given_name": "Demo",
            "family_name": "User",
            "email": "demo@example.com",
        },
        "tx_code": "1234",
        "authorization_details": [
            {
                "type": "openid_credential",
                "credential_configuration_id": "UniversityDegreeCredential",
            }
        ],
    }

    url = f"{TENANT_URL}/tenants/{tenant_uid}/grants/pre-authorized-code"
    print(f"\nPOST {url}")
    print(f"Body: {json.dumps(body, indent=2)}")
    print(f"Auth: private_key_jwt (client_id={client_id})")

    resp = await client.post(
        url,
        json=body,
        headers={
            "Authorization": f"Bearer {assertion}",
        },
    )
    print(f"\nResponse ({resp.status_code}):")
    result = resp.json()
    print(json.dumps(result, indent=2, default=str))

    if resp.status_code != 200:
        raise RuntimeError(f"Failed to create pre-auth code: {resp.status_code}")

    return result


async def step3_token_with_attestation(
    client: httpx.AsyncClient,
    tenant_uid: str,
    pre_auth_code: str,
    tx_code: str,
    attestation_jwt: str,
) -> dict[str, Any]:
    """Step 3: Exchange pre-auth code for tokens, with attestation."""
    print("\n" + "=" * 60)
    print("STEP 3: Token request with attestation")
    print("=" * 60)

    url = f"{TENANT_URL}/tenants/{tenant_uid}/token"
    form_data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": pre_auth_code,
        "tx_code": tx_code,
        "client_attestation": attestation_jwt,
    }

    print(f"\nPOST {url}")
    print(
        f"Form data: {json.dumps({k: v[:60] + '...' if len(str(v)) > 60 else v for k, v in form_data.items()}, indent=2)}"
    )

    resp = await client.post(
        url,
        data=form_data,
    )
    print(f"\nResponse ({resp.status_code}):")
    result = resp.json()
    print(json.dumps(result, indent=2, default=str))

    if resp.status_code != 200:
        raise RuntimeError(f"Token request failed: {resp.status_code}")

    return result


async def step4_introspect(
    client: httpx.AsyncClient,
    tenant_uid: str,
    access_token: str,
    client_id: str,
    client_private_jwk: dict[str, Any],
) -> dict[str, Any]:
    """Step 4: Introspect the access token."""
    print("\n" + "=" * 60)
    print("STEP 4: Token introspection")
    print("=" * 60)

    audience = f"{TENANT_URL}/tenants/{tenant_uid}/introspect"
    assertion = _sign_client_assertion(client_id, client_private_jwk, audience)

    url = f"{TENANT_URL}/tenants/{tenant_uid}/introspect"
    print(f"\nPOST {url}")
    print(f"token: {access_token[:60]}...")

    resp = await client.post(
        url,
        data={"token": access_token},
        headers={
            "Authorization": f"Bearer {assertion}",
        },
    )
    print(f"\nResponse ({resp.status_code}):")
    result = resp.json()
    print(json.dumps(result, indent=2, default=str))
    return result


# ─── Main ─────────────────────────────────────────────────────────────


async def run_demo(tenant_uid: str, client_id: str, client_private_jwk: dict[str, Any]):
    """Run the full attestation demo flow."""
    print("=" * 60)
    print("  ATTESTATION DEMO")
    print("=" * 60)
    print(f"  Admin:  {ADMIN_URL}")
    print(f"  Tenant: {TENANT_URL}")
    print(f"  Tenant UID: {tenant_uid}")
    print(f"  Client ID:  {client_id}")

    # Generate wallet provider keys (the "trusted provider" that signs attestations)
    provider_private_jwk, provider_public_jwk = _gen_ec_key()
    # Use the JWK's own kid (authlib auto-sets it from thumbprint)
    provider_kid = provider_public_jwk.get("kid") or _thumbprint(provider_public_jwk)
    provider_iss = "https://wallet-provider.example.com"

    print(f"\n  Provider ISS: {provider_iss}")
    print(f"  Provider KID: {provider_kid}")

    async with httpx.AsyncClient(timeout=30) as http:
        # Step 1: Register wallet provider
        await step1_register_wallet_provider(
            http, provider_public_jwk, provider_kid, provider_iss
        )

        # Step 2: Create pre-auth code
        grant = await step2_create_pre_auth_code(
            http, tenant_uid, client_id, client_private_jwk
        )
        pre_auth_code = grant["pre_authorized_code"]

        # Step 3: Build attestation JWT, exchange for tokens
        attestation_jwt = _build_attestation_jwt(
            provider_private_jwk=provider_private_jwk,
            provider_kid=provider_kid,
            issuer=provider_iss,
            subject=client_id,
        )

        print("\n--- Attestation JWT ---")
        print(f"  Header: {json.dumps(_decode_jwt_part(attestation_jwt, 0), indent=4)}")
        print(f"  Payload: {json.dumps(_decode_jwt_part(attestation_jwt, 1), indent=4)}")

        token_result = await step3_token_with_attestation(
            http, tenant_uid, pre_auth_code, "1234", attestation_jwt
        )

        # Step 4: Introspect
        access_token = token_result.get("access_token", "")
        if access_token:
            await step4_introspect(
                http, tenant_uid, access_token, client_id, client_private_jwk
            )
        else:
            print("\nNo access_token in response, skipping introspection.")

    print("\n" + "=" * 60)
    print("  DEMO COMPLETE")
    print("=" * 60)


def _decode_jwt_part(token: str, index: int) -> dict[str, Any]:
    """Decode a JWT header (0) or payload (1) for display."""
    part = token.split(".")[index]
    padded = part + "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


async def generate_all_and_run(tenant_uid: str):
    """Generate client keys, seed a client, then run the full demo."""
    print("Generating fresh client keys...")
    client_private_jwk, client_public_jwk = _gen_ec_key()
    kid = _thumbprint(client_public_jwk)
    client_public_jwk["kid"] = kid
    client_id = f"demo-att-{int(time.time()) % 100000}"

    print(f"\n  Generated client_id: {client_id}")
    print(f"  Client public JWK kid: {kid}")

    # Register the client on the tenant via admin
    async with httpx.AsyncClient(timeout=30) as http:
        # Create client via admin API
        client_body = {
            "client_id": client_id,
            "client_auth_method": "private_key_jwt",
            "client_auth_signing_alg": "ES256",
            "jwks": {"keys": [client_public_jwk]},
        }
        print("\nRegistering client via admin API...")
        resp = await http.post(
            f"{ADMIN_URL}/admin/tenants/{tenant_uid}/clients",
            json=client_body,
            headers={"Authorization": f"Bearer {MANAGE_TOKEN}"},
        )
        if resp.status_code not in (200, 201):
            print(f"  Failed ({resp.status_code}): {resp.text}")
            print("  Make sure the tenant exists. Run dev_seed.py first.")
            return
        print(f"  Client registered: {resp.json().get('client_id')}")

    await run_demo(tenant_uid, client_id, client_private_jwk)


def main():
    """Parse command line arguments and run the demo."""
    global ADMIN_URL, TENANT_URL

    parser = argparse.ArgumentParser(description="Demo attestation flow")
    parser.add_argument("--tenant-uid", required=True, help="Tenant UID")
    parser.add_argument("--client-id", help="Existing client_id (private_key_jwt)")
    parser.add_argument(
        "--client-jwk-file",
        help="Path to JSON file with the client's private JWK",
    )
    parser.add_argument(
        "--generate-all",
        action="store_true",
        help="Generate keys and client automatically",
    )
    parser.add_argument(
        "--admin-url",
        default=None,
        help=f"Admin server URL (default: {ADMIN_URL})",
    )
    parser.add_argument(
        "--tenant-url",
        default=None,
        help=f"Tenant server URL (default: {TENANT_URL})",
    )
    args = parser.parse_args()

    if args.admin_url:
        ADMIN_URL = args.admin_url
    if args.tenant_url:
        TENANT_URL = args.tenant_url

    if args.generate_all:
        asyncio.run(generate_all_and_run(args.tenant_uid))
    elif args.client_id and args.client_jwk_file:
        with open(args.client_jwk_file) as f:
            client_private_jwk = json.load(f)
        asyncio.run(run_demo(args.tenant_uid, args.client_id, client_private_jwk))
    else:
        parser.error("Provide --generate-all OR both --client-id and --client-jwk-file")


if __name__ == "__main__":
    main()
