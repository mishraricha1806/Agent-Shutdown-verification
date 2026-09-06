from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass


class AuthenticationError(RuntimeError):
    pass


class AuthorizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Principal:
    tenant_id: str
    actor: str
    roles: frozenset[str]


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class TokenAuthenticator:
    """Small signed service-token implementation for the dependency-free starter."""

    def __init__(self, secret: bytes) -> None:
        if len(secret) < 32:
            raise ValueError("ASV_AUTH_SECRET must contain at least 32 bytes")
        self.secret = secret

    def issue(self, principal: Principal, *, ttl_seconds: int = 3600) -> str:
        now = int(time.time())
        payload = {
            "tenant_id": principal.tenant_id,
            "actor": principal.actor,
            "roles": sorted(principal.roles),
            "iat": now,
            "exp": now + ttl_seconds,
        }
        encoded = _encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        signature = hmac.new(self.secret, f"v1.{encoded}".encode(), hashlib.sha256).hexdigest()
        return f"v1.{encoded}.{signature}"

    def authenticate(self, authorization: str) -> Principal:
        if not authorization.startswith("Bearer "):
            raise AuthenticationError("Bearer token is required")
        token = authorization.removeprefix("Bearer ").strip()
        try:
            version, encoded, supplied_signature = token.split(".", 2)
            if version != "v1":
                raise ValueError("unsupported token version")
            expected = hmac.new(self.secret, f"{version}.{encoded}".encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, supplied_signature):
                raise ValueError("signature mismatch")
            payload = json.loads(_decode(encoded))
            if int(payload["exp"]) <= int(time.time()):
                raise ValueError("token expired")
            if not payload.get("tenant_id") or not payload.get("actor"):
                raise ValueError("token identity is incomplete")
            roles = payload.get("roles")
            if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
                raise ValueError("roles claim is invalid")
        except (ValueError, KeyError, json.JSONDecodeError) as error:
            raise AuthenticationError(f"invalid service token: {error}") from error
        return Principal(str(payload["tenant_id"]), str(payload["actor"]), frozenset(roles))

    @staticmethod
    def require_role(principal: Principal, *allowed_roles: str) -> None:
        if principal.roles.isdisjoint(allowed_roles):
            raise AuthorizationError(f"one of these roles is required: {', '.join(allowed_roles)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a local ASV service token")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--roles", required=True, help="comma-separated role names")
    parser.add_argument("--ttl", type=int, default=3600)
    args = parser.parse_args()
    secret = os.environ.get("ASV_AUTH_SECRET", "").encode()
    authenticator = TokenAuthenticator(secret)
    principal = Principal(args.tenant, args.actor, frozenset(filter(None, args.roles.split(","))))
    print(authenticator.issue(principal, ttl_seconds=args.ttl))


if __name__ == "__main__":
    main()

