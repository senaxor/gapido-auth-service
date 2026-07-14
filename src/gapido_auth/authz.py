"""Central access-control policy: which role may call which gRPC method.

The auth interceptor consults this map for every incoming call. Methods not
listed here are denied outright (default-deny), so adding a new RPC forces
an explicit access decision.
"""

from __future__ import annotations

from enum import Enum

from gapido_auth.db.repositories import ROLE_ADMIN


class Access(Enum):
    PUBLIC = "public"            # no token required
    AUTHENTICATED = "authenticated"  # any valid access token
    ADMIN = "admin"              # valid access token with the admin role


METHOD_ACCESS: dict[str, Access] = {
    # AuthService: reachable without a token by definition.
    "/gapido.auth.v1.AuthService/RequestOtp": Access.PUBLIC,
    "/gapido.auth.v1.AuthService/VerifyOtp": Access.PUBLIC,
    "/gapido.auth.v1.AuthService/RefreshToken": Access.PUBLIC,
    "/gapido.auth.v1.AuthService/Logout": Access.PUBLIC,
    # DemoService: one method per access level (challenge requirement).
    "/gapido.demo.v1.DemoService/GetPublicNotice": Access.PUBLIC,
    "/gapido.demo.v1.DemoService/GetMyProfile": Access.AUTHENTICATED,
    "/gapido.demo.v1.DemoService/ListUsers": Access.ADMIN,
    # Infrastructure: health checks (docker) and reflection (grpcurl).
    "/grpc.health.v1.Health/Check": Access.PUBLIC,
    "/grpc.health.v1.Health/Watch": Access.PUBLIC,
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo": Access.PUBLIC,
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo": Access.PUBLIC,
}


def is_allowed(access: Access, role: str | None) -> bool:
    """Decide whether a caller with ``role`` (None = anonymous) may proceed."""
    if access is Access.PUBLIC:
        return True
    if access is Access.AUTHENTICATED:
        return role is not None
    return role == ROLE_ADMIN
