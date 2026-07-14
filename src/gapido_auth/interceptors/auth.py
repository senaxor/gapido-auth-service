"""gRPC server interceptor enforcing the authz.METHOD_ACCESS policy.

On every call it:

1. Extracts ``authorization: Bearer <jwt>`` metadata if present.
2. Validates the access token and resolves the caller's role.
3. Checks the method's required access level (default-deny).
4. Exposes the verified claims to servicers via the ``current_claims``
   context variable (contextvars are thread-safe under gRPC's thread pool).

Unauthenticated callers get UNAUTHENTICATED, authenticated callers lacking
the role get PERMISSION_DENIED.
"""

from __future__ import annotations

import contextvars
import logging
from typing import Callable

import grpc

from gapido_auth.authz import METHOD_ACCESS, Access, is_allowed
from gapido_auth.core.errors import InvalidTokenError
from gapido_auth.core.tokens import AccessClaims, TokenService

logger = logging.getLogger(__name__)

current_claims: contextvars.ContextVar[AccessClaims | None] = contextvars.ContextVar(
    "current_claims", default=None
)


def _abort_handler(code: grpc.StatusCode, details: str, template) -> grpc.RpcMethodHandler:
    def abort(_request, context):
        context.abort(code, details)

    return grpc.unary_unary_rpc_method_handler(
        abort,
        request_deserializer=template.request_deserializer,
        response_serializer=template.response_serializer,
    )


class AuthInterceptor(grpc.ServerInterceptor):
    def __init__(
        self,
        token_service: TokenService,
        method_access: dict[str, Access] | None = None,
    ) -> None:
        self._tokens = token_service
        self._access = METHOD_ACCESS if method_access is None else method_access

    def intercept_service(
        self,
        continuation: Callable,
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler | None:
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        method = handler_call_details.method
        access = self._access.get(method)

        claims: AccessClaims | None = None
        token_error: str | None = None
        metadata = dict(handler_call_details.invocation_metadata or ())
        header = metadata.get("authorization", "")
        if header.startswith("Bearer "):
            try:
                claims = self._tokens.verify_access(header.removeprefix("Bearer "))
            except InvalidTokenError as exc:
                token_error = str(exc)

        if access is None:
            logger.warning("no access policy for %s, denying", method)
            return _abort_handler(
                grpc.StatusCode.PERMISSION_DENIED, "method not allowed", handler
            )
        if access is not Access.PUBLIC:
            if claims is None:
                return _abort_handler(
                    grpc.StatusCode.UNAUTHENTICATED,
                    token_error or "access token required",
                    handler,
                )
            if not is_allowed(access, claims.role):
                return _abort_handler(
                    grpc.StatusCode.PERMISSION_DENIED, "admin role required", handler
                )

        return self._with_claims(handler, claims)

    @staticmethod
    def _with_claims(
        handler: grpc.RpcMethodHandler, claims: AccessClaims | None
    ) -> grpc.RpcMethodHandler:
        """Rebuild the handler so the behavior runs with claims in context."""
        if handler.unary_unary is None:
            # All RPCs in this service are unary-unary; anything else would be
            # a new handler kind added without updating this interceptor.
            return handler

        inner = handler.unary_unary

        def behavior(request, context):
            token = current_claims.set(claims)
            try:
                return inner(request, context)
            finally:
                current_claims.reset(token)

        return grpc.unary_unary_rpc_method_handler(
            behavior,
            request_deserializer=handler.request_deserializer,
            response_serializer=handler.response_serializer,
        )
