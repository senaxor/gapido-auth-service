"""AuthService gRPC servicer: OTP login, token refresh, logout."""

from __future__ import annotations

import logging

import grpc

from gapido_auth.config import Config
from gapido_auth.core.errors import (
    InvalidOtpError,
    InvalidPhoneError,
    InvalidTokenError,
    RateLimitedError,
)
from gapido_auth.core.otp import OtpService
from gapido_auth.core.tokens import TokenPair, TokenService
from gapido_auth.db.repositories import ROLE_ADMIN, ROLE_USER, UserRepository
from gapido_auth.messaging.publisher import PublishError, SmsJobPublisher
from gapido_auth.proto import auth_pb2, auth_pb2_grpc

logger = logging.getLogger(__name__)


def _token_pair_message(pair: TokenPair) -> auth_pb2.TokenPair:
    return auth_pb2.TokenPair(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        access_expires_in=pair.access_expires_in,
        token_type=pair.token_type,
    )


class AuthServicer(auth_pb2_grpc.AuthServiceServicer):
    def __init__(
        self,
        config: Config,
        otp_service: OtpService,
        token_service: TokenService,
        users: UserRepository,
        publisher: SmsJobPublisher,
    ) -> None:
        self._config = config
        self._otp = otp_service
        self._tokens = token_service
        self._users = users
        self._publisher = publisher

    # -- RPCs ----------------------------------------------------------------

    def RequestOtp(self, request, context):
        try:
            issued = self._otp.request_otp(request.phone)
        except InvalidPhoneError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        except RateLimitedError as exc:
            context.set_trailing_metadata((("retry-after", str(exc.retry_after)),))
            context.abort(
                grpc.StatusCode.RESOURCE_EXHAUSTED,
                f"too many requests, retry after {exc.retry_after}s",
            )

        try:
            self._publisher.publish_otp(issued.phone, issued.code)
        except PublishError:
            logger.exception("failed to enqueue otp sms for %s", issued.phone)
            context.abort(
                grpc.StatusCode.UNAVAILABLE, "sms service unavailable, try again later"
            )

        logger.info("otp issued for %s", issued.phone)
        return auth_pb2.RequestOtpResponse(
            expires_in=issued.expires_in, retry_after=issued.retry_after
        )

    def VerifyOtp(self, request, context):
        try:
            phone = self._otp.verify(request.phone, request.code)
        except InvalidPhoneError as exc:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))
        except InvalidOtpError:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid or expired code")

        role = ROLE_ADMIN if phone in self._config.admin_phones else ROLE_USER
        user = self._users.get_or_create(phone, role)
        logger.info("user %s authenticated (role=%s)", user.id, user.role)
        return _token_pair_message(self._tokens.issue_pair(user))

    def RefreshToken(self, request, context):
        if not request.refresh_token:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "refresh_token is required")
        try:
            pair = self._tokens.refresh(request.refresh_token)
        except InvalidTokenError:
            # One opaque message for unknown/expired/reused tokens alike.
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid refresh token")
        return _token_pair_message(pair)

    def Logout(self, request, context):
        if not request.refresh_token:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "refresh_token is required")
        return auth_pb2.LogoutResponse(revoked=self._tokens.logout(request.refresh_token))
