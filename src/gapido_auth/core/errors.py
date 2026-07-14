"""Domain errors raised by the auth core.

The gRPC layer maps these onto status codes; keeping them transport-agnostic
lets the core be tested without a running server.
"""


class AuthError(Exception):
    """Base class for expected authentication failures."""


class InvalidPhoneError(AuthError):
    """The phone number is not a valid Iranian mobile number."""


class RateLimitedError(AuthError):
    """Too many OTP requests; carries how long the caller must wait."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(f"rate limited, retry after {retry_after}s")
        self.retry_after = retry_after


class InvalidOtpError(AuthError):
    """Wrong, expired, consumed or over-attempted code.

    Deliberately a single error so responses don't reveal whether a code
    exists, is expired, or is merely wrong (prevents oracle attacks).
    """


class InvalidTokenError(AuthError):
    """Refresh token is unknown, expired, revoked or malformed."""
