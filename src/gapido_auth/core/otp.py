"""OTP issuing and verification.

Security properties:

- Codes are generated with ``secrets`` (CSPRNG), uniform over the code space.
- Only a peppered HMAC-SHA256 of the code is stored, never the plaintext.
- Codes expire after a short TTL and are single-use.
- Verification attempts are counted atomically and capped, so a 6-digit code
  cannot be brute-forced within its lifetime.
- Requests are rate-limited per phone (resend cooldown + hourly cap).
- Only the most recently issued code for a phone is valid.
- All verification failures raise the same error, revealing nothing about
  whether a code exists, expired, or was simply wrong.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta

from gapido_auth.config import Config
from gapido_auth.core.errors import InvalidOtpError, InvalidPhoneError, RateLimitedError
from gapido_auth.db.repositories import OtpRepository, utcnow

# Iranian mobile numbers: 09 followed by 9 digits.
_PHONE_RE = re.compile(r"^09\d{9}$")

# Keep OTP documents around at least this long after creation so the
# hourly rate-limit window can still count them (see OtpRepository purge_at).
_RATE_WINDOW_SECONDS = 3600


def normalize_phone(phone: str) -> str:
    """Validate and canonicalize a phone number ("+98912..." -> "0912...")."""
    phone = phone.strip().replace(" ", "")
    if phone.startswith("+98"):
        phone = "0" + phone[3:]
    elif phone.startswith("98") and len(phone) == 12:
        phone = "0" + phone[2:]
    if not _PHONE_RE.fullmatch(phone):
        raise InvalidPhoneError("phone must be an Iranian mobile number like 09123456789")
    return phone


@dataclass(frozen=True)
class OtpIssued:
    phone: str
    code: str
    expires_in: int
    retry_after: int


class OtpService:
    def __init__(self, config: Config, otps: OtpRepository) -> None:
        self._config = config
        self._otps = otps

    # -- issuing -----------------------------------------------------------

    def request_otp(self, raw_phone: str) -> OtpIssued:
        phone = normalize_phone(raw_phone)
        now = utcnow()

        latest = self._otps.latest_for(phone)
        if latest is not None:
            elapsed = (now - latest["created_at"]).total_seconds()
            remaining = self._config.otp_resend_cooldown - int(elapsed)
            if remaining > 0:
                raise RateLimitedError(retry_after=remaining)

        window_start = now - timedelta(seconds=_RATE_WINDOW_SECONDS)
        if self._otps.count_since(phone, window_start) >= self._config.otp_max_requests_per_hour:
            raise RateLimitedError(retry_after=_RATE_WINDOW_SECONDS)

        code = self._generate_code()
        self._otps.create(
            phone=phone,
            code_hash=self._hash(phone, code),
            ttl=self._config.otp_ttl,
            purge_after=max(_RATE_WINDOW_SECONDS, self._config.otp_ttl),
        )
        return OtpIssued(
            phone=phone,
            code=code,
            expires_in=self._config.otp_ttl,
            retry_after=self._config.otp_resend_cooldown,
        )

    # -- verification ------------------------------------------------------

    def verify(self, raw_phone: str, code: str) -> str:
        """Verify ``code`` for the phone; returns the normalized phone.

        Raises InvalidOtpError on any failure, always the same error type.
        """
        phone = normalize_phone(raw_phone)
        code = code.strip()
        if not code.isdigit() or len(code) != self._config.otp_length:
            raise InvalidOtpError("invalid code")

        otp = self._otps.latest_for(phone)
        if otp is None or otp["consumed"] or utcnow() > otp["expires_at"]:
            raise InvalidOtpError("invalid code")

        # Count the attempt before comparing, so parallel guesses cannot
        # exceed the cap by racing the comparison.
        attempts = self._otps.register_attempt(otp["_id"])
        if attempts > self._config.otp_max_verify_attempts:
            raise InvalidOtpError("invalid code")

        expected = self._hash(phone, code)
        if not hmac.compare_digest(expected, otp["code_hash"]):
            raise InvalidOtpError("invalid code")

        # Single-use: losing this race means someone else just consumed it.
        if not self._otps.consume(otp["_id"]):
            raise InvalidOtpError("invalid code")
        return phone

    # -- helpers -----------------------------------------------------------

    def _generate_code(self) -> str:
        n = self._config.otp_length
        return f"{secrets.randbelow(10 ** n):0{n}d}"

    def _hash(self, phone: str, code: str) -> str:
        # Binding the phone into the MAC stops a code issued for one number
        # from ever verifying against another.
        message = f"{phone}:{code}".encode()
        return hmac.new(self._config.otp_pepper.encode(), message, hashlib.sha256).hexdigest()
