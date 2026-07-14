"""SMS provider abstraction.

The worker only distinguishes two failure classes:

- TransientSmsError: worth retrying (network trouble, provider 5xx, rate
  limits, temporarily depleted credit).
- PermanentSmsError: retrying cannot help (bad API key, invalid template,
  invalid receptor); the job goes straight to the dead-letter queue.
"""

from __future__ import annotations

import logging
from typing import Protocol

logger = logging.getLogger(__name__)


class SmsError(Exception):
    pass


class TransientSmsError(SmsError):
    pass


class PermanentSmsError(SmsError):
    pass


class SmsProvider(Protocol):
    def send_otp(self, phone: str, code: str) -> None:
        """Deliver the code; raise Transient/PermanentSmsError on failure."""


class ConsoleSmsProvider:
    """Development fallback: prints the OTP to the worker log."""

    def send_otp(self, phone: str, code: str) -> None:
        logger.info("[console-sms] OTP for %s: %s", phone, code)


def build_provider(config) -> SmsProvider:
    if config.sms_provider == "kavenegar":
        from gapido_auth.sms.kavenegar import KavenegarProvider

        return KavenegarProvider(
            api_key=config.kavenegar_api_key,
            template=config.kavenegar_template,
        )
    return ConsoleSmsProvider()
