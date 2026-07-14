"""Kavenegar Verify Lookup client.

Uses the dedicated OTP endpoint (``verify/lookup.json``) with a template
defined in the Kavenegar panel. Implemented directly over HTTP so error
classification is explicit rather than hidden inside an SDK.

Kavenegar wraps every response in an envelope:

    {"return": {"status": <code>, "message": "..."}, "entries": ...}

``return.status`` codes and how this client classifies them:

    200  sent                          -> success
    400  invalid parameters            -> permanent
    401  account suspended             -> permanent
    402  operation failed              -> transient
    403  invalid API key               -> permanent
    406  empty mandatory parameter     -> permanent
    409  server unable to respond      -> transient
    411  invalid receptor              -> permanent
    412  invalid sender line           -> permanent
    413  message empty or too long     -> permanent
    414  request volume too high       -> transient (back off, retry)
    417  invalid date                  -> permanent
    418  insufficient credit           -> transient (retry after top-up)
    422  invalid characters in data    -> permanent
    424  template not found/unapproved -> permanent
    426  feature needs plan upgrade    -> permanent
    428  cannot send code via call     -> permanent
    431  invalid code structure        -> permanent
    432  code parameter missing        -> permanent
    451  rate limited for this IP      -> transient

Anything unknown is treated as transient so a new provider-side code never
silently drops OTPs; after MAX_DELIVERY_ATTEMPTS they park in the DLQ anyway.
"""

from __future__ import annotations

import logging

import requests

from gapido_auth.sms.provider import PermanentSmsError, TransientSmsError

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.kavenegar.com/v1/{api_key}/verify/lookup.json"
_TIMEOUT_SECONDS = 10

_PERMANENT_STATUSES = frozenset(
    {400, 401, 403, 406, 411, 412, 413, 417, 422, 424, 426, 428, 431, 432}
)
_TRANSIENT_STATUSES = frozenset({402, 409, 414, 418, 451})


class KavenegarProvider:
    def __init__(
        self,
        api_key: str,
        template: str,
        session: requests.Session | None = None,
    ) -> None:
        self._url = _BASE_URL.format(api_key=api_key)
        self._template = template
        self._session = session or requests.Session()

    def send_otp(self, phone: str, code: str) -> None:
        try:
            response = self._session.post(
                self._url,
                data={"receptor": phone, "token": code, "template": self._template},
                timeout=_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            raise TransientSmsError(f"kavenegar unreachable: {exc}") from exc

        if response.status_code >= 500:
            raise TransientSmsError(f"kavenegar HTTP {response.status_code}")

        try:
            envelope = response.json()
            status = int(envelope["return"]["status"])
            message = str(envelope["return"]["message"])
        except (ValueError, KeyError, TypeError) as exc:
            raise TransientSmsError(f"unparseable kavenegar response: {exc}") from exc

        if status == 200:
            logger.info("kavenegar accepted OTP sms for %s", phone)
            return
        # The envelope message is provider metadata, safe to log (no OTP).
        if status in _PERMANENT_STATUSES:
            raise PermanentSmsError(f"kavenegar status {status}: {message}")
        if status not in _TRANSIENT_STATUSES:
            logger.warning("unknown kavenegar status %d (%s), treating as transient", status, message)
        raise TransientSmsError(f"kavenegar status {status}: {message}")
