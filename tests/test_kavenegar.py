import pytest
import requests

from gapido_auth.sms.kavenegar import KavenegarProvider
from gapido_auth.sms.provider import PermanentSmsError, TransientSmsError


class FakeResponse:
    def __init__(self, status_code=200, payload=None, invalid_json=False):
        self.status_code = status_code
        self._payload = payload
        self._invalid_json = invalid_json

    def json(self):
        if self._invalid_json:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    def __init__(self, response=None, exception=None):
        self.response = response
        self.exception = exception
        self.calls = []

    def post(self, url, data=None, timeout=None):
        self.calls.append({"url": url, "data": data, "timeout": timeout})
        if self.exception:
            raise self.exception
        return self.response


def provider_with(response=None, exception=None):
    session = FakeSession(response, exception)
    provider = KavenegarProvider(api_key="KEY", template="otp-login", session=session)
    return provider, session


def envelope(status, message="msg"):
    return {"return": {"status": status, "message": message}, "entries": []}


def test_success_posts_expected_fields():
    provider, session = provider_with(FakeResponse(200, envelope(200)))
    provider.send_otp("09123456789", "123456")
    call = session.calls[0]
    assert "KEY/verify/lookup.json" in call["url"]
    assert call["data"] == {
        "receptor": "09123456789",
        "token": "123456",
        "template": "otp-login",
    }


@pytest.mark.parametrize("status", [400, 401, 403, 411, 424, 431, 432])
def test_permanent_statuses(status):
    provider, _ = provider_with(FakeResponse(200, envelope(status)))
    with pytest.raises(PermanentSmsError):
        provider.send_otp("09123456789", "123456")


@pytest.mark.parametrize("status", [402, 409, 414, 418, 451])
def test_transient_statuses(status):
    provider, _ = provider_with(FakeResponse(200, envelope(status)))
    with pytest.raises(TransientSmsError):
        provider.send_otp("09123456789", "123456")


def test_unknown_status_is_transient():
    provider, _ = provider_with(FakeResponse(200, envelope(599)))
    with pytest.raises(TransientSmsError):
        provider.send_otp("09123456789", "123456")


def test_http_5xx_is_transient():
    provider, _ = provider_with(FakeResponse(502, invalid_json=True))
    with pytest.raises(TransientSmsError):
        provider.send_otp("09123456789", "123456")


def test_network_error_is_transient():
    provider, _ = provider_with(exception=requests.ConnectionError("boom"))
    with pytest.raises(TransientSmsError):
        provider.send_otp("09123456789", "123456")


def test_unparseable_body_is_transient():
    provider, _ = provider_with(FakeResponse(200, invalid_json=True))
    with pytest.raises(TransientSmsError):
        provider.send_otp("09123456789", "123456")
