from datetime import timedelta

import pytest

from gapido_auth.core.errors import InvalidOtpError, InvalidPhoneError, RateLimitedError
from gapido_auth.core.otp import OtpService, normalize_phone


@pytest.fixture
def service(config, otp_repo) -> OtpService:
    return OtpService(config, otp_repo)


class TestNormalizePhone:
    def test_accepts_local_format(self):
        assert normalize_phone("09123456789") == "09123456789"

    def test_converts_plus98(self):
        assert normalize_phone("+989123456789") == "09123456789"

    def test_converts_bare_98(self):
        assert normalize_phone("989123456789") == "09123456789"

    def test_strips_spaces(self):
        assert normalize_phone(" 0912 345 6789 ") == "09123456789"

    @pytest.mark.parametrize(
        "bad", ["", "0912", "9123456789", "08123456789", "0912345678a", "0912345678900"]
    )
    def test_rejects_invalid(self, bad):
        with pytest.raises(InvalidPhoneError):
            normalize_phone(bad)


class TestRequestOtp:
    def test_issues_code_of_configured_length(self, service, config):
        issued = service.request_otp("09123456789")
        assert len(issued.code) == config.otp_length
        assert issued.code.isdigit()
        assert issued.expires_in == config.otp_ttl

    def test_plaintext_code_is_never_stored(self, service, otp_repo):
        issued = service.request_otp("09123456789")
        stored = otp_repo.docs[0]
        assert issued.code not in str(stored)
        assert len(stored["code_hash"]) == 64  # sha256 hex

    def test_resend_cooldown(self, service):
        service.request_otp("09123456789")
        with pytest.raises(RateLimitedError) as exc_info:
            service.request_otp("09123456789")
        assert 0 < exc_info.value.retry_after <= 60

    def test_cooldown_is_per_phone(self, service):
        service.request_otp("09123456789")
        service.request_otp("09123456780")  # different phone: no error

    def test_hourly_cap(self, service, otp_repo, config):
        phone = "09123456789"
        for _ in range(config.otp_max_requests_per_hour):
            service.request_otp(phone)
            # age past the cooldown but keep inside the hourly window
            for doc in otp_repo.docs:
                doc["created_at"] -= timedelta(seconds=61)
        with pytest.raises(RateLimitedError):
            service.request_otp(phone)


class TestVerifyOtp:
    def test_roundtrip(self, service):
        issued = service.request_otp("09123456789")
        assert service.verify("09123456789", issued.code) == "09123456789"

    def test_verify_accepts_intl_format(self, service):
        issued = service.request_otp("09123456789")
        assert service.verify("+989123456789", issued.code) == "09123456789"

    def test_code_is_single_use(self, service):
        issued = service.request_otp("09123456789")
        service.verify("09123456789", issued.code)
        with pytest.raises(InvalidOtpError):
            service.verify("09123456789", issued.code)

    def test_wrong_code_rejected(self, service):
        issued = service.request_otp("09123456789")
        wrong = "000000" if issued.code != "000000" else "000001"
        with pytest.raises(InvalidOtpError):
            service.verify("09123456789", wrong)

    def test_no_code_requested(self, service):
        with pytest.raises(InvalidOtpError):
            service.verify("09123456789", "123456")

    def test_expired_code_rejected(self, service, otp_repo):
        issued = service.request_otp("09123456789")
        otp_repo.docs[0]["expires_at"] -= timedelta(seconds=999)
        with pytest.raises(InvalidOtpError):
            service.verify("09123456789", issued.code)

    def test_attempt_cap_blocks_brute_force(self, service, config):
        issued = service.request_otp("09123456789")
        wrong = "000000" if issued.code != "000000" else "000001"
        for _ in range(config.otp_max_verify_attempts):
            with pytest.raises(InvalidOtpError):
                service.verify("09123456789", wrong)
        # even the correct code is dead now
        with pytest.raises(InvalidOtpError):
            service.verify("09123456789", issued.code)

    def test_only_latest_code_is_valid(self, service, otp_repo):
        first = service.request_otp("09123456789")
        for doc in otp_repo.docs:
            doc["created_at"] -= timedelta(seconds=61)
        second = service.request_otp("09123456789")
        with pytest.raises(InvalidOtpError):
            service.verify("09123456789", first.code)
        # attempts above burned one try; the latest code still works
        assert service.verify("09123456789", second.code)

    def test_malformed_code_rejected(self, service):
        service.request_otp("09123456789")
        for bad in ("", "12345", "1234567", "12345a"):
            with pytest.raises(InvalidOtpError):
                service.verify("09123456789", bad)
