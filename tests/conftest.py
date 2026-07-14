import pytest

from gapido_auth.config import Config

from tests.fakes import FakeOtpRepository, FakeRefreshTokenRepository, FakeUserRepository

ADMIN_PHONE = "09120000009"


@pytest.fixture
def config() -> Config:
    return Config(
        mongo_uri="mongodb://unused:27017",
        mongo_db="test",
        rabbitmq_url="amqp://unused",
        jwt_secret="test-jwt-secret-0123456789abcdef0123456789abcdef",
        access_token_ttl=900,
        refresh_token_ttl=3600,
        otp_ttl=120,
        otp_length=6,
        otp_max_verify_attempts=3,
        otp_resend_cooldown=60,
        otp_max_requests_per_hour=3,
        otp_pepper="test-otp-pepper-0123456789abcdef0123456789abcdef",
        sms_provider="console",
        kavenegar_api_key="",
        kavenegar_template="",
        admin_phones=frozenset({ADMIN_PHONE}),
        grpc_port=0,
    )


@pytest.fixture
def otp_repo() -> FakeOtpRepository:
    return FakeOtpRepository()


@pytest.fixture
def refresh_repo() -> FakeRefreshTokenRepository:
    return FakeRefreshTokenRepository()


@pytest.fixture
def user_repo() -> FakeUserRepository:
    return FakeUserRepository()
