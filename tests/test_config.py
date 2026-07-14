import pytest

from gapido_auth.config import Config, ConfigError

STRONG = "0123456789abcdef0123456789abcdef-strong"


def base_env():
    return {
        "JWT_SECRET": STRONG,
        "OTP_PEPPER": STRONG,
        "MONGO_URI": "mongodb://x:27017",
        "RABBITMQ_URL": "amqp://x",
    }


def test_loads_defaults(monkeypatch):
    for key, value in base_env().items():
        monkeypatch.setenv(key, value)
    config = Config.from_env()
    assert config.sms_provider == "console"
    assert config.otp_length == 6
    assert config.access_token_ttl == 900


def test_rejects_weak_jwt_secret(monkeypatch):
    env = base_env() | {"JWT_SECRET": "short"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ConfigError):
        Config.from_env()

def test_rejects_placeholder_secret(monkeypatch):
    env = base_env() | {"OTP_PEPPER": "change-me-" + "x" * 40}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ConfigError):
        Config.from_env()


def test_kavenegar_requires_key_and_template(monkeypatch):
    env = base_env() | {"SMS_PROVIDER": "kavenegar"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("KAVENEGAR_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        Config.from_env()


def test_unknown_provider_rejected(monkeypatch):
    env = base_env() | {"SMS_PROVIDER": "smtp"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ConfigError):
        Config.from_env()


def test_admin_phones_parsed(monkeypatch):
    env = base_env() | {"ADMIN_PHONES": "09120000001, 09120000002"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert Config.from_env().admin_phones == {"09120000001", "09120000002"}
