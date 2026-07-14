"""Application configuration, loaded from environment variables.

Every knob the service exposes lives here so the rest of the codebase never
touches ``os.environ`` directly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class ConfigError(Exception):
    """Raised when the environment is missing or holds invalid settings."""


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise ConfigError(f"required environment variable {name} is not set")
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class Config:
    # MongoDB
    mongo_uri: str
    mongo_db: str

    # RabbitMQ
    rabbitmq_url: str

    # JWT
    jwt_secret: str
    access_token_ttl: int
    refresh_token_ttl: int

    # OTP policy
    otp_ttl: int
    otp_length: int
    otp_max_verify_attempts: int
    otp_resend_cooldown: int
    otp_max_requests_per_hour: int
    otp_pepper: str

    # SMS
    sms_provider: str
    kavenegar_api_key: str
    kavenegar_template: str

    # Roles
    admin_phones: frozenset[str] = field(default_factory=frozenset)

    # Server
    grpc_port: int = 50051

    @classmethod
    def from_env(cls) -> "Config":
        sms_provider = os.environ.get("SMS_PROVIDER", "console").lower()
        if sms_provider not in ("console", "kavenegar"):
            raise ConfigError(
                f"SMS_PROVIDER must be 'console' or 'kavenegar', got {sms_provider!r}"
            )
        if sms_provider == "kavenegar":
            kavenegar_api_key = _env("KAVENEGAR_API_KEY")
            kavenegar_template = _env("KAVENEGAR_TEMPLATE")
        else:
            kavenegar_api_key = os.environ.get("KAVENEGAR_API_KEY", "")
            kavenegar_template = os.environ.get("KAVENEGAR_TEMPLATE", "")

        jwt_secret = _env("JWT_SECRET")
        otp_pepper = _env("OTP_PEPPER")
        for name, secret in (("JWT_SECRET", jwt_secret), ("OTP_PEPPER", otp_pepper)):
            if len(secret) < 32 or secret.startswith("change-me"):
                raise ConfigError(
                    f"{name} must be a strong random value of at least 32 characters"
                )

        admin_phones = frozenset(
            p.strip() for p in os.environ.get("ADMIN_PHONES", "").split(",") if p.strip()
        )

        return cls(
            mongo_uri=_env("MONGO_URI", "mongodb://localhost:27017"),
            mongo_db=_env("MONGO_DB", "gapido_auth"),
            rabbitmq_url=_env("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/%2F"),
            jwt_secret=jwt_secret,
            access_token_ttl=_env_int("ACCESS_TOKEN_TTL_SECONDS", 900),
            refresh_token_ttl=_env_int("REFRESH_TOKEN_TTL_SECONDS", 14 * 24 * 3600),
            otp_ttl=_env_int("OTP_TTL_SECONDS", 120),
            otp_length=_env_int("OTP_LENGTH", 6),
            otp_max_verify_attempts=_env_int("OTP_MAX_VERIFY_ATTEMPTS", 5),
            otp_resend_cooldown=_env_int("OTP_RESEND_COOLDOWN_SECONDS", 60),
            otp_max_requests_per_hour=_env_int("OTP_MAX_REQUESTS_PER_HOUR", 5),
            otp_pepper=otp_pepper,
            sms_provider=sms_provider,
            kavenegar_api_key=kavenegar_api_key,
            kavenegar_template=kavenegar_template,
            admin_phones=admin_phones,
            grpc_port=_env_int("GRPC_PORT", 50051),
        )
