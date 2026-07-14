"""Access / refresh token management.

- Access tokens are short-lived HS256 JWTs carrying user id, phone and role.
- Refresh tokens are opaque 256-bit random strings. Only their SHA-256 hash
  is persisted, so a database leak does not leak usable tokens.
- Refresh tokens rotate on every use. Tokens are grouped into a *family*
  (one login session); presenting an already-rotated token is treated as
  theft and revokes the entire family (reuse detection).
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta

import jwt

from gapido_auth.config import Config
from gapido_auth.core.errors import InvalidTokenError
from gapido_auth.db.repositories import RefreshTokenRepository, User, UserRepository, utcnow

_JWT_ALGORITHM = "HS256"


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_in: int
    token_type: str = "Bearer"


@dataclass(frozen=True)
class AccessClaims:
    user_id: str
    phone: str
    role: str


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class TokenService:
    def __init__(
        self,
        config: Config,
        refresh_tokens: RefreshTokenRepository,
        users: UserRepository,
    ) -> None:
        self._config = config
        self._refresh = refresh_tokens
        self._users = users

    # -- issuing -----------------------------------------------------------

    def issue_pair(self, user: User, family_id: str | None = None) -> TokenPair:
        now = utcnow()
        access = jwt.encode(
            {
                "sub": user.id,
                "phone": user.phone,
                "role": user.role,
                "type": "access",
                "jti": uuid.uuid4().hex,
                "iat": now,
                "exp": now + timedelta(seconds=self._config.access_token_ttl),
            },
            self._config.jwt_secret,
            algorithm=_JWT_ALGORITHM,
        )

        refresh = secrets.token_urlsafe(32)
        self._refresh.create(
            token_hash=_hash_token(refresh),
            user_id=user.id,
            family_id=family_id or uuid.uuid4().hex,
            expires_at=now + timedelta(seconds=self._config.refresh_token_ttl),
        )
        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            access_expires_in=self._config.access_token_ttl,
        )

    # -- refresh rotation ---------------------------------------------------

    def refresh(self, refresh_token: str) -> TokenPair:
        record = self._refresh.find_by_hash(_hash_token(refresh_token))
        if record is None:
            raise InvalidTokenError("unknown refresh token")
        if record["revoked"]:
            # The token was already rotated or logged out. Someone replaying
            # it means the token leaked: kill the whole session family.
            self._refresh.revoke_family(record["family_id"])
            raise InvalidTokenError("refresh token reuse detected")
        if utcnow() > record["expires_at"]:
            raise InvalidTokenError("refresh token expired")

        # Atomic revoke doubles as a concurrency guard: if two requests race
        # with the same token, exactly one wins the rotation.
        if not self._refresh.revoke(record["token_hash"]):
            self._refresh.revoke_family(record["family_id"])
            raise InvalidTokenError("refresh token reuse detected")

        user = self._users.get_by_id(record["user_id"])
        if user is None:
            raise InvalidTokenError("user no longer exists")
        return self.issue_pair(user, family_id=record["family_id"])

    def logout(self, refresh_token: str) -> bool:
        record = self._refresh.find_by_hash(_hash_token(refresh_token))
        if record is None:
            return False
        self._refresh.revoke_family(record["family_id"])
        return True

    # -- access token verification ------------------------------------------

    def verify_access(self, token: str) -> AccessClaims:
        try:
            claims = jwt.decode(
                token,
                self._config.jwt_secret,
                algorithms=[_JWT_ALGORITHM],
                options={"require": ["sub", "exp", "iat", "role", "type"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(str(exc)) from exc
        if claims.get("type") != "access":
            raise InvalidTokenError("not an access token")
        return AccessClaims(
            user_id=claims["sub"],
            phone=claims.get("phone", ""),
            role=claims["role"],
        )
