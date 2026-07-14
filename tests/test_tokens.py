from datetime import timedelta

import jwt as pyjwt
import pytest

from gapido_auth.core.errors import InvalidTokenError
from gapido_auth.core.tokens import TokenService


@pytest.fixture
def service(config, refresh_repo, user_repo) -> TokenService:
    return TokenService(config, refresh_repo, user_repo)


@pytest.fixture
def user(user_repo):
    return user_repo.get_or_create("09123456789", "user")


class TestAccessTokens:
    def test_issue_and_verify(self, service, user):
        pair = service.issue_pair(user)
        claims = service.verify_access(pair.access_token)
        assert claims.user_id == user.id
        assert claims.phone == user.phone
        assert claims.role == "user"

    def test_tampered_token_rejected(self, service, user, config):
        pair = service.issue_pair(user)
        forged = pyjwt.encode(
            {**pyjwt.decode(pair.access_token, options={"verify_signature": False}),
             "role": "admin"},
            "wrong-secret-0123456789abcdef0123456789abcdef",
            algorithm="HS256",
        )
        with pytest.raises(InvalidTokenError):
            service.verify_access(forged)

    def test_garbage_rejected(self, service):
        with pytest.raises(InvalidTokenError):
            service.verify_access("not-a-jwt")

    def test_non_access_type_rejected(self, service, user, config):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        token = pyjwt.encode(
            {"sub": user.id, "role": "user", "type": "refresh",
             "iat": now, "exp": now + timedelta(hours=1)},
            config.jwt_secret,
            algorithm="HS256",
        )
        with pytest.raises(InvalidTokenError):
            service.verify_access(token)


class TestRefreshRotation:
    def test_refresh_returns_new_working_pair(self, service, user):
        pair = service.issue_pair(user)
        new_pair = service.refresh(pair.refresh_token)
        assert new_pair.refresh_token != pair.refresh_token
        assert service.verify_access(new_pair.access_token).user_id == user.id

    def test_old_token_dead_after_rotation(self, service, user):
        pair = service.issue_pair(user)
        service.refresh(pair.refresh_token)
        with pytest.raises(InvalidTokenError):
            service.refresh(pair.refresh_token)

    def test_reuse_revokes_whole_family(self, service, user):
        pair = service.issue_pair(user)
        new_pair = service.refresh(pair.refresh_token)
        with pytest.raises(InvalidTokenError):
            service.refresh(pair.refresh_token)  # replay of rotated token
        # the replay must have killed the still-valid descendant too
        with pytest.raises(InvalidTokenError):
            service.refresh(new_pair.refresh_token)

    def test_unknown_token_rejected(self, service):
        with pytest.raises(InvalidTokenError):
            service.refresh("completely-unknown")

    def test_expired_refresh_rejected(self, service, user, refresh_repo):
        pair = service.issue_pair(user)
        for doc in refresh_repo.docs.values():
            doc["expires_at"] -= timedelta(days=365)
        with pytest.raises(InvalidTokenError):
            service.refresh(pair.refresh_token)

    def test_plaintext_refresh_token_never_stored(self, service, user, refresh_repo):
        pair = service.issue_pair(user)
        assert pair.refresh_token not in str(refresh_repo.docs)


class TestLogout:
    def test_logout_revokes_family(self, service, user):
        pair = service.issue_pair(user)
        assert service.logout(pair.refresh_token) is True
        with pytest.raises(InvalidTokenError):
            service.refresh(pair.refresh_token)

    def test_logout_unknown_token(self, service):
        assert service.logout("unknown") is False
