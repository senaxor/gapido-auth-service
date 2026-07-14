"""In-memory stand-ins for the Mongo repositories.

They mirror the repository interfaces exactly so the core services can be
unit-tested without a database. Tests may reach into ``.docs`` to simulate
time passing (e.g. backdating ``created_at`` or ``expires_at``).
"""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta
from typing import Any

from gapido_auth.db.repositories import User, utcnow

_ids = itertools.count(1)


class FakeOtpRepository:
    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []

    def latest_for(self, phone: str) -> dict[str, Any] | None:
        matches = [d for d in self.docs if d["phone"] == phone]
        return max(matches, key=lambda d: d["created_at"]) if matches else None

    def count_since(self, phone: str, since: datetime) -> int:
        return sum(1 for d in self.docs if d["phone"] == phone and d["created_at"] >= since)

    def create(self, phone: str, code_hash: str, ttl: int, purge_after: int) -> None:
        now = utcnow()
        self.docs.append(
            {
                "_id": next(_ids),
                "phone": phone,
                "code_hash": code_hash,
                "attempts": 0,
                "consumed": False,
                "created_at": now,
                "expires_at": now + timedelta(seconds=ttl),
                "purge_at": now + timedelta(seconds=purge_after),
            }
        )

    def register_attempt(self, otp_id: Any) -> int:
        for doc in self.docs:
            if doc["_id"] == otp_id:
                doc["attempts"] += 1
                return doc["attempts"]
        return 0

    def consume(self, otp_id: Any) -> bool:
        for doc in self.docs:
            if doc["_id"] == otp_id and not doc["consumed"]:
                doc["consumed"] = True
                return True
        return False


class FakeRefreshTokenRepository:
    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}

    def create(self, token_hash: str, user_id: str, family_id: str, expires_at: datetime) -> None:
        self.docs[token_hash] = {
            "token_hash": token_hash,
            "user_id": user_id,
            "family_id": family_id,
            "revoked": False,
            "created_at": utcnow(),
            "expires_at": expires_at,
        }

    def find_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        return self.docs.get(token_hash)

    def revoke(self, token_hash: str) -> bool:
        doc = self.docs.get(token_hash)
        if doc is None or doc["revoked"]:
            return False
        doc["revoked"] = True
        return True

    def revoke_family(self, family_id: str) -> None:
        for doc in self.docs.values():
            if doc["family_id"] == family_id:
                doc["revoked"] = True


class FakeUserRepository:
    def __init__(self) -> None:
        self.by_phone: dict[str, User] = {}

    def get_or_create(self, phone: str, role: str) -> User:
        user = self.by_phone.get(phone)
        if user is None:
            user = User(id=str(next(_ids)), phone=phone, role=role, created_at=utcnow())
            self.by_phone[phone] = user
        return user

    def get_by_id(self, user_id: str) -> User | None:
        return next((u for u in self.by_phone.values() if u.id == user_id), None)

    def list_page(self, page: int, page_size: int) -> tuple[list[User], int]:
        users = sorted(self.by_phone.values(), key=lambda u: u.created_at)
        start = (page - 1) * page_size
        return users[start : start + page_size], len(users)
