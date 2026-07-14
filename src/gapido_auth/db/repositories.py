"""Persistence layer: thin repositories over MongoDB collections.

All timestamps are timezone-aware UTC datetimes. Documents:

users:          {_id, phone, role, created_at, last_login_at}
otps:           {_id, phone, code_hash, attempts, consumed,
                 created_at, expires_at, purge_at}
refresh_tokens: {_id, token_hash, user_id, family_id, revoked,
                 created_at, expires_at}
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from bson import ObjectId
from pymongo import ReturnDocument
from pymongo.database import Database

ROLE_USER = "user"
ROLE_ADMIN = "admin"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class User:
    id: str
    phone: str
    role: str
    created_at: datetime

    @classmethod
    def from_doc(cls, doc: dict[str, Any]) -> "User":
        return cls(
            id=str(doc["_id"]),
            phone=doc["phone"],
            role=doc["role"],
            created_at=doc["created_at"],
        )


class UserRepository:
    def __init__(self, db: Database) -> None:
        self._col = db.users

    def get_or_create(self, phone: str, role: str) -> User:
        """Fetch the user for ``phone``, creating it on first login.

        The role is only applied at creation time; an existing user's role is
        never silently changed by logging in.
        """
        now = utcnow()
        doc = self._col.find_one_and_update(
            {"phone": phone},
            {
                "$set": {"last_login_at": now},
                "$setOnInsert": {"phone": phone, "role": role, "created_at": now},
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return User.from_doc(doc)

    def get_by_id(self, user_id: str) -> User | None:
        if not ObjectId.is_valid(user_id):
            return None
        doc = self._col.find_one({"_id": ObjectId(user_id)})
        return User.from_doc(doc) if doc else None

    def list_page(self, page: int, page_size: int) -> tuple[list[User], int]:
        total = self._col.count_documents({})
        cursor = (
            self._col.find()
            .sort("created_at", 1)
            .skip((page - 1) * page_size)
            .limit(page_size)
        )
        return [User.from_doc(d) for d in cursor], total


class OtpRepository:
    """Stores hashed OTP codes; plaintext codes never reach the database."""

    def __init__(self, db: Database) -> None:
        self._col = db.otps

    def latest_for(self, phone: str) -> dict[str, Any] | None:
        return self._col.find_one({"phone": phone}, sort=[("created_at", -1)])

    def count_since(self, phone: str, since: datetime) -> int:
        return self._col.count_documents({"phone": phone, "created_at": {"$gte": since}})

    def create(self, phone: str, code_hash: str, ttl: int, purge_after: int) -> None:
        now = utcnow()
        self._col.insert_one(
            {
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
        """Atomically increment the attempt counter and return the new value."""
        doc = self._col.find_one_and_update(
            {"_id": otp_id},
            {"$inc": {"attempts": 1}},
            return_document=ReturnDocument.AFTER,
        )
        return doc["attempts"] if doc else 0

    def consume(self, otp_id: Any) -> bool:
        """Mark the OTP used; returns False if it was already consumed
        (guards against two concurrent verifications of the same code)."""
        result = self._col.update_one(
            {"_id": otp_id, "consumed": False}, {"$set": {"consumed": True}}
        )
        return result.modified_count == 1


class RefreshTokenRepository:
    """Stores SHA-256 hashes of refresh tokens, grouped into families.

    A family is one login session: the original token and every token that
    rotation produced from it. Revoking the family kills the whole session.
    """

    def __init__(self, db: Database) -> None:
        self._col = db.refresh_tokens

    def create(
        self, token_hash: str, user_id: str, family_id: str, expires_at: datetime
    ) -> None:
        self._col.insert_one(
            {
                "token_hash": token_hash,
                "user_id": user_id,
                "family_id": family_id,
                "revoked": False,
                "created_at": utcnow(),
                "expires_at": expires_at,
            }
        )

    def find_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        return self._col.find_one({"token_hash": token_hash})

    def revoke(self, token_hash: str) -> bool:
        """Atomically revoke one token; False means it was already revoked."""
        result = self._col.update_one(
            {"token_hash": token_hash, "revoked": False},
            {"$set": {"revoked": True}},
        )
        return result.modified_count == 1

    def revoke_family(self, family_id: str) -> None:
        self._col.update_many({"family_id": family_id}, {"$set": {"revoked": True}})
