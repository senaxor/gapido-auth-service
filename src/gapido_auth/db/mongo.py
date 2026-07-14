"""MongoDB connection and index bootstrap."""

from __future__ import annotations

from pymongo import ASCENDING, MongoClient
from pymongo.database import Database

from gapido_auth.config import Config


def create_database(config: Config) -> Database:
    client: MongoClient = MongoClient(
        config.mongo_uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        # Return stored datetimes as aware UTC; the whole codebase compares
        # against timezone-aware datetimes and naive ones would crash.
        tz_aware=True,
    )
    return client[config.mongo_db]


def ensure_indexes(db: Database) -> None:
    """Create all indexes; safe to call on every startup (idempotent)."""
    db.users.create_index([("phone", ASCENDING)], unique=True)

    db.otps.create_index([("phone", ASCENDING), ("created_at", ASCENDING)])
    # Mongo TTL reaper removes OTP documents once they are no longer needed
    # for expiry checks or hourly rate-limit accounting.
    db.otps.create_index([("purge_at", ASCENDING)], expireAfterSeconds=0)

    db.refresh_tokens.create_index([("token_hash", ASCENDING)], unique=True)
    db.refresh_tokens.create_index([("family_id", ASCENDING)])
    db.refresh_tokens.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
