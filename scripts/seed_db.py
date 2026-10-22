"""Database Initialization and Seeder Script (Step 7).

Populates SentinelX database with initial administrative, analyst, and auditor accounts,
production CMDB assets, and standard ingestion API keys.
Maintains tamper-evident hash chaining continuity (Law 4) across all seed mutations.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import uuid
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import select

from backend.app.core.config import settings
from backend.app.core.database import async_session_factory, engine, init_db
from backend.app.core.security import hash_api_key, hash_password
from backend.app.models.api_key import ApiKey
from backend.app.models.asset import Asset
from backend.app.models.user import User
from backend.app.services.audit_service import audit_service

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelx.seeder")

DEFAULT_USERS = [
    {
        "username": "admin",
        "email": "admin@sentinelx.local",
        "password": "Admin123!Secure",
        "role": "Admin",
    },
    {
        "username": "analyst",
        "email": "analyst@sentinelx.local",
        "password": "Analyst123!Secure",
        "role": "Analyst",
    },
    {
        "username": "auditor",
        "email": "auditor@sentinelx.local",
        "password": "Auditor123!Secure",
        "role": "Auditor",
    },
]

DEFAULT_ASSETS = [
    {
        "id": "server-prod-01",
        "hostname": "server-prod-01",
        "ip_address": "192.168.1.10",
        "asset_type": "server",
        "criticality": "high",
        "description": "Primary Production Application Server (Linux/Nginx)",
    },
    {
        "id": "db-prod-01",
        "hostname": "db-prod-01",
        "ip_address": "192.168.1.20",
        "asset_type": "database",
        "criticality": "critical",
        "description": "Core Production Database Cluster (PostgreSQL)",
    },
    {
        "id": "firewall-edge-01",
        "hostname": "firewall-edge-01",
        "ip_address": "192.168.1.1",
        "asset_type": "firewall",
        "criticality": "high",
        "description": "Perimeter Edge Gateway & Firewall (pfSense/OPNsense)",
    },
    {
        "id": "ws-eng-100",
        "hostname": "ws-eng-100",
        "ip_address": "192.168.1.100",
        "asset_type": "workstation",
        "criticality": "low",
        "description": "Developer Engineering Workstation (Ubuntu 24.04)",
    },
]

DEFAULT_API_KEYS = [
    {
        "name": "Default Ingestion Key",
        "raw_key": settings.INGEST_API_KEY,  # "sen_ingest_demo_key"
        "scope": "ingest",
        "asset_id": None,
    },
    {
        "name": "Server-Prod-01 Agent Key",
        "raw_key": "sen_agent_server_prod_01_key_99",
        "scope": "ingest",
        "asset_id": "server-prod-01",
    },
]


async def seed_database(reset: bool = False) -> None:
    """Seeds the database with baseline users, assets, and API keys."""
    logger.info("Initializing database schema on %s...", settings.DATABASE_URL)
    if reset:
        from backend.app.core.database import Base

        async with engine.begin() as conn:
            logger.warning("Dropping all existing database tables (--reset requested)...")
            await conn.run_sync(Base.metadata.drop_all)

    await init_db()

    async with async_session_factory() as session:
        # 1. Seed Users
        for user_data in DEFAULT_USERS:
            stmt = select(User).where(User.username == user_data["username"])
            result = await session.execute(stmt)
            existing_user = result.scalars().first()

            if not existing_user:
                new_user = User(
                    id=str(uuid.uuid4()),
                    username=user_data["username"],
                    email=user_data["email"],
                    hashed_password=hash_password(user_data["password"]),
                    role=user_data["role"],
                    is_active=True,
                )
                session.add(new_user)
                await session.flush()

                await audit_service.log_action(
                    session,
                    action="USER_CREATED",
                    resource_type="User",
                    resource_id=new_user.id,
                    user_id="system-seeder",
                    status="SUCCESS",
                    details={"username": new_user.username, "role": new_user.role},
                )
                logger.info("Seeded user '%s' (%s)", new_user.username, new_user.role)
            else:
                logger.info("User '%s' already exists, skipping", user_data["username"])

        # 2. Seed Assets
        for asset_data in DEFAULT_ASSETS:
            stmt = select(Asset).where(Asset.id == asset_data["id"])
            result = await session.execute(stmt)
            existing_asset = result.scalars().first()

            if not existing_asset:
                new_asset = Asset(
                    id=asset_data["id"],
                    hostname=asset_data["hostname"],
                    ip_address=asset_data["ip_address"],
                    asset_type=asset_data["asset_type"],
                    criticality=asset_data["criticality"],
                    description=asset_data["description"],
                )
                session.add(new_asset)
                await session.flush()

                await audit_service.log_action(
                    session,
                    action="ASSET_CREATED",
                    resource_type="Asset",
                    resource_id=new_asset.id,
                    user_id="system-seeder",
                    status="SUCCESS",
                    details={"hostname": new_asset.hostname, "ip": new_asset.ip_address},
                )
                logger.info("Seeded asset '%s' (%s)", new_asset.id, new_asset.ip_address)
            else:
                logger.info("Asset '%s' already exists, skipping", asset_data["id"])

        # 3. Seed API Keys
        for key_data in DEFAULT_API_KEYS:
            raw_key = key_data["raw_key"]
            key_hash = hash_api_key(raw_key)

            stmt = select(ApiKey).where(ApiKey.key_hash == key_hash)
            result = await session.execute(stmt)
            existing_key = result.scalars().first()

            if not existing_key:
                new_key = ApiKey(
                    id=str(uuid.uuid4()),
                    name=key_data["name"],
                    key_hash=key_hash,
                    prefix=raw_key[:8],
                    scope=key_data["scope"],
                    asset_id=key_data["asset_id"],
                    is_active=True,
                )
                session.add(new_key)
                await session.flush()

                await audit_service.log_action(
                    session,
                    action="API_KEY_CREATED",
                    resource_type="ApiKey",
                    resource_id=new_key.id,
                    user_id="system-seeder",
                    status="SUCCESS",
                    details={"name": new_key.name, "prefix": new_key.prefix},
                )
                logger.info(
                    "Seeded API Key '%s' (prefix: %s...)",
                    new_key.name,
                    new_key.prefix,
                )
            else:
                logger.info("API Key '%s' already exists, skipping", key_data["name"])

        await session.commit()

    logger.info("Database seeding successfully completed.")
    print("\n" + "=" * 60)
    print(" SentinelX Seed Configuration")
    print("=" * 60)
    print(" Users:")
    for u in DEFAULT_USERS:
        print(f"   * {u['username']:<10} | Role: {u['role']:<8} | Pass: {u['password']}")
    print("\n Monitored Assets:")
    for a in DEFAULT_ASSETS:
        print(f"   * {a['id']:<16} | IP: {a['ip_address']:<14} | Tier: {a['criticality'].upper()}")
    print("\n Ingestion API Keys:")
    for k in DEFAULT_API_KEYS:
        print(f"   * {k['name']:<28} | Key: {k['raw_key']}")
    print("=" * 60 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelX Database Seeder")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Drop and recreate all tables before seeding",
    )
    args = parser.parse_args()
    asyncio.run(seed_database(reset=args.reset))


if __name__ == "__main__":
    main()
