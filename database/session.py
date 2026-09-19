"""
Async database session factory.

Usage:
    engine = make_engine(db_url)
    await init_db(engine)                    # creates tables (dev / test only)
    SessionFactory = make_session_factory(engine)

    async with SessionFactory() as session:
        repo = ScanRepository(session)
        ...

Production note: use Alembic migrations (`alembic upgrade head`) instead of
`init_db()` to evolve an existing schema. `init_db()` is for fresh environments
and tests only.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

# Import all models so SQLModel.metadata knows about them before create_all.
import database.models  # noqa: F401


def make_engine(db_url: str, echo: bool = False):
    """Create an async engine.

    For PostgreSQL:  "postgresql+asyncpg://user:pass@host/dbname"
    For SQLite:      "sqlite+aiosqlite:///./recon.db"
    For tests:       "sqlite+aiosqlite://"   (in-memory)
    """
    return create_async_engine(db_url, echo=echo, future=True)


def make_session_factory(engine):
    """Return an async session factory."""
    return sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db(engine) -> None:
    """Create all tables from SQLModel metadata. Use for dev/tests only."""
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


async def drop_db(engine) -> None:
    """Drop all tables. Tests only."""
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
