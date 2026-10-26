"""
SentinelVAPT — Async Database Session Management
Supports PostgreSQL (when driver available) and SQLite (automatic fallback / development).
"""

import logging
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.config.settings import get_settings

logger = logging.getLogger("sentinelvapt.db")
settings = get_settings()

db_url = settings.database_url
db_url_sync = settings.database_url_sync


def _build_engines(async_url: str, sync_url: str):
    if "sqlite" in async_url:
        a_eng = create_async_engine(async_url, echo=False)
        s_eng = create_engine(sync_url, echo=False)
    else:
        a_eng = create_async_engine(
            async_url,
            echo=False,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
        )
        s_eng = create_engine(sync_url, echo=False, pool_pre_ping=True)
    return a_eng, s_eng


# Try initializing with configured URLs, fallback to sqlite if driver/connection fails
try:
    async_engine, sync_engine = _build_engines(db_url, db_url_sync)
except (ImportError, ModuleNotFoundError, Exception) as err:
    logger.warning("Database driver not available for %s (%s). Falling back to SQLite.", db_url, err)
    _sqlite_file = settings.project_root / "sentinelvapt.db"
    _sqlite_async = f"sqlite+aiosqlite:///{_sqlite_file.as_posix()}"
    _sqlite_sync = f"sqlite:///{_sqlite_file.as_posix()}"
    async_engine, sync_engine = _build_engines(_sqlite_async, _sqlite_sync)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)
SyncSessionLocal = sessionmaker(bind=sync_engine)


async def get_async_session() -> AsyncSession:
    """Dependency for FastAPI route injection."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def _sync_migrate_sqlite(sync_conn):
    """Ensure newly added columns exist in existing SQLite databases without requiring manual migration."""
    try:
        from sqlalchemy import text
        cols_result = sync_conn.execute(text("PRAGMA table_info(jobs)"))
        cols = [r[1] for r in cols_result.fetchall()]
        if cols:
            if "enabled_tools" not in cols:
                sync_conn.execute(text("ALTER TABLE jobs ADD COLUMN enabled_tools JSON DEFAULT '[]'"))
                logger.info("Auto-migrated: added 'enabled_tools' column to jobs table.")
            if "disabled_tools" not in cols:
                sync_conn.execute(text("ALTER TABLE jobs ADD COLUMN disabled_tools JSON DEFAULT '[]'"))
                logger.info("Auto-migrated: added 'disabled_tools' column to jobs table.")
            if "ai_analysis_result" not in cols:
                sync_conn.execute(text("ALTER TABLE jobs ADD COLUMN ai_analysis_result JSON"))
                logger.info("Auto-migrated: added 'ai_analysis_result' column to jobs table.")
            if "ai_orchestration_mode" not in cols:
                sync_conn.execute(text("ALTER TABLE jobs ADD COLUMN ai_orchestration_mode VARCHAR(32) DEFAULT 'ai_driven'"))
                logger.info("Auto-migrated: added 'ai_orchestration_mode' column to jobs table.")
            if "current_iteration" not in cols:
                sync_conn.execute(text("ALTER TABLE jobs ADD COLUMN current_iteration INTEGER DEFAULT 0"))
                logger.info("Auto-migrated: added 'current_iteration' column to jobs table.")
            if "max_iterations" not in cols:
                sync_conn.execute(text("ALTER TABLE jobs ADD COLUMN max_iterations INTEGER DEFAULT 20"))
                logger.info("Auto-migrated: added 'max_iterations' column to jobs table.")
    except Exception as m_err:
        logger.debug("SQLite auto-migration skipped: %s", m_err)


async def init_db():
    """Create all tables and auto-migrate missing columns. Falls back to SQLite if PostgreSQL is unavailable."""
    global async_engine, sync_engine, AsyncSessionLocal, SyncSessionLocal
    from backend.db.models import Base

    try:
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.run_sync(_sync_migrate_sqlite)
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.warning(
            "Primary database connection failed: %s. Switching to local SQLite database.",
            e,
        )
        sqlite_path = settings.project_root / "sentinelvapt.db"
        fallback_async = f"sqlite+aiosqlite:///{sqlite_path.as_posix()}"
        fallback_sync = f"sqlite:///{sqlite_path.as_posix()}"
        async_engine, sync_engine = _build_engines(fallback_async, fallback_sync)
        AsyncSessionLocal.configure(bind=async_engine)
        SyncSessionLocal.configure(bind=sync_engine)
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.run_sync(_sync_migrate_sqlite)
        logger.info("Database initialized successfully with SQLite fallback: %s", sqlite_path)
