"""Alembic migration environment for Folio360 using synchronous SQLAlchemy 2.x."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from app.core.config import get_settings
from app.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _get_database_url() -> str:
    """Resolve MIGRATION_DATABASE_URL from Settings without logging or exposing credentials."""
    settings = get_settings()
    if settings.MIGRATION_DATABASE_URL is None:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL must be configured to run Alembic migrations"
        )
    database_url = settings.MIGRATION_DATABASE_URL.get_secret_value().strip()
    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL must be configured to run Alembic migrations"
        )
    return database_url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = _get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode using a synchronous NullPool engine."""
    settings = get_settings()
    url = _get_database_url()
    connectable = create_engine(
        url,
        poolclass=pool.NullPool,
        hide_parameters=True,
        connect_args={"connect_timeout": settings.DB_CONNECT_TIMEOUT},
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
