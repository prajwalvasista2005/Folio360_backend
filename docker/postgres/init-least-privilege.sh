#!/usr/bin/env bash
# Creates separate least-privilege migrator (DDL) and application (DML-only)
# PostgreSQL roles and restricts database/public schema privileges during
# first-time container initialization.

(
  set -euo pipefail

  : "${POSTGRES_USER:?POSTGRES_USER must be set}"
  : "${POSTGRES_DB:?POSTGRES_DB must be set}"
  : "${MIGRATOR_DB_USER:?MIGRATOR_DB_USER must be set}"
  : "${MIGRATOR_DB_PASSWORD:?MIGRATOR_DB_PASSWORD must be set}"
  : "${APP_DB_USER:?APP_DB_USER must be set}"
  : "${APP_DB_PASSWORD:?APP_DB_PASSWORD must be set}"

  if [ "${MIGRATOR_DB_USER}" = "${POSTGRES_USER}" ]; then
    echo "Error: MIGRATOR_DB_USER must not equal POSTGRES_USER (${POSTGRES_USER})" >&2
    exit 1
  fi

  if [ "${APP_DB_USER}" = "${POSTGRES_USER}" ]; then
    echo "Error: APP_DB_USER must not equal POSTGRES_USER (${POSTGRES_USER})" >&2
    exit 1
  fi

  if [ "${APP_DB_USER}" = "${MIGRATOR_DB_USER}" ]; then
    echo "Error: APP_DB_USER must not equal MIGRATOR_DB_USER (${MIGRATOR_DB_USER})" >&2
    exit 1
  fi

  psql -v ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" \
    --no-password \
    --no-psqlrc <<'EOSQL'
\getenv migrator_user MIGRATOR_DB_USER
\getenv migrator_password MIGRATOR_DB_PASSWORD
\getenv app_user APP_DB_USER
\getenv app_password APP_DB_PASSWORD
\getenv target_db POSTGRES_DB

SELECT format(
  'CREATE ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION PASSWORD %L',
  :'migrator_user',
  :'migrator_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'migrator_user')
\gexec

ALTER ROLE :"migrator_user" WITH
  LOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  PASSWORD :'migrator_password';

SELECT format(
  'CREATE ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION PASSWORD %L',
  :'app_user',
  :'app_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user')
\gexec

ALTER ROLE :"app_user" WITH
  LOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  PASSWORD :'app_password';

REVOKE ALL ON DATABASE :"target_db" FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

REVOKE ALL ON DATABASE :"target_db" FROM :"app_user";
REVOKE ALL ON SCHEMA public FROM :"app_user";

ALTER DATABASE :"target_db" OWNER TO :"migrator_user";
ALTER SCHEMA public OWNER TO :"migrator_user";

GRANT CONNECT, TEMPORARY ON DATABASE :"target_db" TO :"migrator_user";
GRANT USAGE, CREATE ON SCHEMA public TO :"migrator_user";

GRANT CONNECT, TEMPORARY ON DATABASE :"target_db" TO :"app_user";
GRANT USAGE ON SCHEMA public TO :"app_user";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"app_user";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO :"app_user";

ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_user" IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_user" IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO :"app_user";
EOSQL
)
