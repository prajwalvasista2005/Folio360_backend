#!/usr/bin/env bash
# Creates the least-privilege application role and restricts database/public
# schema privileges during PostgreSQL first-time container initialization.

(
  set -euo pipefail

  : "${POSTGRES_USER:?POSTGRES_USER must be set}"
  : "${POSTGRES_DB:?POSTGRES_DB must be set}"
  : "${APP_DB_USER:?APP_DB_USER must be set}"
  : "${APP_DB_PASSWORD:?APP_DB_PASSWORD must be set}"

  if [ "${APP_DB_USER}" = "${POSTGRES_USER}" ]; then
    echo "Error: APP_DB_USER must not equal POSTGRES_USER (${POSTGRES_USER})" >&2
    exit 1
  fi

  psql -v ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" \
    --no-password \
    --no-psqlrc <<'EOSQL'
\getenv app_user APP_DB_USER
\getenv app_password APP_DB_PASSWORD
\getenv target_db POSTGRES_DB

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

ALTER DATABASE :"target_db" OWNER TO :"app_user";
ALTER SCHEMA public OWNER TO :"app_user";

GRANT CONNECT, TEMPORARY ON DATABASE :"target_db" TO :"app_user";
GRANT USAGE, CREATE ON SCHEMA public TO :"app_user";
EOSQL
)
