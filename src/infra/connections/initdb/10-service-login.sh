#!/usr/bin/env bash
# Runs once, on an empty database, as the owner of the schema (POSTGRES_USER).
# Creates the registry's own login without further attributes; connections-migrate
# then grants it data rights only (membership in connections_app). psql reads the
# password from the secret file itself, so it is in no variable and no argument.
set -euo pipefail
if [[ ! -s /run/secrets/connections-service-db-password ]]; then
    echo "initdb: the secret connections-service-db-password is missing or empty" >&2
    exit 1
fi
psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" <<'SQL'
\set pw `cat /run/secrets/connections-service-db-password`
CREATE ROLE connections_service LOGIN PASSWORD :'pw';
SQL
