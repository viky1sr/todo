#!/usr/bin/env bash
# One-time PostgreSQL setup for Layer 4 (object metadata): creates the login role
# `todo_app` (no superuser/createdb/createrole) and the databases `todo` and `todo_test`
# owned by it, with CONNECT revoked from PUBLIC.
#
# The password is read from the secret file and turned into a SCRAM-SHA-256 verifier
# locally (python3), so neither the password nor the verifier appears in argv/`ps`, and
# the server (and its statement log) only ever sees the verifier. SQL goes on stdin.
#
#   bash scripts/gen_secrets.sh
#   bash scripts/bootstrap_postgres.sh               # runs: psql -d postgres (needs a superuser role)
#   PSQL_ADMIN="sudo -u postgres psql" bash scripts/bootstrap_postgres.sh
#   bash scripts/bootstrap_postgres.sh --dry-run     # print SQL with the verifier masked
#
# The app connects over TCP (127.0.0.1, scram-sha-256 in the default pg_hba.conf):
#   TODO_POSTGRES_URL=postgres://todo_app@127.0.0.1:5432/todo
set -euo pipefail

CONFIG_DIR="${TODO_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/todo}"
PW_FILE="${TODO_POSTGRES_PASSWORD_FILE:-$CONFIG_DIR/secrets/postgres_password}"
ADMIN="${PSQL_ADMIN:-psql -d postgres}"

[[ -f "$PW_FILE" ]] || { echo "missing $PW_FILE (run scripts/gen_secrets.sh)" >&2; exit 1; }
if [[ "$(stat -c %a "$PW_FILE")" != 600 && "$(stat -c %a "$PW_FILE")" != 400 ]]; then
  echo "$PW_FILE must be chmod 600" >&2; exit 1
fi

scram_verifier() {
  python3 -c '
import base64, hashlib, hmac, os, sys
pw = sys.stdin.read().strip().encode()
if not pw:
    sys.exit("empty password file")
salt, it = os.urandom(16), 4096
salted = hashlib.pbkdf2_hmac("sha256", pw, salt, it)
ck = hmac.new(salted, b"Client Key", "sha256").digest()
sk = hmac.new(salted, b"Server Key", "sha256").digest()
b = lambda x: base64.b64encode(x).decode()
print(f"SCRAM-SHA-256${it}:{b(salt)}${b(hashlib.sha256(ck).digest())}:{b(sk)}")
' < "$PW_FILE"
}

sql() {
  cat <<SQL
\set ON_ERROR_STOP on
SELECT 'CREATE ROLE todo_app' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'todo_app')
\gexec
ALTER ROLE todo_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 30 PASSWORD '$1';
SELECT 'CREATE DATABASE todo OWNER todo_app ENCODING ''UTF8'' TEMPLATE template0'
  WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'todo')
\gexec
SELECT 'CREATE DATABASE todo_test OWNER todo_app ENCODING ''UTF8'' TEMPLATE template0'
  WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'todo_test')
\gexec
REVOKE ALL ON DATABASE todo FROM PUBLIC;
REVOKE ALL ON DATABASE todo_test FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE todo, todo_test TO todo_app;
SQL
}

if [[ "${1:-}" == "--dry-run" ]]; then
  sql 'SCRAM-SHA-256$4096:********'
  exit 0
fi
VERIFIER="$(scram_verifier)"
[[ "$VERIFIER" =~ ^SCRAM-SHA-256\$4096:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$ ]] \
  || { echo "could not build SCRAM verifier" >&2; exit 1; }
sql "$VERIFIER" | $ADMIN -q -X >/dev/null
unset VERIFIER
echo "PostgreSQL: role todo_app and databases todo, todo_test ready."
echo "Next: set -a; . $CONFIG_DIR/todo.env; set +a; cargo run -p todo-web"
