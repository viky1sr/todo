#!/usr/bin/env bash
# One-time MariaDB setup (needs the MariaDB root account, e.g. via sudo unix_socket):
# creates databases `todo` and `todo_test` and the least-privilege user
# 'todo_app'@'localhost' whose password is read from the secret file. SQL is sent on
# stdin, so the password never appears in argv/`ps` or shell history.
#
#   bash scripts/gen_secrets.sh
#   bash scripts/bootstrap_mariadb.sh             # runs: sudo mariadb
#   MARIADB_ADMIN="mariadb -uroot -p" bash scripts/bootstrap_mariadb.sh
#   bash scripts/bootstrap_mariadb.sh --dry-run   # print SQL with the password masked
#   bash scripts/bootstrap_mariadb.sh --seed      # initialize databases and apply user seed
set -euo pipefail

CONFIG_DIR="${TODO_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/todo}"
PW_FILE="${TODO_MARIADB_PASSWORD_FILE:-$CONFIG_DIR/secrets/mariadb_password}"
ADMIN="${MARIADB_ADMIN:-sudo mariadb}"

[[ -f "$PW_FILE" ]] || { echo "missing $PW_FILE (run scripts/gen_secrets.sh)" >&2; exit 1; }
if [[ "$(stat -c %a "$PW_FILE")" != 600 && "$(stat -c %a "$PW_FILE")" != 400 ]]; then
  echo "$PW_FILE must be chmod 600" >&2; exit 1
fi
PW="$(tr -d '\n' < "$PW_FILE")"
[[ "$PW" =~ ^[A-Za-z0-9._~-]+$ ]] || { echo "password must be [A-Za-z0-9._~-] (use gen_secrets.sh)" >&2; exit 1; }

sql() {
  cat <<SQL
CREATE DATABASE IF NOT EXISTS todo CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE IF NOT EXISTS todo_test CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER IF NOT EXISTS 'todo_app'@'localhost' IDENTIFIED BY '$1';
ALTER USER 'todo_app'@'localhost' IDENTIFIED BY '$1';
-- DML + the DDL needed by the embedded sqlx migrations; no DROP/GRANT/FILE/SUPER.
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES ON todo.* TO 'todo_app'@'localhost';
GRANT ALL PRIVILEGES ON todo_test.* TO 'todo_app'@'localhost';
FLUSH PRIVILEGES;
SQL
}

if [[ "${1:-}" == "--dry-run" ]]; then
  sql '********'
  exit 0
fi
sql "$PW" | $ADMIN
echo "MariaDB: databases todo, todo_test and user todo_app@localhost ready."
if [[ "${1:-}" == "--seed" ]]; then
  echo "Applying MariaDB user seed..."
  $ADMIN todo < crates/database/seeds/mariadb/0001_seed_users.sql
  echo "MariaDB: seed applied successfully."
fi
echo "Next: set -a; . $CONFIG_DIR/todo.env; set +a; cargo run -p todo-rest -- migrate && cargo run -p todo-rest -- seed"
