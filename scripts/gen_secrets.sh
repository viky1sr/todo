#!/usr/bin/env bash
# Generate random secrets as owner-only files OUTSIDE the repository and write an env
# file that contains only *paths* (never secret values). Existing files are kept.
#
#   bash scripts/gen_secrets.sh            # default: ${XDG_CONFIG_HOME:-~/.config}/todo
#   TODO_CONFIG_DIR=/etc/todo bash scripts/gen_secrets.sh
#
# Load before running the binaries:  set -a; . ~/.config/todo/todo.env; set +a
set -euo pipefail
umask 077

CONFIG_DIR="${TODO_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/todo}"
SECRETS_DIR="$CONFIG_DIR/secrets"
mkdir -p "$SECRETS_DIR"
chmod 700 "$CONFIG_DIR" "$SECRETS_DIR"

hex32() { head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n'; }
token64() { head -c 48 /dev/urandom | base64 -w0 | tr '+/' '-_' | tr -d '='; }

make_secret() { # name generator
  local f="$SECRETS_DIR/$1"
  if [[ -e "$f" ]]; then
    echo "keep     $f"
  else
    "$2" > "$f"
    chmod 600 "$f"
    echo "created  $f"
  fi
}

make_secret mariadb_password hex32
make_secret postgres_password hex32
make_secret redis_password hex32
make_secret upload_key_hex hex32
make_secret pii_key_hex hex32
make_secret api_token token64

ENV_FILE="$CONFIG_DIR/todo.env"
if [[ -e "$ENV_FILE" ]]; then
  echo "keep     $ENV_FILE"
else
  cat > "$ENV_FILE" <<ENV
# todo runtime configuration: paths only, no secret values. Overrides the
# config/*.toml templates in the repository.
TODO_MARIADB_URL=mysql://todo_app@localhost/todo?socket=/run/mysqld/mysqld.sock
TODO_MARIADB_PASSWORD_FILE=$SECRETS_DIR/mariadb_password
TODO_PII_KEY_HEX_FILE=$SECRETS_DIR/pii_key_hex
TODO_UPLOAD_KEY_HEX_FILE=$SECRETS_DIR/upload_key_hex
TODO_API_TOKEN_FILE=$SECRETS_DIR/api_token
TODO_POSTGRES_URL=postgres://todo_app@127.0.0.1:5432/todo
TODO_POSTGRES_PASSWORD_FILE=$SECRETS_DIR/postgres_password
TODO_REDIS_URL=redis://127.0.0.1:6379/0
# Only when Redis has requirepass/ACL set to this value:
# TODO_REDIS_PASSWORD_FILE=$SECRETS_DIR/redis_password
ENV
  chmod 600 "$ENV_FILE"
  echo "created  $ENV_FILE"
fi
