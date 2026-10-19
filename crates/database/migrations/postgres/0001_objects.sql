-- Layer 4: metadata of sealed objects stored in IPFS. Holds no plaintext and no key:
-- the nonce and tag are public AEAD parameters; the object key stays in
-- TODO_UPLOAD_KEY_HEX. owner_id refers to MariaDB users.id (different server, so no FK).
CREATE TABLE objects (
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id              BIGINT      NOT NULL CHECK (owner_id > 0),
    object_id             TEXT        NOT NULL CHECK (object_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    root_cid              TEXT        NOT NULL CHECK (root_cid ~ '^[A-Za-z0-9]{8,128}$'),
    backend               TEXT        NOT NULL CHECK (backend ~ '^[a-z_]{1,32}$'),
    crypto_mode           TEXT        NOT NULL CHECK (char_length(crypto_mode) BETWEEN 1 AND 32),
    sealed_format_version SMALLINT    NOT NULL CHECK (sealed_format_version > 0),
    nonce                 BYTEA       NOT NULL CHECK (octet_length(nonce) = 12),
    tag                   BYTEA       NOT NULL CHECK (octet_length(tag) = 16),
    original_size         BIGINT      NOT NULL CHECK (original_size > 0),
    compressed_size       BIGINT      NOT NULL CHECK (compressed_size > 0),
    sealed_size           BIGINT      NOT NULL CHECK (sealed_size > compressed_size),
    encryption_plan       JSONB       NOT NULL CHECK (jsonb_typeof(encryption_plan) = 'object'),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT objects_root_cid_key UNIQUE (root_cid)
);

CREATE INDEX objects_owner_recent_idx ON objects (owner_id, id DESC);
