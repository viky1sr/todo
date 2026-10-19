-- Production durability: generation-aware immutable objects plus a durable upload journal.
-- Existing rows are backfilled deterministically in insertion order so repeated object_id
-- values owned by the same user become generation 1, 2, ... without breaking migration.
ALTER TABLE objects ADD COLUMN generation BIGINT;

WITH ranked AS (
    SELECT id,
           row_number() OVER (PARTITION BY owner_id, object_id ORDER BY id) AS generation
    FROM objects
)
UPDATE objects o
SET generation = ranked.generation
FROM ranked
WHERE ranked.id = o.id;

ALTER TABLE objects ALTER COLUMN generation SET NOT NULL;
ALTER TABLE objects ALTER COLUMN generation SET DEFAULT 1;
ALTER TABLE objects ADD CONSTRAINT objects_generation_positive CHECK (generation > 0);

ALTER TABLE objects
    ADD COLUMN state TEXT NOT NULL DEFAULT 'healthy'
    CHECK (state IN ('committed', 'healthy', 'degraded', 'suspect', 'corrupted', 'repairing', 'unrecoverable'));

-- Set only for journal-backed uploads. NULL preserves compatibility for historical rows
-- and explicit direct-record test/demo paths.
ALTER TABLE objects
    ADD COLUMN transaction_id TEXT
    CHECK (transaction_id IS NULL OR transaction_id ~ '^[0-9a-f]{32}$');


-- A CID identifies content, not ownership. The v1 schema made root_cid globally unique,
-- which incorrectly rejected two owners cataloguing the same content-addressed root.
ALTER TABLE objects DROP CONSTRAINT IF EXISTS objects_root_cid_key;
CREATE UNIQUE INDEX objects_owner_root_cid_key ON objects (owner_id, root_cid);

CREATE UNIQUE INDEX objects_owner_object_generation_key
    ON objects (owner_id, object_id, generation);
CREATE UNIQUE INDEX objects_transaction_id_key
    ON objects (transaction_id)
    WHERE transaction_id IS NOT NULL;

CREATE TABLE object_upload_transactions (
    transaction_id        TEXT        PRIMARY KEY CHECK (transaction_id ~ '^[0-9a-f]{32}$'),
    owner_id              BIGINT      NOT NULL CHECK (owner_id > 0),
    object_id             TEXT        NOT NULL CHECK (object_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    generation            BIGINT      NOT NULL CHECK (generation > 0),
    state                 TEXT        NOT NULL CHECK (state IN ('writing', 'publishing', 'committed', 'aborted')),

    root_cid              TEXT        CHECK (root_cid IS NULL OR root_cid ~ '^[A-Za-z0-9]{8,128}$'),
    backend               TEXT        CHECK (backend IS NULL OR backend ~ '^[a-z_]{1,32}$'),
    crypto_mode           TEXT        CHECK (crypto_mode IS NULL OR char_length(crypto_mode) BETWEEN 1 AND 32),
    sealed_format_version SMALLINT    CHECK (sealed_format_version IS NULL OR sealed_format_version > 0),
    nonce                 BYTEA       CHECK (nonce IS NULL OR octet_length(nonce) = 12),
    tag                   BYTEA       CHECK (tag IS NULL OR octet_length(tag) = 16),
    original_size         BIGINT      CHECK (original_size IS NULL OR original_size > 0),
    compressed_size       BIGINT      CHECK (compressed_size IS NULL OR compressed_size > 0),
    sealed_size           BIGINT      CHECK (sealed_size IS NULL OR sealed_size > 0),
    encryption_plan       JSONB       CHECK (encryption_plan IS NULL OR jsonb_typeof(encryption_plan) = 'object'),

    last_error            TEXT,
    started_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A WRITING row is owned while this lease is renewed by the active uploader.
    -- Recovery may abort it only after expiry; PUBLISHING is deterministic and lease-free.
    lease_expires_at      TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '60 seconds'),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT object_upload_owner_object_generation_key UNIQUE (owner_id, object_id, generation),
    CONSTRAINT object_upload_publishing_metadata_check CHECK (
        state IN ('writing', 'aborted') OR (
            root_cid IS NOT NULL AND backend IS NOT NULL AND crypto_mode IS NOT NULL AND
            sealed_format_version IS NOT NULL AND nonce IS NOT NULL AND tag IS NOT NULL AND
            original_size IS NOT NULL AND compressed_size IS NOT NULL AND sealed_size IS NOT NULL AND
            encryption_plan IS NOT NULL AND sealed_size > compressed_size
        )
    )
);

-- Only one unfinished transaction per logical object. A new generation can start after
-- the prior journal reaches COMMITTED or ABORTED.
CREATE UNIQUE INDEX object_upload_one_active_per_object
    ON object_upload_transactions (owner_id, object_id)
    WHERE state IN ('writing', 'publishing');

CREATE INDEX object_upload_recovery_idx
    ON object_upload_transactions (state, lease_expires_at, updated_at, transaction_id);
