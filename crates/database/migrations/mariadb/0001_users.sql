-- Layer 3: user accounts (MariaDB). Applied by sqlx (`todo-rest migrate` or at startup).
-- password_hash: Argon2id PHC string. *_enc: PII sealed by todo-crypto AES-256-GCM-SIV,
-- layout 0x01 || nonce(12) || ciphertext || tag(16), AAD = "todo/pii/v1" || table ||
-- column || user id, so a blob copied to another row/column fails authentication.
CREATE TABLE users (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username        VARCHAR(32)     NOT NULL,
    password_hash   VARCHAR(255)    NOT NULL,
    role            ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    email_enc       VARBINARY(512)  NULL,
    national_id_enc VARBINARY(128)  NULL,
    created_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      TIMESTAMP(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                    ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_bin;
