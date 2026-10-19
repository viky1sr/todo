-- Layer 3: user accounts (MariaDB) seed data.
-- Seed accounts: user (user@skycipher.com) and admin (admin@skycipher.com)
-- Initial default password: "correct horse battery"
-- Argon2id PHC hash (m=19456, t=2, p=1).
INSERT INTO users (username, password_hash, role)
VALUES
    ('user', '$argon2id$v=19$m=19456,t=2,p=1$AZOFoyrtTUJiLTrFhC6cQA$sc3Kelwj5+D5fVT9iUhyxp+ZztVWkaxdV6RiTnJGPjQ', 'user'),
    ('admin', '$argon2id$v=19$m=19456,t=2,p=1$AZOFoyrtTUJiLTrFhC6cQA$sc3Kelwj5+D5fVT9iUhyxp+ZztVWkaxdV6RiTnJGPjQ', 'admin')
ON DUPLICATE KEY UPDATE
    password_hash = VALUES(password_hash),
    role = VALUES(role);
