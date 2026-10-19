# REST/Web integration contract (proposals, inspect actual routes first)

## Layers

`REST controller -> application service -> todo-zstd + todo-crypto -> todo-ipfs adapter -> persistence`, while UI consumes only validated REST models and public status. This is a **proposed** decomposition, not a claim existing Rust code uses these handlers.

Suggested versioned endpoints (adapt to actual routes):

| HTTP | Path | Result |
|---|---|---|
| POST | `/api/v1/experiments` | enqueue validated benchmark job; no arbitrary server-side commands |
| GET | `/api/v1/experiments/{id}` | environment, params, correctness, distributions, warnings |
| POST | `/api/v1/objects` | upload with bounded streaming, responds after durable authenticated commit |
| GET | `/api/v1/objects/{id}` | metadata, generation, encryption algorithm, replica states |
| GET | `/api/v1/objects/{id}/content` | stream **after AEAD verify**, with output size policy |
| GET | `/api/v1/objects/{id}/integrity` | trusted canonical root, status, proof summary |
| POST | `/api/v1/objects/{id}/verify` | authenticated request, rate-limited verification job |
| POST | `/api/v1/objects/{id}/repair` | authorized maintenance job (no direct trust in client proof) |
| GET | `/api/v1/health` | readiness without secret data |

## API safety

- Reject path traversal, arbitrary filesystem paths, oversized data, unexpectedly large decompression, invalid MIME/type claims, untrusted client-supplied shell commands and unreasonable benchmark thread counts.
- Use clear machine-readable errors (400 invalid request, 401/403 unauthorized, 404 missing, 409 generation conflict, 413 too large, 422 cryptographic/format invalid, 429 throttled, 503 backend unavailable).
- Authentication and role-based authorization for object access and repair; isolated per-tenant storage; HTTPS for transport; server-side encryption keys outside browser.
- Capture structured correlation IDs, duration and resource metrics; never log plaintext, key bytes or sensitive serialized AAD.
- Benchmark API must not mix wall-time and compute-time or present mock throughput as physical network/storage results.

## UI labels and integrity visualization

- Show Original/Compressed/Encrypted sizes, compression ratio, original-to-end-to-end MiB/s, algorithm, frame count, `polyval_segments`, Rayon threads, tag count, storage replicas, root/generation and verification result.
- Display `parallel_not_exercised` if compressed length yields <=1 POLYVAL segment.
- Display `mock` vs `live` badges/labels for IPFS and ledger distinctly; do not call an internal state machine a deployed smart contract.
- Provide version and repair event timeline; `repair` should not create a new canonical generation.
- For failed decryption/tag mismatch, show safe generic errors, not secret-specific diagnostics.

## Implemented: `crates/web` (`todo-web`)

Binary `todo-web` (`cargo run --release -p todo-web`; `WEB_HOST` default `127.0.0.1`, `WEB_PORT` default `8000`, IPFS backend via `TODO_IPFS_BACKEND`/`TODO_IPFS_URL` as in `todo-rest`). Askama templates in `crates/web/templates/`, CSS/JS in `crates/web/static/` (embedded with `include_str!`, no CDN).

| Page | Purpose |
|---|---|
| `/` | runtime config (Rayon threads, adaptive threshold, decompression bound), health, invariants, mock/live badge |
| `/pipeline` | `POST /api/v1/pipeline/verify`: sizes, ratio, frames, `polyval_segments`, plan, `parallel_not_exercised`, seq = par = upstream tag, stage times (single run); tamper demo (ciphertext/tag/AAD/nonce) |
| `/equivalence` | `POST /api/v1/verify-equivalence` (POLYVAL only, fixed test `H`) |
| `/benchmark` | `GET /api/v1/benchmark` (crypto-only); single-segment rows show `parallel_not_exercised` |
| `/storage` | `POST /api/v1/ipfs/publish` / `fetch`, root CID, manifest blocks |

`/api/v1/*` is served same-origin through `todo_rest::server::dispatch` (identical semantics to `todo-rest`). New route `POST /api/v1/pipeline/verify` (also in `todo-rest`): `data_utf8|data_hex`, `key_hex`, `nonce_hex`, optional `compression_level` (1–22), `compression_mode` (`single-frame`|`independent-frames`), `frame_size`, `segmentation` (`adaptive`|`sequential`|`fixed`), `polyval_segment_size`; returns `PipelineVerificationReport`; input ≤ 16 MiB.

Hardening: Content-Length bodies ≤ 12 MiB (413), headers ≤ 16 KiB (431), no chunked (411), 30 s read timeout, CSP `default-src 'none'` with self-only script/style (no inline), `nosniff`, `X-Frame-Options: DENY`, `no-store`; POST `/api/*` requires `application/json` and same-origin `Origin` (415/403). Tag failures are shown with a generic message; server text is rendered via `textContent`.

Limitations (demo console, not a production object service): **no authentication**; keys/nonces are generated in the browser (`crypto.getRandomValues`) and sent to the server because the current REST contract takes `key_hex`. That conflicts with "server-side keys outside browser" above, and production use needs server-side key management. Keys are never persisted in browser storage. Timings are single runs, not benchmarks. The mock backend is labelled `MOCK (in-memory, not IPFS)`.

## `crypto_mode` (selectable encryption)

Optional string field `crypto_mode` on `POST /api/v1/pipeline/process`, `/pipeline/recover`, `/pipeline/verify`, `/ipfs/publish`, `/ipfs/fetch` (default `aes-gcm-siv`; aliases such as `aegis`, `ascon`, `cascade` accepted). `GET /api/v1/crypto-modes` returns the catalog (`crypto_mode`, `id`, `description`, `authenticated`, `tag_size_bytes`, `overhead_bytes`, `parallel_polyval`, `is_default`).

- `SealedStream` JSON now carries `crypto_mode` and a variable-length `tag` (0/16/32 B). JSON without `crypto_mode` is read as `aes-gcm-siv`.
- Recover without `crypto_mode` uses the authenticated mode recorded in the stream; the unauthenticated `xchacha20` must be named explicitly (otherwise 400). A mismatch between requested and recorded mode → 400 (`CryptoModeMismatch`).
- `PipelineVerificationReport`: `aes_gcm_siv_equivalence` is `null` for non-AES modes; new fields `crypto_mode`, `authenticated`, `tag_size_bytes`, `crypto_overhead_bytes`, `deterministic_reencryption`, `tamper_rejected`; plan reason `not_applicable` for modes without POLYVAL.
- Optional `stream_chunk_size` (bytes, 1024..=2^30, non-AES only; AES-GCM-SIV → 400) on `pipeline/process`, `pipeline/verify`, `ipfs/publish`: parallel STREAM chunks, sealed stream `version` 3 with `stream_chunk_size` in JSON (field omitted otherwise). Recover reads the chunk size from the authenticated header. The catalog has `stream_chunking`. Report fields: `stream_chunk_size`, `aead_chunks`, `stream_parallel_exercised`, `chunk_transposition_rejected`, `chunk_truncation_rejected`.
- `/pipeline` page has a `crypto_mode` selector and a STREAM chunk size field; the tamper demo adds a chunk-swap case; the tamper demo reports `xchacha20` as "not authenticated" instead of PASS.

## Implemented: large-file upload `POST /api/v1/objects/upload` (`todo-rest`, also via `todo-web`)

Raw body (`Content-Type: application/octet-stream`, `Content-Length` required, no chunked/multipart), optional `X-Object-Id` (`[A-Za-z0-9._-]`). Flow (`crates/rest/src/upload.rs`): body streamed to a private temp file (0600, `O_EXCL`, unlinked immediately on Unix) → read-only `memmap2` → **one** stateful Zstd frame streamed into a second temp file → mutable `memmap2` → AES-GCM-SIV **in place, one message, one tag** (`todo_crypto::aes_gcm_siv_encrypt_in_place_planned`, adaptive POLYVAL plan from the compressed length) → sealed stream format version 1 (byte-identical to `SealedStream::to_bytes`) → `ObjectStore::put_object` (mmap passed directly, blocks hashed in 4 MiB batches) → JSON with `ipfs_cid`, `nonce_hex`, `tag_hex`, sizes, `encryption_plan`, `num_polyval_segments`, `parallel_path_exercised`, single-run timings.

Configuration: `TODO_UPLOAD_KEY_HEX` (16/32 B, server-side; unset → 503), `TODO_UPLOAD_MAX_BYTES` (default 512 MiB, max 1 GiB − 1 MiB because of the IPFS object limit), `TODO_UPLOAD_TMPDIR`, `TODO_UPLOAD_MAX_CONCURRENT` (default 2, else 429), `TODO_UPLOAD_ZSTD_LEVEL` (default 3). Idle timeout 30 s per read (408). Errors: 400/411/413/415/429/502/503 with generic messages.

Oracle (`crates/rest/tests/upload.rs`, `crates/crypto/tests/in_place_equivalence.rs`): in-place = copying = RFC 8452 vectors = upstream `aes-gcm-siv`; sealed file re-encrypted by upstream gives identical ciphertext+tag; tamper rejected; HTTP round trip via mock IPFS + `recover_pipeline`; no temp files left.

Limitations: compression is single-threaded (one frame); temp-file deletion is not secure erasure (use an encrypted volume/tmpfs); random 96-bit nonce per upload under one server key; access control see "Bearer token" below; TLS see "In-process TLS 1.3" below; recovery currently via `POST /api/v1/ipfs/fetch` with the key (in RAM, ≤ 1 GiB). Timings are single runs, not benchmarks; the mock backend proves nothing about live IPFS.

## Implemented: verified object download

`GET /api/v1/objects/{cid}?nonce=<24 hex>` (todo-rest and todo-web; enabled with the same
`TODO_UPLOAD_KEY_HEX` as upload). The nonce is not stored in the v1 format, so the client
passes the `nonce_hex` returned by upload.

Flow (`crates/rest/src/download.rs`): CID-verified IPFS blocks are streamed into a private,
unlinked temp file → `MmapMut` → v1 header/size validation → **in-place AES-GCM-SIV decrypt
of the whole message (one tag)**; on tag failure the buffer is zeroed and nothing is sent →
only then each Zstd frame is decompressed, bounded by its authenticated declared size, into
a second temp file → `200` with `Content-Length`, `Content-Disposition: attachment`,
`X-Root-Cid`, `X-Encryption-Plan`, `Server-Timing`, `nosniff`, `no-store`. No plaintext byte
is written to the socket before the tag verifies. Objects from `/api/v1/ipfs/publish`
(`aes-gcm-siv`, independent frames) are downloadable too; other crypto modes → `422`.

| Status | Meaning |
|---|---|
| 400 | invalid CID or missing/invalid nonce |
| 404 | block not in the store |
| 413 | declared plaintext size above `TODO_UPLOAD_MAX_BYTES` |
| 422 | not a v1 AES-GCM-SIV object, malformed header, or authentication failure (wrong nonce/key, tampering) |
| 429 | all upload/download permits busy |
| 502 | IPFS/CID verification failure |
| 503 | no server key configured |

The REST server sends no `Access-Control-Allow-Origin` on this route; todo-web adds its
usual CSP/frame/referrer headers. CID and nonce are not secrets; access to plaintext is
controlled only by the bearer token (next section).

## Implemented: Secure Vault page

`/vault` (todo-web, `crates/web/templates/vault.html`, `initVault` in `static/app.js`) is a
browser front-end for the two routes above; it adds no server API.

- Upload: drag-and-drop/file picker → `XMLHttpRequest` raw body (`application/octet-stream`,
  `X-Object-Id` derived from the file name) to `POST /api/v1/objects/upload` with a progress
  bar; shows CID, nonce, sizes, segment plan and single-run timings.
- Download: `fetch` `GET /api/v1/objects/{cid}?nonce=…`; on `200` the verified body is saved
  as a file (`Content-Disposition` name), on error the JSON message is shown (`422` →
  generic authentication-failure text). "Uji nonce salah" flips one nonce bit and must
  yield `422` with no plaintext.
- The CID/nonce list lives only in the tab's memory (no Web Storage), because CID + nonce
  is enough to download. The page renders disabled when no server key is configured; the
  key is never sent to the browser.
- The browser buffers the downloaded file as a `Blob` before saving it (server memory is
  still bounded by temp files).

## Implemented: bearer token for the object routes

`TODO_API_TOKEN` (32..=512 RFC 6750 `b64token` chars, e.g. `openssl rand -base64 32`)
makes `POST /api/v1/objects/upload` and `GET /api/v1/objects/{cid}` require
`Authorization: Bearer <token>` on todo-rest and todo-web (`UploadConfig::with_api_token` /
`authorize`).

- Checked before any body byte is spooled (upload) and before any block is fetched
  (download); failure → `401` + `WWW-Authenticate: Bearer`, generic message. Order:
  `503` (no key) → `401` → other validation.
- The server keeps only SHA-256(token) and compares digests in constant time; the token
  and the `Authorization` header are redacted in `Debug` and never logged.
- **Fail closed:** with `TODO_UPLOAD_KEY_HEX` but without `TODO_API_TOKEN`, both binaries
  refuse to start on a non-loopback address (`RestServiceController::check_exposure`);
  on 127.0.0.1/::1 the routes stay open for local development. An invalid token aborts start.
  The token is ignored when no upload key is set (routes are `503` anyway).
- `/vault` shows a password field when a token is required; JS keeps it in memory only and
  sends it as a header (no cookies, so no CSRF surface; the existing same-origin check
  stays). REST CORS preflight allows `Authorization`; download responses still carry no
  `Access-Control-Allow-Origin`.
- Limitations: one shared static token (no users/roles, no per-object authorization, no
  rotation without restart, no rate limiting — brute force relies on token entropy); other
  routes (`/pipeline/*`, `/ipfs/*`) are not covered because they take client keys; without
  TLS the token is visible on the network — enable in-process TLS 1.3 or use a proxy.

## Implemented: in-process TLS 1.3

`TODO_TLS_CERT` + `TODO_TLS_KEY` (PEM chain and private key; both or neither) make todo-rest
and todo-web serve HTTPS (`crates/rest/src/tls.rs`, `server::serve_with`,
`todo_web::server::serve_with`).

- rustls 0.23 with the aws-lc-rs provider (already used by `reqwest`); `ServerConfig` lists
  **only TLS 1.3**, so TLS 1.2 clients fail the handshake; ALPN `http/1.1`; no client
  certificates. Cipher suites/key exchange are the provider defaults (e.g. curl negotiated
  `TLS_AES_256_GCM_SHA384` with `X25519MLKEM768`).
- Handshake bounded by 10 s; failed handshakes are dropped silently. Responses are flushed
  and the write side shut down (TLS `close_notify`).
- todo-web adds `Strict-Transport-Security: max-age=31536000` on HTTPS responses only.
- Start fails on unreadable/empty/mismatched cert or key, or when only one variable is set;
  errors name the file, never key material. A key file readable by group/others prints a
  warning.
- Off loopback without TLS the binaries still start but print a warning (decision: warn,
  not refuse — TLS may be terminated by a reverse proxy).
- Tests: `crates/rest/tests/tls.rs` (TLS 1.3 + ALPN, 2 MiB upload/download with token
  over HTTPS, TLS 1.2-only client rejected, plain HTTP on the TLS port gets no HTTP
  response, untrusted certificate rejected, configuration errors) and the HTTPS test in
  `crates/web/tests/web_server_e2e.rs` (HSTS, same-origin upload with `https://` Origin).
  Test certificates are generated at runtime with `rcgen` (dev-dependency only).
- Limitations: certificate reload requires restart; no OCSP stapling; no HTTP→HTTPS
  redirect listener; for a real deployment use a CA-issued certificate (self-signed
  certificates only for local demos). TLS protects transport only; data at rest is
  protected by the AES-GCM-SIV object format.

## Implemented: page compression (`Content-Encoding`, `todo-web`)

- Negotiated from `Accept-Encoding` (RFC 9110 §12.5.3): highest q wins, `zstd` on ties,
  `q=0` excludes, `*` covers unlisted codings; no header → identity. Fallback `gzip`
  (`flate2`). `Vary: Accept-Encoding` on every eligible response.
- zstd encoder: `todo_zstd::content_encoding::encode_http_zstd` — one frame with content
  size + checksum, levels 1..=19 only and window ≤ 2^23 (RFC 9659 browser limit). This is
  transport compression of public bytes, separate from the sealed AEAD pipeline.
- Eligible: status 200, non-`/api/` path, HTML/CSS/JS/SVG, body ≥ 256 B, and only if the
  encoded body is smaller. Pages: zstd 3 / gzip 6 per request; embedded assets: zstd 19 /
  gzip 9, compressed once and cached. HEAD reports the encoded `Content-Length`.
- Never compressed: API JSON (may echo caller input next to secrets — BREACH length
  oracle), decrypted object downloads, error/404 pages (404 reflects the path).
- Measured locally (bytes, identity / gzip / zstd): `/` 10517 / 3514 / 3664; `/vault`
  9670 / 3347 / 3518; `app.js` 44174 / 12888 / 12246; `app.css` 28785 / 6733 / 6386.
  At page levels gzip-6 is slightly smaller than zstd-3; pages are small, so the gain is
  bandwidth on slow links, not server throughput. Tests: `crates/web/tests/compression.rs`.

## Implemented: accounts in MariaDB (Layer 3, `todo-database`)

- Crate `crates/database` (`todo-database`): `secrets`, `accounts`; migrations embedded
  from `crates/database/migrations/mariadb` (`users`: username unique, Argon2id PHC
  `password_hash`, `role` user|admin, `email_enc`/`national_id_enc` VARBINARY).
- Passwords: Argon2id v19, m = 19 MiB, t = 2, p = 1, random 128-bit salt, blocking pool;
  unknown users verified against a dummy hash (no username-existence timing signal).
  Policy: 12–128 chars, no control characters. Username `[a-z0-9._-]{3,32}`, lowercased.
- PII: `0x01 || nonce(12, random) || ct || tag(16)` with `todo_crypto` AES-256-GCM-SIV
  (sequential, one message/one tag; equal to upstream, unit-tested). AAD
  `"todo/pii/v1\0" || table || 0 || column || 0 || user_id(be64)`: a blob copied to another
  row/column fails. Key `TODO_PII_KEY_HEX(_FILE)`, must differ from the object key
  (checked at startup). Plaintext only after tag verification. Email/NIK validated.
- Secrets: every secret `X` is read from `X_FILE` (regular file, mode without group/world
  bits, ≤ 4 KiB) or `X` (dev); both set = error; values never in error messages. Applies to
  `TODO_MARIADB_PASSWORD`, `TODO_PII_KEY_HEX`, `TODO_UPLOAD_KEY_HEX`, `TODO_API_TOKEN`.
  `TODO_MARIADB_URL` must not contain a password (rejected).
- Setup: `scripts/gen_secrets.sh` (random secrets in `~/.config/todo/secrets`, 0700/0600,
  plus `todo.env` with paths only; non-secret templates `config/*.toml`),
  `scripts/bootstrap_mariadb.sh` (root via `sudo mariadb`, SQL on stdin; DBs `todo`,
  `todo_test`; user `todo_app@localhost` with DML + migration DDL on `todo`), then
  `todo-rest migrate` and `todo-rest user add` (JSON on stdin, never argv).
- Tests: unit tests in `todo-database`; live `crates/database/tests/accounts_mariadb.rs`
  (`#[ignore]`, `TODO_TEST_MARIADB_URL` must point at `todo_test`).
- Not yet: key rotation, blind index for searching by email.

## Implemented: login and sessions in Redis (Layer 2, `todo-database::sessions`, `todo-web`)

- Enabled only when both `TODO_MARIADB_URL` and `TODO_REDIS_URL` are set (one without the
  other = startup error); `todo-web` runs the MariaDB migrations at startup. Otherwise
  `/api/v1/auth/*` returns 503 and the "Akun" page explains it is disabled.
- Routes (JSON body, `Content-Type: application/json`, same-origin check like the other
  POSTs, responses `Cache-Control: no-store`, never compressed):
  `POST /api/v1/auth/login` `{"username","password"}` → `{"status":"ok","username","role"}`
  plus `Set-Cookie`; `POST /api/v1/auth/logout`; `GET /api/v1/auth/me` → username, role,
  decrypted email/NIK (only after GCM-SIV tag verification), creation times. Page `/account`.
- Cookie: only a random 256-bit ID (64 hex), no data. Over TLS
  `__Host-todo_sid=…; Path=/; HttpOnly; SameSite=Strict; Max-Age=…; Secure`; over plain
  HTTP (loopback dev) `todo_sid` without `Secure`. A login destroys the previous session
  (no fixation); logout deletes the Redis key and sends `Max-Age=0`.
- Redis: `todo:v1:sess:{sha256(token)}` (the raw token is never stored), `SET NX EX`;
  each request `GETEX … EX idle` (sliding) plus absolute-lifetime check. Defaults: idle
  30 min (`TODO_SESSION_IDLE_SECS`), absolute 12 h (`TODO_SESSION_ABSOLUTE_SECS`), both
  60..=2592000 s and idle ≤ absolute.
- Brute force: atomic `INCR` + `EXPIRE NX` counters `todo:v1:login-fail:ip:{peer}` (max 20)
  and `todo:v1:login-fail:user:{sha256(username)}` (max 5) per 15 min → 429. A success
  clears the user counter. Failure message is the same for an unknown user and a wrong
  password.
- Object routes with accounts enabled: valid session → allowed (owner = session user);
  else if `TODO_API_TOKEN` is configured → bearer token required; else 401
  `login required`. Without accounts the earlier rules apply (token or loopback only).
- Config: `TODO_REDIS_URL` (e.g. `redis://127.0.0.1:6379/0`; a password inside the URL is
  rejected), `TODO_REDIS_PASSWORD(_FILE)` for `requirepass`/ACL servers.
- Tests: `crates/database` unit tests, live `crates/database/tests/sessions_redis.rs`
  (`#[ignore]`, `TODO_TEST_REDIS_URL`), `crates/web/tests/accounts_e2e.rs` (in-memory
  directory + in-memory session store: login/me/logout, CSRF, rate limit, 503, object
  access matrix).
- Limitations: the rate-limit IP is the TCP peer (no `X-Forwarded-For` support behind a
  proxy); the local Redis has no password/ACL by default (set `requirepass` or an ACL user
  and `TODO_REDIS_PASSWORD_FILE` in production); no "log out everywhere" or MFA.

## Implemented: object metadata in PostgreSQL (Layer 4, `todo-database::objects`)

- Enabled by `TODO_POSTGRES_URL` (+ `TODO_POSTGRES_PASSWORD(_FILE)`); requires accounts
  (startup error otherwise); `todo-web` runs `migrations/postgres` at startup. A password
  inside the URL (userinfo or `?password=`) is rejected.
- Table `objects`: `owner_id` (MariaDB `users.id`; other server, so no FK), `object_id`,
  `root_cid` (unique), `backend` (`mock`/`kubo_rpc`/...), `crypto_mode`,
  `sealed_format_version`, `nonce` (12 B), `tag` (16 B), original/compressed/sealed size,
  `encryption_plan` JSONB, `created_at`. CHECK constraints mirror the application
  validation. No plaintext, no key: nonce and tag are public AEAD parameters, the object
  key stays in `TODO_UPLOAD_KEY_HEX`. `object_id` is already public in the IPFS manifest.
- Upload by a session user: `todo_rest::upload::upload_object` returns an
  `UploadReceipt`; the row is inserted after publishing, response gains `metadata_id`,
  `metadata_store`. If the insert fails → 503 `metadata store unavailable; object not
  recorded` (the ciphertext already in IPFS stays encrypted and unreferenced).
- `GET /api/v1/vault/objects` → `{"status":"ok","objects":[…]}` (owner's rows, newest
  first, max 100; `no-store`; 401 without session, 503 without catalog).
- Download by a session user: `(owner_id, canonical CID)` must exist, else 404
  `object not found for this account` (also with the correct nonce). The nonce comes from
  the row (`todo_rest::prepare_download_with`); a `nonce=` in the query takes precedence,
  which keeps the "wrong nonce → 422" demonstration. Bearer-token clients keep the
  previous behaviour (nonce in the query, no ownership; the token is an operator key).
- Vault page: with a session + catalog, the list ("Objek saya") is loaded from the server
  and "Unduh" sends no nonce; otherwise the list stays in tab memory as before.
- Setup: `scripts/bootstrap_postgres.sh` (role `todo_app` without superuser/createdb/
  createrole; DBs `todo`, `todo_test` owned by it, CONNECT revoked from PUBLIC; SCRAM
  verifier computed client-side, so the server and its logs never see the password;
  idempotent; `--dry-run`). Connection over TCP `127.0.0.1` (scram-sha-256 in
  `pg_hba.conf`); sqlx is built without TLS, so keep PostgreSQL on loopback.
- Tests: unit (`validate`, URL rules, `MemoryCatalog`), live
  `crates/database/tests/objects_postgres.rs` and `crates/web/tests/live_stack.rs`
  (Redis + PostgreSQL through the web server; `#[ignore]`), in-memory e2e
  `catalog_records_uploads_and_scopes_downloads_to_owner`.
- Limitations: no delete/unpin route; rows referring to the mock backend become
  unreachable after a restart (the mock store is in memory); no admin view of all objects.

### Unified configuration check (root binary)

- `cargo run -- --check-config` loads `config/*.toml` (or `TODO_CONFIG_TOML_DIR`) with
  environment overrides, applies `harden_process()` and prints a redacted report
  (secrets as `<redacted; file:PATH>`; exit 1 on error). Safe to show in Docker/Portainer logs.
- `TODO_ENV=production`: plain-env secret values are refused (visible via `docker inspect`
  and `/proc/PID/environ`); use `*_FILE` / `*_file` pointing to Docker secrets (mode 0400).
- Limitation: `todo-web`/`todo-rest` binaries still read their own env loaders (the root
  crate depends on them, so they cannot import this module).
