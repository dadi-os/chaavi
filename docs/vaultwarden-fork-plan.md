# Chaavi as a Vaultwarden fork: migration plan

Status: implemented (2026-10-22). Kept as the design record; the README describes the result. Where they differ, the README and the code win (for example Chaavi also falls back to a single account and to the old `BW_PASSWORD`, and serves `GET /v1/events` and the `folder` filter).

## Goal

Replace the two containers `chaavi` (TypeScript adapter + `@bitwarden/cli`) and `chaavi-vault` (upstream Vaultwarden) with one container, `chaavi`: a Vaultwarden fork that serves the Bitwarden API unchanged **and** the `/v1` API natively.

- Bitwarden clients (Arc extension, web vault, mobile) keep working exactly as today.
- Thaali and Hath keep calling `http://chaavi.dadi/v1/...` with the same request and response shapes. They do not change.
- The data volume (`chaavi_vault`) and its SQLite database are reused as-is. No data migration.

## Why this is real work, not a rename

Vaultwarden is zero-knowledge. Every item name, username, password, note, card number and key in its database is an EncString (`2.<iv>|<ciphertext>|<mac>`) encrypted on the client with a key derived from the master password. The server has no code that can read or write plaintext.

Today `bw` is the Bitwarden client that does that crypto for Chaavi. A fork has to do it itself, in Rust, inside Vaultwarden. That crypto module is the core of this plan; the rest is porting ~2,900 lines of TypeScript and rewiring Nas.

The zero-knowledge property is already given up for the agent today: Chaavi holds `BW_PASSWORD` and can decrypt everything. The fork moves that capability into the process that also serves the web vault; it does not add a new one.

## What we gain

| Today | After |
| --- | --- |
| 2 containers, 2 images, 2 volumes (`chaavi_bw`, `chaavi_vault`) | 1 container, 1 image, 1 volume |
| `bw` subprocess per call (spawn, parse stdout, match stderr strings) | Direct DB reads and in-process decrypt |
| 2 s background `bw sync` loop and an in-memory catalog that can be stale | No catalog, no loop: reads hit the DB, always current |
| Writes go out over HTTPS to Vaultwarden, then the catalog is patched | Writes go through Vaultwarden's own `update_cipher_from_data`; the extension gets a websocket push immediately |
| Needs a personal API key (`BW_CLIENTID`/`BW_CLIENTSECRET`) plus master password | Needs email + master password only |
| `chaavi` needs the mesh CA and `chaavi.dadi` host-gateway just to reach its own vault | Gone |
| Caddy splits `/v1` and `/health` to one backend and the rest to another | One upstream |

Long term, dadi code lives inside the vault: it can react to vault changes (events, websocket), add item types or fields, and expose new endpoints without a client hop.

## What it costs

- **Rust.** The rest of dadi is TypeScript/Go. The fork is Rocket + Diesel.
- **Upstream merges.** Vaultwarden releases often, frequently for client compatibility (e.g. the `pm-32009-new-item-types` flag we depend on). Every release is a merge we own. Phase 1's layout rules keep this cheap.
- **Owning Bitwarden crypto.** If Bitwarden changes formats (new EncString types, per-item key rules, key rotation), `bw` used to absorb it; now we do.
- **License.** The fork is AGPL-3.0 like Vaultwarden. Fine for private use. Implement the crypto on RustCrypto crates from Bitwarden's public docs; do not vendor Bitwarden's `sdk-internal` crates without checking their license first.

## Design

### Repo layout

The `chaavi` repo becomes a fork of `dani-garcia/vaultwarden`:

- Tag the current TypeScript tree `adapter-final` before anything changes.
- `upstream` remote = `dani-garcia/vaultwarden`. `main` = an upstream release tag + dadi commits. Merge each new release tag into `main` (no rebase; history stays honest).
- All dadi code under `src/dadi/`. Upstream files are touched only at mount points:
  - `src/main.rs`: mount `/v1` and `/health` routes; JSON log format (see Logging).
  - `Cargo.toml`: `aes`, `cbc`, `hkdf` (and whatever of `hmac`/`sha2`/`pbkdf2`/`argon2`/`ed25519-dalek`/`ssh-key` is not already a dependency).
  - Target: under ~50 changed lines outside `src/dadi/`, so upstream merges rarely conflict.
- **No dadi DB migrations.** The fork reads and writes only upstream tables. This keeps rollback (swap back to the upstream image) and upstream merges trivial.

```
src/dadi/
  mod.rs        routes() and the unlock state
  crypto.rs     KDF, key stretch, EncString decrypt/encrypt, per-item keys
  unlock.rs     find user, verify master password, hold the decrypted user key
  items.rs      cipher row <-> /v1 Item (port of cipher.ts)
  folders.rs
  secrets.rs    named Secure Notes, generate
  totp.rs, ssh.rs, password.rs
  errors.rs     { error: { type, message } } with the same codes
tests/dadi/     crypto vectors, mapping, route tests
```

### Crypto (`crypto.rs`)

Personal vault only. Each step fails loudly; nothing is skipped silently.

1. **Master key**: from `user.client_kdf_type`. PBKDF2-SHA256 (`password`, salt = lowercased email, `client_kdf_iter`) or Argon2id (salt = SHA-256 of lowercased email, iter/memory/parallelism from the user row).
2. **Verify**: master password hash = PBKDF2-SHA256(master key, password, 1); check with `user.check_valid_password`. A wrong password is `vault_unconfigured` at boot with a clear message, not a crypto error later.
3. **Stretch**: HKDF-Expand(master key, `"enc"`, 32) and (`"mac"`, 32).
4. **User key**: decrypt `user.akey` (EncString type 2) with the stretched key → 64 bytes (32 enc + 32 mac).
5. **Per-item key**: if `cipher.key` is set, decrypt it with the user key and use it for that cipher's fields; otherwise use the user key.
6. **EncString**: type 2 only (AES-256-CBC + HMAC-SHA256, MAC checked before decrypt, constant-time). Any other type → `corrupt_item` naming the item.
7. **Encrypt** for writes: fresh random IV per string, same format.

Organization ciphers: out of scope (the box has none, see Box survey). A cipher with `organization_uuid` set is a `corrupt_item` naming the item, so one appearing later fails loudly instead of vanishing.

Test vectors: export a throwaway test account's ciphers with `bw` (the current adapter) and assert the Rust module decrypts every field identically. Keep the vectors in `tests/dadi/`.

### Unlock state (`unlock.rs`)

- Env: `CHAAVI_EMAIL`, `CHAAVI_PASSWORD`. Either empty → `/health` reports `vault: "unconfigured"` and `/v1` returns `503 vault_unconfigured` naming the variable (same behaviour as today).
- At boot (after Vaultwarden's DB is up), derive and hold the user key in memory, zeroized on drop. Recompute if the user's `security_stamp` changes (password change / key rotation) and fail closed until it succeeds.
- Create (once) a `Device` row named `Chaavi` for the user, so pushes and the "devices" list show where agent writes come from.

### Reads

No catalog. `GET /v1/items` loads the user's non-deleted ciphers and folders from the DB and decrypts the public fields (names, usernames, URIs, card brand, etc.). A few hundred AES-CBC decrypts is sub-millisecond. Secret fields are decrypted only on the reveal routes, as today.

### Writes

Build the same `CipherData` the web vault would POST (encrypted strings, `encrypted_for` = user id) and call upstream `update_cipher_from_data` with `UpdateType::SyncCipherCreate` / `SyncCipherUpdate`. That reuses upstream validation, revision bumps and `nt.send_cipher_update`, so the extension sees the change at once.

- Edit keeps an existing `cipher.key` and any field we do not touch byte-for-byte (re-encrypting unchanged fields is unnecessary churn).
- Delete: `DELETE /v1/items/:id` keeps today's meaning (`bw delete item` = soft delete to trash) via the same path as upstream's `SoftSingle`.
- Folders: upstream folder model + `SyncFolderCreate/Update/Delete` pushes.
- Risk to check first: `update_cipher_from_data` takes `&Headers`, normally built by a request guard. Phase 2 confirms a `Headers` can be built for the Chaavi device; if not, call the lower-level pieces it uses directly (same three calls: apply data, save, notify).

### HTTP contract

Every route, body, status and error code in today's README stays identical:
`/v1/items` (list, create), `/v1/items/:id` (get, patch, delete), `/v1/items/:id/{reveal,totp,login,card,passkey}`, `/v1/folders` CRUD, `/v1/secrets/:name` (put) and `/reveal`, `/v1/generate`, `/health` → `{ status, vault }`.

The existing `chaavi/test/http.test.ts` cases are rewritten as a black-box contract suite (TypeScript, plain `fetch`) that runs against the built container in CI. That is the guarantee Thaali and Hath do not notice.

### Logging

Vaultwarden logs through `fern` in plain text. Patch the formatter in `main.rs` to emit the nas JSON contract (`service=chaavi`, `level`, `msg`, `code`), so Alloy's existing `chaavi` match works and the `chaavi-vault` drop rule can go. `/v1` request lines keep today's rule: method, path, `request_id`, `duration_ms`, never a secret. Upstream's own request logging stays off as today (`LOG_LEVEL`).

## Nas changes

- `chaavi.container`: image `ghcr.io/dadi-os/chaavi:latest` (the fork), volume `chaavi_vault.volume:/data`, Vaultwarden env from today's `chaavi-vault.container` (`DOMAIN`, `SIGNUPS_ALLOWED`, `ROCKET_PORT`, `EXPERIMENTAL_CLIENT_FEATURE_FLAGS`), `EnvironmentFile=/var/lib/dadi/modules/chaavi/.env`, health on `/health`. Drop the `AddHost` lines, `NODE_EXTRA_CA_CERTS`, the `ExecStartPre` CA copy and `BITWARDENCLI_APPDATA_DIR`.
- Delete `chaavi-vault.container` and `chaavi_bw.volume` (after cutover is verified; remove the volume from the box by hand).
- Caddy: both `chaavi.dadi` blocks proxy everything to the one port; the http block still redirects all but `/v1*` and `/health` to https.
- `service/chaavisettings.go`, both `ChaaviPane.qml` copies: `BW_CLIENTID`/`BW_CLIENTSECRET`/`BW_PASSWORD` → `CHAAVI_EMAIL`/`CHAAVI_PASSWORD`; update the pane text.
- `service/config.go`, `service/main.go`: drop `chaavi-vault` from module and health lists; the health URL stays `chaavi`.
- `config.alloy`: drop `chaavi-vault` from the drop list.
- `docker-compose.yml` (local dev): one `chaavi` service built from the fork's Dockerfile with `--features sqlite`.
- Thaali `SystemMap.tsx`: no change unless it shows `chaavi-vault` as a node (it lists `chaavi` only).

## Phases

1. **Fork skeleton.** Tag `adapter-final`; fork at the release the box runs (1.37.4); add `src/dadi/` with `/health` only; CI builds the alpine/sqlite image and pushes `ghcr.io/dadi-os/chaavi:fork-<sha>` (not `latest`). Done when the image runs against a copy of the box's `/data` and the extension and web vault work unchanged.
2. **Crypto + unlock.** `crypto.rs`, `unlock.rs`, test vectors from a throwaway account. Confirm the `Headers` question and whether the box has org ciphers. Done when every cipher in a copy of the real DB decrypts with no `corrupt_item`.
3. **Read routes.** List, get, reveal, totp, login, card, passkey, folders list, secret reveal, generate. Done when the contract suite's read cases pass.
4. **Parity check (shadow).** Run the fork on a *copy* of the box's DB next to the current adapter on the real one, and diff `/v1/items`, `/v1/folders` and every reveal route item by item. Done at zero diffs.
5. **Write routes.** Create/update/delete items and folders, `PUT /v1/secrets/:name`. Done when the full contract suite passes and an edit made through `/v1` appears in the Arc extension without a manual sync.
6. **Cutover.** Back up `chaavi_vault` (`/data`). Ship the Nas changes and move `latest` to the fork in one go. Watch Hath fill flows and Thaali's Chaavi page. Rollback = restore the old two quadlets and upstream image; the DB is compatible because no migration ran.
7. **Cleanup.** Remove `chaavi_bw` volume, `@bitwarden/cli`, the old CI, and update READMEs (chaavi, nas) to say Chaavi *is* the vault.

## Upstream merge routine

On each Vaultwarden release: merge the tag into `main`, run `cargo test` + the contract suite + crypto vectors, and check the release notes for client/crypto changes (new EncString types, cipher-key defaults, new item types, feature flags). Merge only through CI; `AutoUpdate=registry` then rolls it out.

## Box survey (2026-10-19)

Read-only counts from `chaavi_vault/db.sqlite3` (no field decrypted) and `dadi chaavi_list_items`:

| What | Value | Consequence |
| --- | --- | --- |
| Users | 1, KDF PBKDF2-SHA256, 600,000 iterations | PBKDF2 path is the one exercised; Argon2id stays (small) so a KDF change in the web vault does not break Chaavi |
| Organizations / org ciphers | 0 / 0 | No RSA org-key decrypt in v1 |
| Ciphers | 20 logins (1 in trash) + 1 Secure Note; 0 with a per-item `key` | Per-item keys stay supported (newer clients may start writing them) but are tested on vectors, not live data |
| EncString types | all type 2 (`name` and `akey`) | Type 2 only, as designed |
| Folders / attachments | 4 / 0 | Attachments stay out of scope |
| `/v1/items` via `dadi` | 20 (19 login, 1 note) | Matches the DB (trash excluded): the Phase 4 parity baseline |
| Schema | Diesel migration `20260902120000` | Fork starts from the release that carries this migration (1.37.4) |

The vault is small, so Phase 4's parity diff can cover every item and every reveal route.

## Decisions

- `SIGNUPS_ALLOWED=true` stays as today (Caddy keeps the vault mesh-only).
- The box stores the master password (`CHAAVI_PASSWORD` in Chaavi's module env, set once in Preferences). No derived-key-only mode.
