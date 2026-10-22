# Chaavi

dadi's credential vault. Chaavi **is** a [Vaultwarden](https://github.com/dani-garcia/vaultwarden) fork: one container that serves the Bitwarden API to the official Bitwarden clients (the Arc extension, the web vault, mobile) and dadi's own `/v1` credential API to Thaali and Hath. It replaces the earlier pair of a TypeScript adapter plus an unmodified Vaultwarden (the adapter's last commit is the `adapter-final` tag).

Vaultwarden stays zero-knowledge for everyone else. Chaavi unlocks one account for the agents the way a Bitwarden client does: it derives the key from the account's master password (`CHAAVI_PASSWORD`), decrypts what a request needs, and encrypts what a write stores. Unauthenticated; private mesh only (Caddy keeps `chaavi.dadi` off the internet).

Human fill in Arc uses the official Bitwarden extension at `https://chaavi.dadi`. Thaali's Chaavi page is the full password manager over `/v1`. Caddy terminates TLS with a mesh-local CA (Thaali installs it on join); `http://chaavi.dadi` serves `/v1*` and `/health` and redirects the rest to HTTPS (Bitwarden clients need a secure context). Both go to this one container.

Chaavi serves every Bitwarden item type (login with websites, TOTP and passkeys; Secure Note; card; identity; SSH key; bank account; driver's license; passport), custom fields of every kind, and folders. Bank accounts, driver's licenses and passports need Vaultwarden 1.37.4+ with the `pm-32009-new-item-types` client feature flag, which Nas sets on the container.

## Layout

This repo is `dani-garcia/vaultwarden` at a release tag plus dadi commits. dadi's code lives in `src/dadi/`; upstream files change only where they must (about 15 lines in `src/main.rs` and one re-export in `src/api/core/mod.rs`). There are no dadi database migrations, so the database is plain Vaultwarden's and the upstream image can always read it back.

```
src/dadi/
  mod.rs        /v1 routes, events stream, writes through upstream's update_cipher_from_data
  unlock.rs     finds the account, checks the master password, caches the user key per security stamp
  crypto.rs     master key (PBKDF2 / Argon2id), HKDF stretch, type 2 EncStrings, zeroized keys
  codec.rs      stored cipher <-> plaintext cipher JSON (item keys, URI checksums, password history)
  cipher.rs     plaintext cipher <-> /v1 items, reveals, secrets, passkeys
  schemas.rs    strict request validation (unknown keys are a 422)
  totp.rs, ssh.rs, password.rs, error.rs, log.rs
  testdata/     crypto vectors computed independently with Node
dadi-tests/     interop suite: the official Bitwarden CLI is the oracle for what /v1 reads and writes
docs/           upstream's README and the design/migration plan
```

## Config

Vaultwarden's own settings are environment variables (see `docs/vaultwarden-README.md`); Nas sets `DOMAIN`, `SIGNUPS_ALLOWED`, `ROCKET_PORT` and the `pm-32009-new-item-types` flag on the container. Chaavi's module env, edited in Preferences → Chaavi (which writes `modules/chaavi/.env` and restarts it):

| Variable | Required at boot | Notes |
| --- | --- | --- |
| `CHAAVI_EMAIL` | no | The vault account to unlock. Empty with exactly one account in the vault uses that account; with several it names this variable in a 503. |
| `CHAAVI_PASSWORD` | no | That account's master password. The adapter's old `BW_PASSWORD` is read when this is empty. |

The process always boots. Without a password `/health` reports `vault: "unconfigured"` and `/v1` returns `503 vault_unconfigured` naming the variable. An unlock key is derived on the first `/v1` call and cached until the account's security stamp changes (a password change or key rotation), when it is derived again. Empty string counts as unset.

## Vault setup

1. Sign up the first user at `https://chaavi.dadi` (`SIGNUPS_ALLOWED` is on the container).
2. Put that account's email and master password in Preferences → Chaavi on the box. In compose they live in `chaavi/.env`.
3. `/health` should report `"vault": "ready"`. Thaali and Hath can call `/v1/*`.

## Local run

```sh
cd ../nas
docker compose up chaavi
```

Compose builds `docker/Dockerfile.alpine` with SQLite only. For a plain build and the checks CI runs:

```sh
cargo test --features sqlite dadi::      # unit tests for src/dadi
cargo clippy --features sqlite --tests   # upstream builds with -D warnings
cd dadi-tests && npm ci && ./serve-local.sh &    # a throwaway vault with self-signed TLS on :8099
NODE_EXTRA_CA_CERTS=/tmp/chaavi-interop/cert.pem CHAAVI_URL=https://localhost:8099 npm test
```

## CI / CD

| Workflow | When | What |
| --- | --- | --- |
| `build.yml` (upstream) | PR + push touching source | cargo build, test, clippy, fmt on the upstream matrix |
| `chaavi.yml` → `interop` | PR + push to `main` | unit tests, a debug build, then the interop suite against it |
| `chaavi.yml` → `publish` | `main` after `interop` | builds `docker/Dockerfile.alpine` and pushes `ghcr.io/<owner>/chaavi:{latest,sha}` |
| `check-templates.yml`, `hadolint.yml` (upstream) | push / PR | Dockerfile template and lint checks |

Upstream's release, trivy, zizmor, typos and cache-cleanup workflows are removed: they publish to Vaultwarden's own registry or lint files this fork does not own.

## Taking an upstream release

```sh
tools/dadi/merge-upstream.sh 1.37.5          # a release tag
tools/dadi/merge-upstream.sh upstream/main   # or try upstream's tip before a tag exists
```

The script fetches upstream, merges it without committing, settles the conflicts that are always dadi's (`README.md` stays ours through `.gitattributes`; the upstream workflows we removed stay removed; upstream's README is refreshed into `docs/vaultwarden-README.md`), and prints:

- the **conflicts left** for you, if any;
- a **watch list**: upstream changes to the files `src/dadi` depends on (cipher and user models, notifications, auth, crypto, `main.rs`). A change there can break Chaavi without a merge conflict;
- the **cipher types upstream's write path accepts**. `src/dadi` handles types 1–8; if upstream adds a ninth (a wallet or anything else), `GET /v1/items` returns `corrupt_item` for an item of that type until `ItemType` in `schemas.rs` and `cipher.rs` learn it. That is deliberate: the list is never silently short.

Then build and test it (`cargo test --features sqlite 'dadi::'`, `cargo clippy --features sqlite --tests`, the interop suite above) and commit. `git merge --abort` backs out. A trial against upstream's tip (19 commits past 1.37.4) merged with no conflicts, built clippy-clean, passed all 65 unit tests and all 14 interop tests.

Keep dadi's changes inside `src/dadi/`; every line added elsewhere in a file Vaultwarden owns is a line a future merge can conflict with.

## Logging / error codes

Every line is a JSON object on stdout in the Nas contract (`service=chaavi`, `level`, `msg`, `time`): upstream Vaultwarden's own lines too. Each `/v1` and `/health` request logs one summary line with `request_id` / `method` / `path` / `status` / `duration_ms` and echoes `X-Request-Id`; errors add `code`. Request lines carry the path, which includes an item id on reveal routes and the secret's name on `/v1/secrets/:name` — never a password, TOTP key or code, notes, card number or code, identity number, private key, hidden field value, or passkey key. A cipher that does not decrypt, or does not map to an item (an unknown type, a typed item without its type data, an organization item), fails the list with `corrupt_item` naming the item; the list is never silently short.

HTTP errors: `{ "error": { "type": "<code>", "message": "..." } }`.

| Code | Status | When |
| --- | --- | --- |
| `invalid_request` | 422 | Validation; a type object or reveal field the item's type lacks; an empty secret; an unknown folder id in a write. A body that is not JSON is a 400. |
| `not_found` | 404 | Unknown item or folder id; no Secure Note has the secret's name; an unknown `folder` in a list query |
| `conflict` | 409 | Two Secure Notes share a secret's name, or a note has two `Secret` fields |
| `corrupt_item` | 502 | A stored item is not a valid item; `message` names it |
| `vault_unconfigured` | 503 | The password (or, with several accounts, the email) is empty; `message` names it |
| `vault_unreachable` | 502 | The account is missing, the password does not unlock it, or storage failed |
| `internal_error` | 500 | Unexpected failure |

## Routes

Items are type-aware: every item has `id`, `name`, `type` (`login` \| `note` \| `card` \| `identity` \| `sshKey` \| `bankAccount` \| `driversLicense` \| `passport`), `folderId`, `favorite`, `hasNotes`, `fields`, `revisionDate`, and one object for its type (named like the type) holding its non-secret fields and `has…` flags for its secrets. Custom fields are `text` (value), `hidden` (`hasValue` only), `boolean` (value) or `linked` (`linkedTo`, a property of that item type). List and detail never carry a secret value; the reveal routes decrypt one on demand.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/health` | `{ "status": "ok", "vault": "ready" \| "unconfigured" }`. Ready means a password and an account to unlock; it does not derive the key. |
| `GET` | `/v1/items` | Every live item, sorted by name. Query: `q` (name, username, websites, card brand/holder, identity name/email, text fields), `uri`, `type`, `folder` (a folder name, case-insensitive; it takes the folders nested under it too, since a slash in a name nests: `Dev` takes `Dev/api`; an unknown folder is a 404). |
| `GET` | `/v1/items/:id` | One item. |
| `GET` | `/v1/events` | SSE; emits `{ "type": "changed", "at" }` whenever the account's items or folders change, from `/v1` or from any Bitwarden client (the account's revision date is checked once a second). No replay. |
| `POST` | `/v1/items` | Create any type (`201`). Body: `type`, `name`, optional `folderId`, `favorite`, `notes`, `fields`, and the type object. A login without `password` gets a generated one (`length` 12–64, default 20; `special`, default true); an SSH key without key material gets a new Ed25519 key (else give `privateKey`, `publicKey`, `keyFingerprint` together). |
| `PATCH` | `/v1/items/:id` | Change only the given keys; `""` clears an optional value; `fields` replaces the list, and a hidden field without `value` keeps its stored value; the type object must match. `{ "folderId" }` moves the item (`null` = no folder); `{ "favorite" }` stars it. A changed login password or hidden field goes to the item's password history. |
| `DELETE` | `/v1/items/:id` | Move any type to the trash (`204`); Bitwarden clients can restore it. |
| `POST` | `/v1/items/:id/reveal` | `{ "field": "password" \| "totp" \| "number" \| "code" \| "ssn" \| "passportNumber" \| "licenseNumber" \| "privateKey" \| "accountNumber" \| "pin" \| "iban" \| "nationalIdentificationNumber" \| "notes" }` or `{ "field": "custom", "name" }` for a hidden field → `{ "value" }`. |
| `POST` | `/v1/items/:id/totp` | `{ "code", "period", "remaining" }` from the login's key (base32 or `otpauth://totp`). |
| `POST` | `/v1/items/:id/login` | `{ "username", "password" }` for a login fill; `username` is null when the login has none. |
| `POST` | `/v1/items/:id/card` | `{ "cardholderName", "brand", "number", "expMonth", "expYear", "code" }` for a card fill. |
| `POST` | `/v1/items/:id/passkey` | CDP-ready passkey (`credentialId`, `rpId`, `privateKey`, `userHandle`, `signCount`, `resident`). |
| `GET` | `/v1/folders` | `{ "folders": [{ "id", "name" }] }`. |
| `POST` | `/v1/folders` | `{ "name" }` → folder (`201`). |
| `PATCH` | `/v1/folders/:id` | `{ "name" }` → folder. |
| `DELETE` | `/v1/folders/:id` | `204`; its items move to no folder. |
| `PUT` | `/v1/secrets/:name` | Agent secret: create (`201`) or update (`200`) the Secure Note named `name` (case-insensitive) with `{ "value", "notes"? }` in its hidden `Secret` field; other fields stay. → `{ "item", "created" }`. |
| `POST` | `/v1/secrets/:name/reveal` | `{ "value" }` of that note's hidden `Secret` field. |
| `POST` | `/v1/generate` | `{ "length"?, "special"? }` → `{ "password" }`, not stored. |

Unknown query and body fields are a 422. Writes go through the same code path as the web vault's, so Bitwarden clients see them at once over the notification websocket. Items that belong to an organization are not read (the vault has none).
