# Chaavi

Credential data API for dadi. Chaavi owns the catalog and `/v1` semantics for Thaali and Hath. Vaultwarden is the encrypted store (zero-knowledge durability for the Bitwarden extension). `@bitwarden/cli` is the crypto/transport driver only — unlock, background sync, create/edit/delete, and decrypt-on-reveal. Chaavi serves every Bitwarden item type (login with websites, TOTP and passkeys; Secure Note; card; identity; SSH key; bank account; driver's license; passport), custom fields of every kind, and folders. Bank accounts, driver's licenses and passports need Vaultwarden 1.37.4+ with the `pm-32009-new-item-types` client feature flag, which Nas sets on `chaavi-vault`; the CLI refuses to create them otherwise.

Human fill in Arc uses the official Bitwarden extension at `https://chaavi.dadi`. Thaali's Chaavi page is the full password manager over this adapter. Caddy terminates TLS with a mesh-local CA (Thaali installs it on join): `/v1*` and `/health` go to Chaavi; everything else goes to Vaultwarden. This repo does not fork Vaultwarden; Nas runs unmodified upstream `vaultwarden/server:1.37.2-alpine`.

Unauthenticated; private mesh only.

## Dependencies

- Vaultwarden at `VAULT_URL` (Nas sidecar `chaavi-vault`, image `vaultwarden/server:1.37.2-alpine`)
- Nas for mesh DNS (`chaavi.dadi`), compose/prod networking, and the shared logging contract
- Bitwarden CLI (`@bitwarden/cli`) in-process — driver for sync/create/edit/delete/reveal when `BW_*` are set

Dwar operational keys stay in Nas `modules/dwar`. Agent unlock keys are Chaavi module env, not Dwar/Nas operational secrets.

## Layout

```
chaavi/
  src/
    app.ts, config.ts, logging.ts, errors.ts, constants.ts
    vault/        Vault interface; bw.ts (CLI driver + in-memory catalog); cipher.ts (cipher <-> item
                  mapping, writes, reveal); totp.ts, ssh.ts (Ed25519 generation), password.ts
    routers/      HTTP routes + schemas
    types/        domain types
  test/
  config.toml
```

## Config vs env

`config.toml` (checked in): vault `timeout_ms`, `sync_interval_ms` (background Vaultwarden pull; default 2000, so an edit made in another Bitwarden client reaches Thaali within about two seconds).

Default bind is `0.0.0.0:8080` in `src/constants.ts`. Prod may set `HOST` and `PORT` (validated; empty falls back to the constants).

| Variable | Required at boot | Notes |
| --- | --- | --- |
| `VAULT_URL` | no | Internal Vaultwarden URL. Nas injects it. Empty → `vault: "unconfigured"`. |
| `BW_CLIENTID` | no | Personal API key client id. Set in Preferences → Chaavi. |
| `BW_CLIENTSECRET` | no | Personal API key client secret. |
| `BW_PASSWORD` | no | Master password for `bw unlock`. |
| `BITWARDENCLI_APPDATA_DIR` | no | CLI state dir. Set in the image/compose. |

The process always boots. Empty or partial vault env is reported by `/health` as `vault: "unconfigured"`; `Vault.start` is a no-op and `/v1` returns `503 vault_unconfigured` naming the first empty variable. When vault env is complete, boot unlocks, runs a first sync into the in-memory catalog (fails closed if that sync fails), then refreshes on `sync_interval_ms`. Empty string counts as unset.

## Local run

```sh
cd ../nas
docker compose up chaavi chaavi-vault
docker compose run --rm chaavi npm test
```

Source is bind-mounted; edits restart in place.

## CI / CD

| Workflow | When | What |
| --- | --- | --- |
| `ci.yml` → `ci` | PR + push to `main` | Build `dev`, `npm test` in the container (`VAULT_URL` set, `BW_*` empty), build `production` |
| `ci.yml` → `publish` | `main` after `ci` | Push `ghcr.io/<owner>/chaavi:{latest,sha}` |

Concurrency cancels superseded runs on the same ref.

## Logging / error codes

Logs follow the nas JSON contract (`service=chaavi`, request summary with `request_id` / `duration_ms`, errors with `code`). Default Fastify access logging is off. Process-level boot/shutdown lines use the same JSON shape via `createLogger()`. Request lines include method and path (item id on reveal routes, the secret's name on `/v1/secrets/:name`) — never a password, TOTP key or code, notes, card number or code, identity number, private key, hidden field value, or passkey key. A cipher that does not map to an item (an unknown type, or a typed item without its type data) fails the sync with `corrupt_item` naming the item; the catalog is never silently short. Background sync failures log `vault_unreachable` and retry on the next tick.

HTTP errors: `{ "error": { "type": "<code>", "message": "..." } }`. Shared codes include `invalid_request`, `not_found`, `conflict`, `internal_error`. Domain codes include `vault_unconfigured`, `vault_unreachable`. See nas README for the shared catalog.

| Code | Status | When |
| --- | --- | --- |
| `invalid_request` | 422 | Validation; a type object or reveal field the item's type lacks; an empty secret; an unknown folder id in a write |
| `not_found` | 404 | Unknown item or folder id; no Secure Note has the secret's name |
| `conflict` | 409 | Two Secure Notes share a secret's name, or a note has two `Secret` fields |
| `corrupt_item` | 502 | A stored item is not a valid item (unknown type, or missing its type data); `message` names it |
| `vault_unconfigured` | 503 | A vault env var is empty; `message` names it |
| `vault_unreachable` | 502 | `bw` / Vaultwarden failure; `message` carries the CLI's first stderr line |
| `internal_error` | 500 | Unexpected failure |

## Vault setup

1. Sign up the first user at `https://chaavi.dadi` (Bitwarden web vault or extension). Thaali trusts the mesh CA on join. `SIGNUPS_ALLOWED` is on the Vaultwarden container, not this process.
2. Create a personal API key in the Bitwarden account.
3. Put `BW_CLIENTID`, `BW_CLIENTSECRET`, and `BW_PASSWORD` in Preferences → Chaavi on the box (writes `modules/chaavi/.env` and restarts chaavi). In compose, the same keys live in `chaavi/.env`.
4. `/health` should report `"vault": "ready"`. Thaali and Hath can call `/v1/*`.

Human fill uses `https://chaavi.dadi` (Bitwarden extension / web vault). Thaali's password manager and Hath inject use cleartext `http://chaavi.dadi/v1*` (mesh proxy).

## Routes

Items are type-aware: every item has `id`, `name`, `type` (`login` \| `note` \| `card` \| `identity` \| `sshKey` \| `bankAccount` \| `driversLicense` \| `passport`), `folderId`, `favorite`, `hasNotes`, `fields`, `revisionDate`, and one object for its type (named like the type) holding its non-secret fields and `has…` flags for its secrets. Custom fields are `text` (value), `hidden` (`hasValue` only), `boolean` (value) or `linked` (`linkedTo`, a property of that item type). List and detail never carry a secret value; the reveal routes decrypt one on demand.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/health` | `{ "status": "ok", "vault": "ready" \| "unconfigured" }`. Does not ping Vaultwarden. |
| `GET` | `/v1/items` | Catalog from memory. Query: `q` (name, username, websites, card brand/holder, identity name/email, text fields), `uri`, `type`, `folder` (a folder name, case-insensitive; it takes the folders nested under it too, since a slash in a name nests: `Dev` takes `Dev/api`; an unknown folder is a 404). |
| `GET` | `/v1/items/:id` | One item from the catalog. |
| `GET` | `/v1/events` | SSE; emits `{ type: "changed", at }` whenever the catalog's items or folders change (a write here, or a sync that pulled something new). No replay. |
| `POST` | `/v1/items` | Create any type (`201`). Body: `type`, `name`, optional `folderId`, `favorite`, `notes`, `fields`, and the type object. A login without `password` gets a generated one (`length` 12–64, default 20; `special`, default true); an SSH key without key material gets a new Ed25519 key (else give `privateKey`, `publicKey`, `keyFingerprint` together). |
| `PATCH` | `/v1/items/:id` | Change only the given keys; `""` clears an optional value; `fields` replaces the list, and a hidden field without `value` keeps its stored value; the type object must match. `{ "folderId" }` moves the item (`null` = no folder); `{ "favorite" }` stars it. |
| `DELETE` | `/v1/items/:id` | Delete any type (`204`; Vaultwarden keeps it in trash). |
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

Unknown query and body fields are a 422.
