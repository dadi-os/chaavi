# Chaavi

Credential store adapter for dadi. Vaultwarden holds passwords and passkeys; this process is the HTTP adapter in front of it (`GET /health` plus `/v1/*` for Hath catalog and Dimaag inject). Human fill in Arc uses the official Bitwarden extension pointed at `https://chaavi.dadi` — Caddy terminates TLS with a mesh-local CA (Hath installs it on join) and sends non-`/v1` traffic to Vaultwarden. This repo does not fork Vaultwarden; Nas runs unmodified upstream `vaultwarden/server:1.37.2-alpine`.

Unauthenticated; private mesh only.

## Dependencies

- Vaultwarden at `VAULT_URL` (Nas sidecar `chaavi-vault`, image `vaultwarden/server:1.37.2-alpine`)
- Nas for mesh DNS (`chaavi.dadi`), compose/prod networking, and the shared logging contract
- Bitwarden CLI (`@bitwarden/cli`) in-process — decrypts for `/v1` when `BW_*` are set

Dwar operational keys stay in Nas `modules/dwar`. Agent unlock keys are Chaavi module env, not Dwar/Nas operational secrets.

## Layout

```
chaavi/
  src/
    app.ts, config.ts, logging.ts, errors.ts, constants.ts
    vault/        Vault interface + bw CLI implementation
    routers/      HTTP routes + schemas
    types/        domain types
  test/
  config.toml
```

## Config vs env

`config.toml` (checked in): vault `timeout_ms`.

Default bind is `0.0.0.0:8080` in `src/constants.ts`. Prod may set `HOST` and `PORT` (validated; empty falls back to the constants).

| Variable | Required at boot | Notes |
| --- | --- | --- |
| `VAULT_URL` | no | Internal Vaultwarden URL. Nas injects it. Empty fails on first `/v1` use. |
| `BW_CLIENTID` | no | Personal API key client id. Set in Preferences → Chaavi. |
| `BW_CLIENTSECRET` | no | Personal API key client secret. |
| `BW_PASSWORD` | no | Master password for `bw unlock`. |
| `BITWARDENCLI_APPDATA_DIR` | no | CLI state dir. Set in the image/compose. |

The process always boots. Empty or partial vault env is reported by `/health` as `vault: "unconfigured"`. The first `/v1` call returns `503 vault_unconfigured` and names the first empty variable. Empty string counts as unset.

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

Logs follow the nas JSON contract (`service=chaavi`, request summary with `request_id` / `duration_ms`, errors with `code`). Default Fastify access logging is off. Process-level boot/shutdown lines use the same JSON shape via `createLogger()`. Request lines include method and path (item id on reveal routes) — never password, totp, notes body, or secret values.

HTTP errors: `{ "error": { "type": "<code>", "message": "..." } }`. Shared codes include `invalid_request`, `not_found`, `internal_error`. Domain codes include `vault_unconfigured`, `vault_unreachable`. See nas README for the shared catalog.

| Code | Status | When |
| --- | --- | --- |
| `invalid_request` | 422 | Validation / item is not a login / no secret to reveal |
| `not_found` | 404 | Unknown item id |
| `vault_unconfigured` | 503 | A vault env var is empty; `message` names it |
| `vault_unreachable` | 502 | `bw` / Vaultwarden failure |
| `internal_error` | 500 | Unexpected failure |

## Vault setup

1. Sign up the first user at `https://chaavi.dadi` (Bitwarden web vault or extension). Hath trusts the mesh CA on join. `SIGNUPS_ALLOWED` is on the Vaultwarden container, not this process.
2. Create a personal API key in the Bitwarden account.
3. Put `BW_CLIENTID`, `BW_CLIENTSECRET`, and `BW_PASSWORD` in Preferences → Chaavi on the box (writes `modules/chaavi/.env` and restarts chaavi). In compose, the same keys live in `chaavi/.env`.
4. `/health` should report `"vault": "ready"`. Hath and Dimaag can call `/v1/*`.

Human fill uses `https://chaavi.dadi`. Hath/Dimaag catalog and inject stay on cleartext `http://chaavi.dadi/v1*` (mesh proxy).

## Routes

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/health` | `{ "status": "ok", "vault": "ready" \| "unconfigured" }`. Does not ping Vaultwarden. |
| `GET` | `/v1/items` | Catalog metadata. Query: `q`, `uri`, `kind` (`login` \| `note` \| `secret`). |
| `GET` | `/v1/items/:id` | One item's metadata. |
| `POST` | `/v1/items/:id/login` | `{ "username", "password" }` for a login item. |
| `POST` | `/v1/items/:id/secret` | `{ "value" }` — login password, note body, or a single secret field. |

Unknown query fields are a 422. List/detail never include password, totp, notes body, keys, or attachments.
