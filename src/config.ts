/** Typed process config. The only module that reads the environment or config.toml. */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";
import { z } from "zod";
import { HOST, LOG_LEVEL, PORT } from "./constants.js";

const serviceRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const tomlPath = join(serviceRoot, "config.toml");

const fileSchema = z.object({
  vault: z.object({
    timeout_ms: z.number().int().positive(),
    sync_interval_ms: z.number().int().positive(),
  }),
});

/** Parsed `config.toml` (vault CLI timeout and background sync interval). */
export type FileConfig = z.infer<typeof fileSchema>;

/**
 * Personal API key + master password used by the Bitwarden CLI.
 * Fields may be empty; {@link missingVaultCredential} is checked on first vault use.
 */
export type BwCredentials = {
  clientId: string;
  clientSecret: string;
  password: string;
  /** Directory for `bw` state (`BITWARDENCLI_APPDATA_DIR`). */
  appDataDir: string;
};

/** Runtime config: toml + env (memoized by `loadConfig`). Empty secrets are allowed. */
export type Config = {
  serviceRoot: string;
  env: {
    /** `VAULT_URL`. Empty until the process environment sets it. */
    vaultUrl: string;
    host: string;
    port: number;
    logLevel: typeof LOG_LEVEL;
    bw: BwCredentials;
  };
  vault: FileConfig["vault"];
};

/** Read and validate `config.toml` next to the package root. */
export function loadFileConfig(): FileConfig {
  let raw: string;
  try {
    raw = readFileSync(tomlPath, "utf8");
  } catch {
    throw new Error(`missing config file: ${tomlPath}`);
  }
  const parsed = fileSchema.safeParse(parseToml(raw));
  if (!parsed.success) {
    throw new Error(`invalid config.toml: ${parsed.error.message}`);
  }
  return parsed.data;
}

let cached: Config | undefined;

/** Clear the memoized config (tests only). */
export function resetConfigCache(): void {
  cached = undefined;
}

/**
 * Load process config from config.toml and the environment.
 * Vault secrets may be empty; the process still boots. {@link missingVaultCredential}
 * names the first empty value when a route actually unlocks the vault.
 * @throws When config.toml is invalid or PORT is not a valid port.
 */
export function loadConfig(): Config {
  if (cached) {
    return cached;
  }
  const file = loadFileConfig();
  cached = {
    serviceRoot,
    env: {
      vaultUrl: envString("VAULT_URL"),
      host: listenHost(),
      port: listenPort(),
      logLevel: LOG_LEVEL,
      bw: {
        clientId: envString("BW_CLIENTID"),
        clientSecret: envString("BW_CLIENTSECRET"),
        password: envString("BW_PASSWORD"),
        appDataDir: envString("BITWARDENCLI_APPDATA_DIR"),
      },
    },
    vault: file.vault,
  };
  return cached;
}

/**
 * First empty vault env var, in unlock order.
 * Undefined when every vault value is set.
 */
export function missingVaultCredential(config: Config): string | undefined {
  const pairs: Array<[string, string]> = [
    ["VAULT_URL", config.env.vaultUrl],
    ["BW_CLIENTID", config.env.bw.clientId],
    ["BW_CLIENTSECRET", config.env.bw.clientSecret],
    ["BW_PASSWORD", config.env.bw.password],
    ["BITWARDENCLI_APPDATA_DIR", config.env.bw.appDataDir],
  ];
  for (const [name, value] of pairs) {
    if (value.length === 0) {
      return name;
    }
  }
  return undefined;
}

/** Read an env var. Unset and empty are both `""`. */
function envString(name: string): string {
  const value = process.env[name];
  if (value === undefined) {
    return "";
  }
  return value;
}

/**
 * HTTP bind host. Prod may set HOST so the listener, not a container network,
 * is the boundary around the vault adapter.
 */
function listenHost(): string {
  const value = process.env.HOST;
  if (value !== undefined && value.length > 0) {
    return value;
  }
  return HOST;
}

/** HTTP bind port. Prod may set PORT. */
function listenPort(): number {
  const value = process.env.PORT;
  if (value === undefined || value.length === 0) {
    return PORT;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`invalid PORT: ${value}`);
  }
  return parsed;
}
