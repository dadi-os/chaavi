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
  }),
});

/** Parsed `config.toml` (vault timeout). */
export type FileConfig = z.infer<typeof fileSchema>;

/** Personal API key + master password used by the Bitwarden CLI. */
export type BwCredentials = {
  clientId: string;
  clientSecret: string;
  password: string;
  /** Directory for `bw` state (`BITWARDENCLI_APPDATA_DIR`). */
  appDataDir: string;
};

/** Runtime config: toml + required env (memoized by `loadConfig`). */
export type Config = {
  serviceRoot: string;
  env: {
    vaultUrl: string;
    host: string;
    port: number;
    logLevel: typeof LOG_LEVEL;
    /** Present only when BW_CLIENTID, BW_CLIENTSECRET, and BW_PASSWORD are all set. */
    bw: BwCredentials | undefined;
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
 * Load process config from config.toml and required env.
 * @throws When config.toml is invalid, VAULT_URL is missing, BW_* is partial, or
 *   BITWARDENCLI_APPDATA_DIR is missing while the vault is configured.
 */
export function loadConfig(): Config {
  if (cached) {
    return cached;
  }
  const file = loadFileConfig();
  const vaultUrl = requiredEnv("VAULT_URL");
  cached = {
    serviceRoot,
    env: {
      vaultUrl,
      host: listenHost(),
      port: listenPort(),
      logLevel: LOG_LEVEL,
      bw: loadBwCredentials(),
    },
    vault: file.vault,
  };
  return cached;
}

/** Read a required env var; empty string is missing. */
function requiredEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  return value;
}

/** Read an optional env var; empty string is unset. */
function optionalEnv(name: string): string | undefined {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    return undefined;
  }
  return value;
}

/**
 * BW_* are all empty (unconfigured) or all set. Partial credentials fail startup.
 * When configured, BITWARDENCLI_APPDATA_DIR is required.
 */
function loadBwCredentials(): BwCredentials | undefined {
  const names = ["BW_CLIENTID", "BW_CLIENTSECRET", "BW_PASSWORD"] as const;
  const present = names.filter((name) => optionalEnv(name) !== undefined);
  const missing = names.filter((name) => optionalEnv(name) === undefined);
  if (present.length === 0) {
    return undefined;
  }
  if (missing.length > 0) {
    throw new Error(
      `partial Bitwarden credentials: set ${missing.join(", ")} or clear ${present.join(", ")}`,
    );
  }
  const clientId = optionalEnv("BW_CLIENTID");
  const clientSecret = optionalEnv("BW_CLIENTSECRET");
  const password = optionalEnv("BW_PASSWORD");
  if (clientId === undefined || clientSecret === undefined || password === undefined) {
    throw new Error("partial Bitwarden credentials");
  }
  const appDataDir = optionalEnv("BITWARDENCLI_APPDATA_DIR");
  if (appDataDir === undefined) {
    throw new Error("BITWARDENCLI_APPDATA_DIR is required when the vault is configured");
  }
  return { clientId, clientSecret, password, appDataDir };
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
