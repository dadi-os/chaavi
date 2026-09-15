/** Bitwarden CLI vault: lazy unlock, then list/get over `--session`. */

import { spawn } from "node:child_process";
import { join } from "node:path";
import type { Config } from "../config.js";
import { ChaaviError } from "../errors.js";
import type { ItemFilter, ItemKind, ItemRecord, LoginCredential, SecretValue } from "../types/domain.js";
import type { Vault } from "./index.js";

const CIPHER_LOGIN = 1;
const CIPHER_SECURE_NOTE = 2;
const CIPHER_SSH_KEY = 5;

/** Keep items matching list query fields (`q` / `uri` / `kind`). */
export function filterItems(items: ItemRecord[], filter: ItemFilter): ItemRecord[] {
  return items.filter((item) => {
    if (filter.kind !== undefined && item.kind !== filter.kind) {
      return false;
    }
    if (filter.uri !== undefined) {
      const needle = filter.uri.toLowerCase();
      if (!item.uris.some((uri) => uri.toLowerCase().includes(needle))) {
        return false;
      }
    }
    if (filter.q !== undefined) {
      const q = filter.q.toLowerCase();
      const nameHit = item.name.toLowerCase().includes(q);
      const userHit = item.username !== null && item.username.toLowerCase().includes(q);
      const uriHit = item.uris.some((uri) => uri.toLowerCase().includes(q));
      if (!nameHit && !userHit && !uriHit) {
        return false;
      }
    }
    return true;
  });
}

type Cipher = {
  id?: unknown;
  name?: unknown;
  type?: unknown;
  notes?: unknown;
  login?: {
    username?: unknown;
    password?: unknown;
    uris?: Array<{ uri?: unknown }>;
  };
  sshKey?: {
    privateKey?: unknown;
  };
};

type BwExec = {
  stdout: string;
  stderr: string;
  code: number | null;
};

/**
 * Vault backed by `@bitwarden/cli` (`bw`). Session is established once, on
 * first use, under a mutex. Stdout of `get item` is parsed in memory and never logged.
 */
export class BwVault implements Vault {
  readonly #config: Config;
  readonly #bin: string;
  #session: Promise<string> | undefined;

  constructor(config: Config) {
    this.#config = config;
    this.#bin = join(config.serviceRoot, "node_modules", ".bin", "bw");
  }

  async listItems(filter: ItemFilter): Promise<ItemRecord[]> {
    const raw = await this.bw(["list", "items"], { session: true });
    const parsed: unknown = parseJson(raw);
    if (!Array.isArray(parsed)) {
      throw unreachable("vault returned invalid json");
    }
    const items: ItemRecord[] = [];
    for (const entry of parsed) {
      items.push(itemRecordFromCipher(asCipher(entry)));
    }
    return filterItems(items, filter);
  }

  async getItem(id: string): Promise<ItemRecord> {
    const cipher = await this.getCipher(id);
    return itemRecordFromCipher(cipher);
  }

  async getLogin(id: string): Promise<LoginCredential> {
    const cipher = await this.getCipher(id);
    return loginFromCipher(cipher);
  }

  async getSecret(id: string): Promise<SecretValue> {
    const cipher = await this.getCipher(id);
    return secretFromCipher(cipher);
  }

  /** Fetch one cipher by id; map CLI "Not found." to 404. */
  async getCipher(id: string): Promise<Cipher> {
    const raw = await this.bw(["get", "item", id], { session: true, notFound: true });
    return asCipher(parseJson(raw));
  }

  /**
   * Lazy `bw config` / `login --apikey` / `unlock --raw`. Concurrent callers
   * share one promise; a failed attempt is cleared so the next call retries.
   */
  session(): Promise<string> {
    if (!this.#session) {
      this.#session = this.unlockOnce().catch((err: unknown) => {
        this.#session = undefined;
        throw err;
      });
    }
    return this.#session;
  }

  /** `bw config server`, `login --apikey`, `unlock --passwordenv BW_PASSWORD --raw`. */
  async unlockOnce(): Promise<string> {
    const creds = this.#config.env.bw;
    if (creds === undefined) {
      throw new ChaaviError(503, "vault_unconfigured", "vault is not configured");
    }
    await this.bw(["config", "server", this.#config.env.vaultUrl], { session: false });
    await this.bw(["login", "--apikey"], {
      session: false,
      extraEnv: {
        BW_CLIENTID: creds.clientId,
        BW_CLIENTSECRET: creds.clientSecret,
      },
      alreadyLoggedInOk: true,
    });
    const session = await this.bw(["unlock", "--passwordenv", "BW_PASSWORD", "--raw"], {
      session: false,
      extraEnv: { BW_PASSWORD: creds.password },
    });
    const trimmed = session.trim();
    if (trimmed.length === 0) {
      throw unreachable("vault unlock returned an empty session");
    }
    return trimmed;
  }

  /**
   * Run `bw --nointeraction …`. Never logs stdout. Error messages omit
   * session, password, and CLI stdout.
   */
  async bw(
    args: string[],
    opts: {
      session: boolean;
      extraEnv?: NodeJS.ProcessEnv;
      notFound?: boolean;
      alreadyLoggedInOk?: boolean;
    },
  ): Promise<string> {
    const creds = this.#config.env.bw;
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      ...(opts.extraEnv ?? {}),
    };
    if (creds !== undefined) {
      env.BITWARDENCLI_APPDATA_DIR = creds.appDataDir;
    }
    const argv = ["--nointeraction", ...args];
    if (opts.session) {
      argv.push("--session", await this.session());
    }
    let result: BwExec;
    try {
      result = await runBw(this.#bin, argv, env, this.#config.vault.timeout_ms);
    } catch (err) {
      const message = err instanceof Error ? err.message : "vault command failed";
      throw unreachable(sanitize(message));
    }
    if (result.code === 0) {
      return result.stdout;
    }
    if (opts.notFound && /not found/i.test(result.stderr)) {
      throw new ChaaviError(404, "not_found", "item not found");
    }
    if (opts.alreadyLoggedInOk && /already logged in/i.test(result.stderr)) {
      return "";
    }
    if (result.code === null) {
      throw unreachable("vault command timed out");
    }
    throw unreachable("vault command failed");
  }
}

/** Map a Bitwarden cipher to list/detail metadata (no secrets). */
export function itemRecordFromCipher(cipher: Cipher): ItemRecord {
  const id = typeof cipher.id === "string" ? cipher.id : "";
  if (id.length === 0) {
    throw unreachable("vault item missing id");
  }
  const kind = kindOf(cipher);
  const username =
    kind === "login" && typeof cipher.login?.username === "string" ? cipher.login.username : null;
  const uris = kind === "login" ? loginUris(cipher) : [];
  return {
    id,
    name: typeof cipher.name === "string" ? cipher.name : "",
    kind,
    username,
    uris,
  };
}

/** Username + password for a login cipher. */
export function loginFromCipher(cipher: Cipher): LoginCredential {
  if (numericType(cipher) !== CIPHER_LOGIN) {
    throw new ChaaviError(422, "invalid_request", "item is not a login");
  }
  const password = typeof cipher.login?.password === "string" ? cipher.login.password : "";
  if (password.length === 0) {
    throw new ChaaviError(422, "invalid_request", "item has no password");
  }
  const username = typeof cipher.login?.username === "string" ? cipher.login.username : "";
  return { username, password };
}

/**
 * Secret value: login password, secure-note notes, or a single secret field
 * (SSH private key). Other types with multiple secret fields fail.
 */
export function secretFromCipher(cipher: Cipher): SecretValue {
  const type = numericType(cipher);
  if (type === CIPHER_LOGIN) {
    const password = typeof cipher.login?.password === "string" ? cipher.login.password : "";
    if (password.length === 0) {
      throw new ChaaviError(422, "invalid_request", "item has no secret");
    }
    return { value: password };
  }
  if (type === CIPHER_SECURE_NOTE) {
    const notes = typeof cipher.notes === "string" ? cipher.notes : "";
    if (notes.length === 0) {
      throw new ChaaviError(422, "invalid_request", "item has no secret");
    }
    return { value: notes };
  }
  if (type === CIPHER_SSH_KEY) {
    const privateKey = typeof cipher.sshKey?.privateKey === "string" ? cipher.sshKey.privateKey : "";
    if (privateKey.length === 0) {
      throw new ChaaviError(422, "invalid_request", "item has no secret");
    }
    return { value: privateKey };
  }
  throw new ChaaviError(422, "invalid_request", "item has no single secret field");
}

/** Bitwarden type 1 → login, 2 → note, else secret. */
function kindOf(cipher: Cipher): ItemKind {
  const type = numericType(cipher);
  if (type === CIPHER_LOGIN) {
    return "login";
  }
  if (type === CIPHER_SECURE_NOTE) {
    return "note";
  }
  return "secret";
}

/** Coerce Bitwarden `type` (number or numeric string) to a number. */
function numericType(cipher: Cipher): number {
  return typeof cipher.type === "number" ? cipher.type : Number(cipher.type);
}

/** Collect non-empty login URI strings from a cipher. */
function loginUris(cipher: Cipher): string[] {
  const uris = cipher.login?.uris;
  if (!Array.isArray(uris)) {
    return [];
  }
  const out: string[] = [];
  for (const entry of uris) {
    if (typeof entry.uri === "string" && entry.uri.length > 0) {
      out.push(entry.uri);
    }
  }
  return out;
}

/** Narrow CLI JSON to a cipher object. */
function asCipher(value: unknown): Cipher {
  if (typeof value !== "object" || value === null) {
    throw unreachable("vault returned invalid json");
  }
  return value as Cipher;
}

/** Parse CLI stdout as JSON; map parse failures to vault_unreachable. */
function parseJson(raw: string): unknown {
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw unreachable("vault returned invalid json");
  }
}

/** Build a 502 vault_unreachable error (CLI/protocol failure). */
function unreachable(message: string): ChaaviError {
  return new ChaaviError(502, "vault_unreachable", message);
}

/** Strip session-like tokens from a spawn error before it becomes HTTP JSON. */
function sanitize(message: string): string {
  return message.replace(/[A-Za-z0-9+/=]{20,}/g, "[redacted]");
}

/**
 * Spawn `bw` with a wall-clock timeout. Stdout is returned to the caller only;
 * this helper does not log it.
 */
function runBw(
  bin: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  timeoutMs: number,
): Promise<BwExec> {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, timeoutMs);
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
  });
}
