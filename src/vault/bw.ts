/**
 * Bitwarden CLI vault: Chaavi owns an in-memory catalog of items and folders; Vaultwarden
 * is durability. `bw` is the crypto/transport driver (unlock, sync, create, edit, delete, get).
 */

import { spawn } from "node:child_process";
import { missingVaultCredential, type Config } from "../config.js";
import { ChaaviError } from "../errors.js";
import type { Logger } from "../logging.js";
import type {
  CardCredential,
  CreateItemInput,
  Folder,
  Item,
  ItemFilter,
  LoginCredential,
  PasskeyCredential,
  RevealRequest,
  SaveSecretInput,
  SavedSecret,
  SecretValue,
  TotpCode,
  UpdateItemInput,
} from "../types/domain.js";
import type { Vault } from "./index.js";
import {
  applySecret,
  applyUpdate,
  cardFromCipher,
  cipherForCreate,
  filterItems,
  itemFromCipher,
  loginFromCipher,
  noteSecretFromCipher,
  passkeyFromCipher,
  revealFromCipher,
  secretNoteForCreate,
  totpFromCipher,
  unreachable,
  upsertItem,
  type Cipher,
} from "./cipher.js";

/** One finished `bw` process. */
export type BwExec = {
  stdout: string;
  stderr: string;
  /** Exit code; null when the process was killed on timeout. */
  code: number | null;
};

/** Runs `bw` with argv and env. Never logs stdout. */
export type BwRunner = (args: string[], env: NodeJS.ProcessEnv) => Promise<BwExec>;

/**
 * Vault backed by `@bitwarden/cli`. Catalog metadata lives in process memory and refreshes
 * on a background sync loop. Reveal paths decrypt on demand from the CLI cache; secrets are
 * never stored in the catalog.
 */
export class BwVault implements Vault {
  readonly #config: Config;
  readonly #run: BwRunner;
  readonly #log: Logger;
  #session: Promise<string> | undefined;
  #items: Item[] = [];
  #folders: Folder[] = [];
  #refresh: Promise<void> | undefined;
  #timer: ReturnType<typeof setInterval> | undefined;
  /** Serializes catalog writes so a stale sync cannot overwrite a write. */
  #catalogOp: Promise<unknown> = Promise.resolve();

  constructor(config: Config, log: Logger, run: BwRunner) {
    this.#config = config;
    this.#run = run;
    this.#log = log;
  }

  /**
   * Unlock, pull the first catalog, and start the background sync loop when vault env is
   * complete. No-op when unconfigured (health stays unconfigured).
   * @throws When vault env is set but the first sync fails.
   */
  async start(): Promise<void> {
    if (missingVaultCredential(this.#config) !== undefined) {
      return;
    }
    await this.refreshCatalog();
    this.#timer = setInterval(() => {
      void this.tick();
    }, this.#config.vault.sync_interval_ms);
  }

  /** Stop the background sync loop and wait for an in-flight refresh. */
  async stop(): Promise<void> {
    if (this.#timer !== undefined) {
      clearInterval(this.#timer);
      this.#timer = undefined;
    }
    if (this.#refresh !== undefined) {
      try {
        await this.#refresh;
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        this.#log.warn("vault sync aborted on shutdown", { code: "vault_unreachable", err: message });
      }
    }
  }

  async listItems(filter: ItemFilter): Promise<Item[]> {
    this.requireConfigured();
    return filterItems(this.#items, filter);
  }

  async getItem(id: string): Promise<Item> {
    this.requireConfigured();
    return this.catalogItem(id);
  }

  async createItem(input: CreateItemInput): Promise<Item> {
    this.requireConfigured();
    return this.#withCatalog(async () => {
      this.requireFolder(input.folderId);
      return this.writeCipher(["create", "item"], cipherForCreate(input));
    });
  }

  async updateItem(id: string, input: UpdateItemInput): Promise<Item> {
    this.requireConfigured();
    return this.#withCatalog(async () => {
      this.requireFolder(input.folderId);
      const cipher = await this.getCipher(id);
      return this.writeCipher(["edit", "item", id], applyUpdate(cipher, input));
    });
  }

  async deleteItem(id: string): Promise<void> {
    this.requireConfigured();
    return this.#withCatalog(async () => {
      this.catalogItem(id);
      await this.bw(["delete", "item", id], { session: true, notFound: true });
      this.#items = this.#items.filter((entry) => entry.id !== id);
    });
  }

  async reveal(id: string, request: RevealRequest): Promise<SecretValue> {
    return revealFromCipher(await this.getCipher(id), request);
  }

  async getTotp(id: string): Promise<TotpCode> {
    return totpFromCipher(await this.getCipher(id), Date.now());
  }

  async getLogin(id: string): Promise<LoginCredential> {
    return loginFromCipher(await this.getCipher(id));
  }

  async getCard(id: string): Promise<CardCredential> {
    return cardFromCipher(await this.getCipher(id));
  }

  async getPasskey(id: string): Promise<PasskeyCredential> {
    return passkeyFromCipher(await this.getCipher(id));
  }

  async listFolders(): Promise<Folder[]> {
    this.requireConfigured();
    return this.#folders;
  }

  async createFolder(name: string): Promise<Folder> {
    this.requireConfigured();
    return this.#withCatalog(async () => {
      const raw = await this.bw(["create", "folder", encode({ name })], { session: true });
      const folder = folderFrom(parseJson(raw));
      this.#folders = [...this.#folders, folder];
      return folder;
    });
  }

  async renameFolder(id: string, name: string): Promise<Folder> {
    this.requireConfigured();
    return this.#withCatalog(async () => {
      this.catalogFolder(id);
      const raw = await this.bw(["edit", "folder", id, encode({ name })], { session: true, notFound: true });
      const folder = folderFrom(parseJson(raw));
      this.#folders = this.#folders.map((entry) => (entry.id === id ? folder : entry));
      return folder;
    });
  }

  /** Delete a folder; Vaultwarden moves its items to no folder, and so does the catalog. */
  async deleteFolder(id: string): Promise<void> {
    this.requireConfigured();
    return this.#withCatalog(async () => {
      this.catalogFolder(id);
      await this.bw(["delete", "folder", id], { session: true, notFound: true });
      this.#folders = this.#folders.filter((entry) => entry.id !== id);
      this.#items = this.#items.map((item) => (item.folderId === id ? { ...item, folderId: null } : item));
    });
  }

  /** Create or update the Secure Note named `name` with its hidden `Secret` field set to the value. */
  async saveSecret(name: string, input: SaveSecretInput): Promise<SavedSecret> {
    this.requireConfigured();
    return this.#withCatalog(async () => {
      const existing = this.secretNotes(name);
      if (existing.length === 0) {
        const item = await this.writeCipher(["create", "item"], secretNoteForCreate(name, input.value, input.notes));
        return { item, created: true };
      }
      if (existing.length > 1) {
        throw new ChaaviError(409, "conflict", `${existing.length} secure notes are named "${name}"`);
      }
      const id = existing[0]!.id;
      const cipher = await this.getCipher(id);
      const item = await this.writeCipher(["edit", "item", id], applySecret(cipher, input.value, input.notes));
      return { item, created: false };
    });
  }

  /** The hidden `Secret` field of the one Secure Note named `name` (case-insensitive). */
  async revealSecret(name: string): Promise<SecretValue> {
    this.requireConfigured();
    const notes = this.secretNotes(name);
    if (notes.length === 0) {
      throw new ChaaviError(404, "not_found", `no secure note is named "${name}"`);
    }
    if (notes.length > 1) {
      throw new ChaaviError(409, "conflict", `${notes.length} secure notes are named "${name}"`);
    }
    return noteSecretFromCipher(await this.getCipher(notes[0]!.id));
  }

  /** Secure Notes whose name equals `name`, ignoring case. */
  secretNotes(name: string): Item[] {
    const needle = name.toLowerCase();
    return this.#items.filter((item) => item.type === "note" && item.name.toLowerCase() === needle);
  }

  /** Run a create or edit with `cipher`, then upsert the catalog with what `bw` returns. */
  async writeCipher(command: string[], cipher: Cipher): Promise<Item> {
    const raw = await this.bw([...command, encode(cipher)], { session: true, notFound: command[0] === "edit" });
    const item = itemFromCipher(asCipher(parseJson(raw)));
    this.#items = upsertItem(this.#items, item);
    return item;
  }

  catalogItem(id: string): Item {
    const item = this.#items.find((entry) => entry.id === id);
    if (item === undefined) {
      throw new ChaaviError(404, "not_found", "item not found");
    }
    return item;
  }

  catalogFolder(id: string): Folder {
    const folder = this.#folders.find((entry) => entry.id === id);
    if (folder === undefined) {
      throw new ChaaviError(404, "not_found", "folder not found");
    }
    return folder;
  }

  /** A folder id in a write body must name a catalog folder; null or absent is no folder. */
  requireFolder(folderId: string | null | undefined): void {
    if (folderId !== undefined && folderId !== null && !this.#folders.some((entry) => entry.id === folderId)) {
      throw new ChaaviError(422, "invalid_request", "folderId does not name a folder");
    }
  }

  /** Fetch one cipher by id from the CLI cache; map CLI "Not found." to 404. */
  async getCipher(id: string): Promise<Cipher> {
    this.requireConfigured();
    const raw = await this.bw(["get", "item", id], { session: true, notFound: true });
    return asCipher(parseJson(raw));
  }

  /**
   * Background tick: pull Vaultwarden into the CLI cache and replace the catalog. Failures
   * are logged; the next tick retries.
   */
  async tick(): Promise<void> {
    try {
      await this.refreshCatalog();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      this.#log.warn("vault sync failed", { code: "vault_unreachable", err: message });
    }
  }

  /**
   * Coalesced `bw sync` + list into the catalog. Concurrent callers share one in-flight
   * refresh; writes wait on the same queue.
   */
  refreshCatalog(): Promise<void> {
    if (this.#refresh === undefined) {
      this.#refresh = this.#withCatalog(() => this.pullCatalog()).finally(() => {
        this.#refresh = undefined;
      });
    }
    return this.#refresh;
  }

  /**
   * Sync from Vaultwarden and replace the in-memory catalog. A cipher that does not map to
   * an item fails the whole pull with `corrupt_item` naming it, so the catalog is never
   * missing an item silently.
   */
  async pullCatalog(): Promise<void> {
    await this.bw(["sync"], { session: true });
    const rawItems = parseJson(await this.bw(["list", "items"], { session: true }));
    const rawFolders = parseJson(await this.bw(["list", "folders"], { session: true }));
    if (!Array.isArray(rawItems) || !Array.isArray(rawFolders)) {
      throw unreachable("vault returned invalid json");
    }
    const items = rawItems.map((entry) => itemFromCipher(asCipher(entry)));
    const folders: Folder[] = [];
    for (const entry of rawFolders) {
      if (typeof entry === "object" && entry !== null && (entry as { id?: unknown }).id !== null) {
        folders.push(folderFrom(entry));
      }
    }
    this.#items = items;
    this.#folders = folders;
    this.#log.debug("vault catalog refreshed", { items: items.length, folders: folders.length });
  }

  /**
   * Run `fn` alone against the catalog so a sync cannot finish between a write and its local
   * upsert (or wipe a just-written row).
   */
  #withCatalog<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#catalogOp.then(fn, fn);
    this.#catalogOp = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  /** Throw 503 when vault env is incomplete. */
  requireConfigured(): void {
    const missing = missingVaultCredential(this.#config);
    if (missing !== undefined) {
      throw new ChaaviError(503, "vault_unconfigured", `${missing} is not set`);
    }
  }

  /**
   * Lazy `bw config` / `login --apikey` / `unlock --raw`. Concurrent callers share one
   * promise; a failed attempt is cleared so the next call retries.
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
    this.requireConfigured();
    const creds = this.#config.env.bw;
    await this.ensureServer(this.#config.env.vaultUrl);
    await this.bw(["login", "--apikey"], {
      session: false,
      extraEnv: { BW_CLIENTID: creds.clientId, BW_CLIENTSECRET: creds.clientSecret },
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
   * Point `bw` at `url`. A second start is already logged in, and `bw config server` then
   * exits with "Logout required" even when the saved URL matches.
   */
  async ensureServer(url: string): Promise<void> {
    await this.bw(["config", "server", url], { session: false, serverUnchangedOk: true });
    const current = (await this.bw(["config", "server"], { session: false })).trim();
    if (current === url) {
      return;
    }
    await this.bw(["logout"], { session: false, logoutOk: true });
    await this.bw(["config", "server", url], { session: false });
  }

  /**
   * Run `bw --nointeraction …`. Never logs stdout. Error messages omit session, password,
   * and CLI stdout.
   */
  async bw(
    args: string[],
    opts: {
      session: boolean;
      extraEnv?: NodeJS.ProcessEnv;
      notFound?: boolean;
      alreadyLoggedInOk?: boolean;
      /** `bw config server` refused because a session already exists. */
      serverUnchangedOk?: boolean;
      /** `bw logout` when no session is stored. */
      logoutOk?: boolean;
    },
  ): Promise<string> {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      ...(opts.extraEnv ?? {}),
      BITWARDENCLI_APPDATA_DIR: this.#config.env.bw.appDataDir,
    };
    const argv = ["--nointeraction", ...args];
    if (opts.session) {
      argv.push("--session", await this.session());
    }
    let result: BwExec;
    try {
      result = await this.#run(argv, env);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw unreachable(sanitize(message));
    }
    if (result.code === 0) {
      return result.stdout;
    }
    if (opts.notFound && /not found/i.test(result.stderr)) {
      throw new ChaaviError(404, "not_found", `${args[1] === "folder" ? "folder" : "item"} not found`);
    }
    if (opts.alreadyLoggedInOk && /already logged in/i.test(result.stderr)) {
      return "";
    }
    if (opts.serverUnchangedOk && /logout required before server config update/i.test(result.stderr)) {
      return "";
    }
    if (opts.logoutOk && /not logged in/i.test(result.stderr)) {
      return "";
    }
    if (result.code === null) {
      throw unreachable("vault command timed out");
    }
    throw unreachable(`vault command failed: ${sanitize(firstLine(result.stderr))}`);
  }
}

/**
 * Runner that spawns the `bw` binary with a wall-clock timeout. Stdout is returned to the
 * caller only; this helper does not log it.
 */
export function spawnBwRunner(bin: string, timeoutMs: number): BwRunner {
  return (args, env) =>
    new Promise((resolve, reject) => {
      const child = spawn(bin, args, { env, stdio: ["ignore", "pipe", "pipe"] });
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

/** Base64 JSON, the form `bw create` and `bw edit` take. */
function encode(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64");
}

/** A folder from `bw` JSON. */
function folderFrom(value: unknown): Folder {
  const raw = value as { id?: unknown; name?: unknown };
  if (typeof raw !== "object" || raw === null || typeof raw.id !== "string" || typeof raw.name !== "string") {
    throw unreachable("vault returned an invalid folder");
  }
  return { id: raw.id, name: raw.name };
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

/** First non-empty line of CLI stderr, which names why a command failed. */
function firstLine(stderr: string): string {
  const line = stderr.split("\n").find((entry) => entry.trim().length > 0);
  return line === undefined ? `exit without a message` : line.trim();
}

/** Strip session-like tokens from an error before it becomes HTTP JSON. */
function sanitize(message: string): string {
  return message.replace(/[A-Za-z0-9+/=]{20,}/g, "[redacted]");
}
