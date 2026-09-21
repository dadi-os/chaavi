import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { HOST, LOG_LEVEL, PORT } from "../src/constants.js";
import type { Config } from "../src/config.js";
import { ChaaviError } from "../src/errors.js";
import type {
  CreateLoginInput,
  ItemFilter,
  ItemRecord,
  LoginCredential,
  PasskeyCredential,
  SecretValue,
} from "../src/types/domain.js";
import { filterItems, type Vault } from "../src/vault/index.js";
import { DEFAULT_PASSWORD_LENGTH, generateLoginPassword } from "../src/vault/password.js";

const serviceRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Config for Fastify inject tests. Does not read process.env. */
export function makeConfig(): Config {
  return {
    serviceRoot,
    env: {
      vaultUrl: "http://127.0.0.1:80",
      host: HOST,
      port: PORT,
      logLevel: LOG_LEVEL,
      bw: {
        clientId: "test-client",
        clientSecret: "test-secret",
        password: "test-password",
        appDataDir: "/tmp/chaavi-test-bw",
      },
    },
    vault: { timeout_ms: 30_000, sync_interval_ms: 2_000 },
  };
}

/** In-memory vault item including secret fields used only by reveal routes. */
export type FakeItem = {
  record: ItemRecord;
  password?: string | undefined;
  notes?: string | undefined;
  secret?: string | undefined;
  passkey?: PasskeyCredential | undefined;
};

/** Injectable Vault for HTTP tests (no Bitwarden CLI / Vaultwarden). */
export class FakeVault implements Vault {
  items: FakeItem[] = [];

  seed(items: FakeItem[]): void {
    this.items = items;
  }

  async start(): Promise<void> {}

  async stop(): Promise<void> {}

  async listItems(filter: ItemFilter): Promise<ItemRecord[]> {
    return filterItems(
      this.items.map((item) => item.record),
      filter,
    );
  }

  async getItem(id: string): Promise<ItemRecord> {
    return this.find(id).record;
  }

  async createLogin(input: CreateLoginInput): Promise<ItemRecord> {
    const password = generateLoginPassword({
      length: input.length ?? DEFAULT_PASSWORD_LENGTH,
      special: input.special ?? true,
    });
    const record: ItemRecord = {
      id: randomUUID(),
      name: input.name,
      kind: "login",
      username: input.username,
      uris: input.uri !== undefined ? [input.uri] : [],
      hasPasskey: false,
    };
    this.items.push({ record, password });
    return record;
  }

  async getLogin(id: string): Promise<LoginCredential> {
    const item = this.find(id);
    if (item.record.kind !== "login") {
      throw new ChaaviError(422, "invalid_request", "item is not a login");
    }
    const password = item.password ?? "";
    if (password.length === 0) {
      throw new ChaaviError(422, "invalid_request", "item has no password");
    }
    return { username: item.record.username ?? "", password };
  }

  async getPasskey(id: string): Promise<PasskeyCredential> {
    const item = this.find(id);
    if (item.record.kind !== "login") {
      throw new ChaaviError(422, "invalid_request", "item is not a login");
    }
    if (item.passkey === undefined) {
      throw new ChaaviError(422, "invalid_request", "item has no passkey");
    }
    return item.passkey;
  }

  async getSecret(id: string): Promise<SecretValue> {
    const item = this.find(id);
    if (item.record.kind === "login") {
      const password = item.password ?? "";
      if (password.length === 0) {
        throw new ChaaviError(422, "invalid_request", "item has no secret");
      }
      return { value: password };
    }
    if (item.record.kind === "note") {
      const notes = item.notes ?? "";
      if (notes.length === 0) {
        throw new ChaaviError(422, "invalid_request", "item has no secret");
      }
      return { value: notes };
    }
    const secret = item.secret ?? "";
    if (secret.length === 0) {
      throw new ChaaviError(422, "invalid_request", "item has no single secret field");
    }
    return { value: secret };
  }

  find(id: string): FakeItem {
    const item = this.items.find((entry) => entry.record.id === id);
    if (!item) {
      throw new ChaaviError(404, "not_found", "item not found");
    }
    return item;
  }
}

export const LOGIN_ID = "11111111-1111-1111-1111-111111111111";
export const NOTE_ID = "22222222-2222-2222-2222-222222222222";
export const SSH_ID = "33333333-3333-3333-3333-333333333333";
export const PASSKEY_ID = "44444444-4444-4444-4444-444444444444";
export const MISSING_ID = "00000000-0000-0000-0000-000000000000";

export const SAMPLE_PASSKEY: PasskeyCredential = {
  credentialId: "QUJDRA==",
  rpId: "google.com",
  privateKey: "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCD/////////////////////8P/////w/////w==",
  userHandle: "dXNlcg==",
  signCount: 0,
  resident: true,
};

/** Seed catalog: one login, one note, one ssh secret, one passkey login. */
export function sampleItems(): FakeItem[] {
  return [
    {
      record: {
        id: LOGIN_ID,
        name: "GitHub",
        kind: "login",
        username: "octocat",
        uris: ["https://github.com"],
        hasPasskey: false,
      },
      password: "hunter2",
    },
    {
      record: {
        id: NOTE_ID,
        name: "Wifi",
        kind: "note",
        username: null,
        uris: [],
        hasPasskey: false,
      },
      notes: "hunter2-note",
    },
    {
      record: {
        id: SSH_ID,
        name: "Deploy key",
        kind: "secret",
        username: null,
        uris: [],
        hasPasskey: false,
      },
      secret: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
    },
    {
      record: {
        id: PASSKEY_ID,
        name: "Google",
        kind: "login",
        username: "ada@example.com",
        uris: ["https://accounts.google.com"],
        hasPasskey: true,
      },
      passkey: SAMPLE_PASSKEY,
    },
  ];
}
