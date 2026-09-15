import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { HOST, LOG_LEVEL, PORT } from "../src/constants.js";
import type { Config } from "../src/config.js";
import { ChaaviError } from "../src/errors.js";
import type { ItemFilter, ItemRecord, LoginCredential, SecretValue } from "../src/types/domain.js";
import { filterItems, type Vault } from "../src/vault/index.js";

const serviceRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Config for Fastify inject tests. Does not read process.env. */
export function makeConfig(args: { configured: boolean }): Config {
  return {
    serviceRoot,
    env: {
      vaultUrl: "http://127.0.0.1:80",
      host: HOST,
      port: PORT,
      logLevel: LOG_LEVEL,
      bw: args.configured
        ? {
            clientId: "test-client",
            clientSecret: "test-secret",
            password: "test-password",
            appDataDir: "/tmp/chaavi-test-bw",
          }
        : undefined,
    },
    vault: { timeout_ms: 30_000 },
  };
}

/** In-memory vault item including secret fields used only by reveal routes. */
export type FakeItem = {
  record: ItemRecord;
  password?: string | undefined;
  notes?: string | undefined;
  secret?: string | undefined;
};

/** Injectable Vault for HTTP tests (no Bitwarden CLI / Vaultwarden). */
export class FakeVault implements Vault {
  items: FakeItem[] = [];

  seed(items: FakeItem[]): void {
    this.items = items;
  }

  async listItems(filter: ItemFilter): Promise<ItemRecord[]> {
    return filterItems(
      this.items.map((item) => item.record),
      filter,
    );
  }

  async getItem(id: string): Promise<ItemRecord> {
    return this.find(id).record;
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
export const MISSING_ID = "00000000-0000-0000-0000-000000000000";

/** Seed catalog: one login, one note, one ssh secret. */
export function sampleItems(): FakeItem[] {
  return [
    {
      record: {
        id: LOGIN_ID,
        name: "GitHub",
        kind: "login",
        username: "octocat",
        uris: ["https://github.com"],
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
      },
      secret: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
    },
  ];
}
