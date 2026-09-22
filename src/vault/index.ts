/** Vault interface (tests inject a fake) and Bitwarden CLI implementation. */

import type {
  CreateLoginInput,
  ItemFilter,
  ItemRecord,
  LoginCredential,
  PasskeyCredential,
  SecretValue,
  UpdateLoginInput,
} from "../types/domain.js";

export type {
  CreateLoginInput,
  ItemFilter,
  ItemKind,
  ItemRecord,
  LoginCredential,
  PasskeyCredential,
  SecretValue,
  UpdateLoginInput,
} from "../types/domain.js";
export { BwVault, filterItems, upsertItem } from "./bw.js";
export { generateLoginPassword } from "./password.js";

/**
 * Credential store used by HTTP routes. Implementations must not log
 * passwords, notes bodies, passkey keys, or other secret values.
 *
 * `start` / `stop` own lifecycle (unlock, catalog load, background sync).
 * Catalog reads are in-process; Vaultwarden is durability only.
 */
export type Vault = {
  start(): Promise<void>;
  stop(): Promise<void>;
  listItems(filter: ItemFilter): Promise<ItemRecord[]>;
  getItem(id: string): Promise<ItemRecord>;
  createLogin(input: CreateLoginInput): Promise<ItemRecord>;
  updateLogin(id: string, input: UpdateLoginInput): Promise<ItemRecord>;
  deleteItem(id: string): Promise<void>;
  getLogin(id: string): Promise<LoginCredential>;
  getPasskey(id: string): Promise<PasskeyCredential>;
  getSecret(id: string): Promise<SecretValue>;
};
