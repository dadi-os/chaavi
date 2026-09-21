/** Vault interface (tests inject a fake) and Bitwarden CLI implementation. */

import type { ItemFilter, ItemRecord, LoginCredential, SecretValue } from "../types/domain.js";

export type { ItemFilter, ItemKind, ItemRecord, LoginCredential, SecretValue } from "../types/domain.js";
export { BwVault, filterItems } from "./bw.js";

/**
 * Credential store used by HTTP routes. Implementations must not log
 * passwords, notes bodies, or other secret values.
 */
export type Vault = {
  listItems(filter: ItemFilter): Promise<ItemRecord[]>;
  getItem(id: string): Promise<ItemRecord>;
  getLogin(id: string): Promise<LoginCredential>;
  getSecret(id: string): Promise<SecretValue>;
};
