/** Vault interface (tests inject a fake) and Bitwarden CLI implementation. */

import { ChaaviError } from "../errors.js";
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

/** Vault that rejects every call with `503 vault_unconfigured`. */
export class UnconfiguredVault implements Vault {
  async listItems(_filter: ItemFilter): Promise<ItemRecord[]> {
    throw unconfigured();
  }

  async getItem(_id: string): Promise<ItemRecord> {
    throw unconfigured();
  }

  async getLogin(_id: string): Promise<LoginCredential> {
    throw unconfigured();
  }

  async getSecret(_id: string): Promise<SecretValue> {
    throw unconfigured();
  }
}

/** `503 vault_unconfigured` when BW_* are unset. */
export function unconfigured(): ChaaviError {
  return new ChaaviError(503, "vault_unconfigured", "vault is not configured");
}
