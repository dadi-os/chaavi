/** Vault interface (tests inject a fake) and Bitwarden CLI implementation. */

import type {
  CreateLoginInput,
  ItemFilter,
  ItemRecord,
  LoginCredential,
  PasskeyCredential,
  SecretValue,
} from "../types/domain.js";

export type {
  CreateLoginInput,
  ItemFilter,
  ItemKind,
  ItemRecord,
  LoginCredential,
  PasskeyCredential,
  SecretValue,
} from "../types/domain.js";
export { BwVault, filterItems } from "./bw.js";
export { generateLoginPassword } from "./password.js";

/**
 * Credential store used by HTTP routes. Implementations must not log
 * passwords, notes bodies, passkey keys, or other secret values.
 */
export type Vault = {
  listItems(filter: ItemFilter): Promise<ItemRecord[]>;
  getItem(id: string): Promise<ItemRecord>;
  createLogin(input: CreateLoginInput): Promise<ItemRecord>;
  getLogin(id: string): Promise<LoginCredential>;
  getPasskey(id: string): Promise<PasskeyCredential>;
  getSecret(id: string): Promise<SecretValue>;
};
