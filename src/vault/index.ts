/** Vault interface and the Bitwarden CLI implementation. */

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

export { BwVault, spawnBwRunner, type BwExec, type BwRunner } from "./bw.js";
export { generateLoginPassword } from "./password.js";

/**
 * Credential store used by HTTP routes. Implementations must not log passwords, notes,
 * card numbers, keys, or any other secret value.
 *
 * `start` / `stop` own lifecycle (unlock, catalog load, background sync). Catalog reads are
 * in-process; Vaultwarden is durability only.
 */
export type Vault = {
  start(): Promise<void>;
  stop(): Promise<void>;
  listItems(filter: ItemFilter): Promise<Item[]>;
  getItem(id: string): Promise<Item>;
  createItem(input: CreateItemInput): Promise<Item>;
  updateItem(id: string, input: UpdateItemInput): Promise<Item>;
  deleteItem(id: string): Promise<void>;
  reveal(id: string, request: RevealRequest): Promise<SecretValue>;
  getTotp(id: string): Promise<TotpCode>;
  getLogin(id: string): Promise<LoginCredential>;
  getCard(id: string): Promise<CardCredential>;
  getPasskey(id: string): Promise<PasskeyCredential>;
  listFolders(): Promise<Folder[]>;
  createFolder(name: string): Promise<Folder>;
  renameFolder(id: string, name: string): Promise<Folder>;
  deleteFolder(id: string): Promise<void>;
  saveSecret(name: string, input: SaveSecretInput): Promise<SavedSecret>;
  revealSecret(name: string): Promise<SecretValue>;
};
