/** Agent-facing vault record shapes. Secrets never appear on list/detail. */

/** Catalog kind for a vault item. */
export type ItemKind = "login" | "note" | "secret";

/** Optional list filters applied in-process after `bw list items`. */
export type ItemFilter = {
  q?: string | undefined;
  uri?: string | undefined;
  kind?: ItemKind | undefined;
};

/** Metadata for a vault item. Never includes password, totp, notes body, or keys. */
export type ItemRecord = {
  id: string;
  name: string;
  kind: ItemKind;
  username: string | null;
  uris: string[];
};

/** Username + password for a login item (`POST /v1/items/:id/login`). */
export type LoginCredential = {
  username: string;
  password: string;
};

/** Opaque secret value (`POST /v1/items/:id/secret`). */
export type SecretValue = {
  value: string;
};
