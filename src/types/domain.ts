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
  /** True when a login stores a FIDO2 passkey. Always false for notes/secrets. */
  hasPasskey: boolean;
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

/**
 * Fields for `POST /v1/logins`.
 * When `password` is omitted the vault generates one (`length` / `special`).
 */
export type CreateLoginInput = {
  name: string;
  username: string;
  uri?: string | undefined;
  password?: string | undefined;
  length?: number | undefined;
  special?: boolean | undefined;
};

/**
 * Fields for `PATCH /v1/items/:id` on a login.
 * At least one field is required; omitted password leaves the stored one unchanged.
 */
export type UpdateLoginInput = {
  name?: string | undefined;
  username?: string | undefined;
  uri?: string | undefined;
  password?: string | undefined;
};

/**
 * CDP-ready passkey for a Nas browser virtual authenticator
 * (`POST /v1/items/:id/passkey`). Fields are standard base64, never logged.
 */
export type PasskeyCredential = {
  credentialId: string;
  rpId: string;
  privateKey: string;
  userHandle: string;
  signCount: number;
  resident: boolean;
};
