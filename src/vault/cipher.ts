/**
 * Bitwarden cipher JSON (as `bw` reads and writes it) to and from Chaavi's item contract.
 * Pure: no CLI, no catalog. Secret values leave a cipher only through the reveal mappers.
 */

import { ChaaviError } from "../errors.js";
import type {
  CardCredential,
  CreateItemInput,
  CustomField,
  CustomFieldInput,
  Folder,
  Item,
  ItemFilter,
  ItemType,
  LinkedTarget,
  LoginCredential,
  LoginUri,
  PasskeyCredential,
  PasskeyInfo,
  RevealRequest,
  SecretField,
  SecretValue,
  SshKeyInput,
  TotpCode,
  UpdateItemInput,
  UriMatch,
} from "../types/domain.js";
import { DEFAULT_PASSWORD_LENGTH, generateLoginPassword } from "./password.js";
import { generateSshKey } from "./ssh.js";
import { totpCode } from "./totp.js";

/** Name of the hidden field that holds an agent secret on its Secure Note. */
export const SECRET_FIELD = "Secret";

const TYPE_CODES: Record<ItemType, number> = {
  login: 1,
  note: 2,
  card: 3,
  identity: 4,
  sshKey: 5,
  bankAccount: 6,
  driversLicense: 7,
  passport: 8,
};

/** An item type whose data is a flat object of strings, each public or secret. */
type TextType = "card" | "identity" | "bankAccount" | "driversLicense" | "passport";

/**
 * The string fields of each flat item type as Bitwarden names them: `public` are listed
 * as values, `secret` only as `has…` flags and decrypted one at a time.
 */
const TEXT_FIELDS: Record<TextType, { public: readonly string[]; secret: readonly SecretField[] }> = {
  card: { public: ["cardholderName", "brand", "expMonth", "expYear"], secret: ["number", "code"] },
  identity: {
    public: [
      "title",
      "firstName",
      "middleName",
      "lastName",
      "address1",
      "address2",
      "address3",
      "city",
      "state",
      "postalCode",
      "country",
      "company",
      "email",
      "phone",
      "username",
    ],
    secret: ["ssn", "passportNumber", "licenseNumber"],
  },
  bankAccount: {
    public: ["bankName", "nameOnAccount", "accountType", "routingNumber", "branchNumber", "swiftCode", "bankContactPhone"],
    secret: ["accountNumber", "pin", "iban"],
  },
  driversLicense: {
    public: [
      "firstName",
      "middleName",
      "lastName",
      "dateOfBirth",
      "issuingCountry",
      "issuingState",
      "issueDate",
      "expirationDate",
      "issuingAuthority",
      "licenseClass",
    ],
    secret: ["licenseNumber"],
  },
  passport: {
    public: [
      "surname",
      "givenName",
      "dateOfBirth",
      "sex",
      "birthPlace",
      "nationality",
      "issuingCountry",
      "passportType",
      "issuingAuthority",
      "issueDate",
      "expirationDate",
    ],
    secret: ["passportNumber", "nationalIdentificationNumber"],
  },
};

const FIELD_TEXT = 0;
const FIELD_HIDDEN = 1;
const FIELD_BOOLEAN = 2;
const FIELD_LINKED = 3;

const MATCH_CODES: Record<Exclude<UriMatch, "default">, number> = {
  domain: 0,
  host: 1,
  startsWith: 2,
  exact: 3,
  regex: 4,
  never: 5,
};

/**
 * Bitwarden's linked-field ids per item type (`LoginLinkedId`, `CardLinkedId`,
 * `IdentityLinkedId`). The newer types define none.
 */
const LINKED_IDS: Record<ItemType, Partial<Record<LinkedTarget, number>>> = {
  login: { username: 100, password: 101 },
  card: { cardholderName: 300, expMonth: 301, expYear: 302, code: 303, brand: 304, number: 305 },
  identity: {
    title: 400,
    middleName: 401,
    address1: 402,
    address2: 403,
    address3: 404,
    city: 405,
    state: 406,
    postalCode: 407,
    country: 408,
    company: 409,
    email: 410,
    phone: 411,
    ssn: 412,
    username: 413,
    passportNumber: 414,
    licenseNumber: 415,
    firstName: 416,
    lastName: 417,
    fullName: 418,
  },
  note: {},
  sshKey: {},
  bankAccount: {},
  driversLicense: {},
  passport: {},
};

/** A custom field as `bw` stores it. */
export type RawField = {
  name?: unknown;
  value?: unknown;
  type?: unknown;
  linkedId?: unknown;
};

/** A cipher as `bw` reads and writes it. Unknown keys round-trip on edit. */
export type Cipher = {
  id?: unknown;
  name?: unknown;
  type?: unknown;
  notes?: unknown;
  folderId?: unknown;
  favorite?: unknown;
  revisionDate?: unknown;
  fields?: unknown;
  login?: {
    username?: unknown;
    password?: unknown;
    totp?: unknown;
    uris?: unknown;
    fido2Credentials?: unknown;
    [key: string]: unknown;
  } | null;
  [key: string]: unknown;
};

/** Item type of a cipher. Bitwarden has no type outside 1–8, so another is a corrupt item. */
export function itemTypeOf(cipher: Cipher): ItemType {
  const code = typeof cipher.type === "number" ? cipher.type : Number(cipher.type);
  for (const [type, value] of Object.entries(TYPE_CODES)) {
    if (value === code) {
      return type as ItemType;
    }
  }
  throw corrupt(cipher, `has unknown type ${String(cipher.type)}`);
}

/**
 * The object holding a typed item's own data (`login`, `card`, …). Its absence on an item
 * of that type is a corrupt item, never an empty one.
 */
function typeData(cipher: Cipher, key: Exclude<ItemType, "note">): Record<string, unknown> {
  const data = cipher[key];
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw corrupt(cipher, `is a ${key} item without its ${key} data`);
  }
  return data as Record<string, unknown>;
}

/** `has` + the field name with its first letter raised: `accountNumber` → `hasAccountNumber`. */
function hasKey(field: string): string {
  return `has${field[0]!.toUpperCase()}${field.slice(1)}`;
}

/** Map a cipher to its listed item: every non-secret field, and only flags for secrets. */
export function itemFromCipher(cipher: Cipher): Item {
  const id = text(cipher.id);
  if (id === null) {
    throw corrupt(cipher, "has no id");
  }
  const type = itemTypeOf(cipher);
  const base = {
    id,
    name: typeof cipher.name === "string" ? cipher.name : "",
    folderId: text(cipher.folderId),
    favorite: cipher.favorite === true,
    hasNotes: text(cipher.notes) !== null,
    fields: rawFields(cipher).map((field) => customField(field, type)),
    revisionDate: text(cipher.revisionDate),
  };
  if (type === "note") {
    return { ...base, type };
  }
  const data = typeData(cipher, type);
  if (type === "login") {
    return {
      ...base,
      type,
      login: {
        username: text(data.username),
        uris: loginUris(data),
        hasPassword: text(data.password) !== null,
        hasTotp: text(data.totp) !== null,
        passkeys: fido2List(cipher).map(passkeyInfo),
      },
    };
  }
  if (type === "sshKey") {
    return {
      ...base,
      type,
      sshKey: {
        publicKey: text(data.publicKey),
        keyFingerprint: text(data.keyFingerprint),
        hasPrivateKey: text(data.privateKey) !== null,
      },
    };
  }
  const detail: Record<string, string | boolean | null> = {};
  for (const field of TEXT_FIELDS[type].public) {
    detail[field] = text(data[field]);
  }
  for (const field of TEXT_FIELDS[type].secret) {
    detail[hasKey(field)] = text(data[field]) !== null;
  }
  return { ...base, type, [type]: detail } as Item;
}

/**
 * Keep items matching the list query: `type` exactly, `uri` against login websites, and `q`
 * against the name, login username and websites, the public text of the other types, and
 * text custom fields.
 */
export function filterItems(items: Item[], filter: ItemFilter, folders: Folder[]): Item[] {
  const scope = filter.folder?.toLowerCase();
  const folderOf = new Map(folders.map((folder) => [folder.id, folder.name.toLowerCase()]));
  if (scope !== undefined && !folders.some((folder) => isWithinFolder(folder.name.toLowerCase(), scope))) {
    throw new ChaaviError(404, "not_found", `no folder named "${filter.folder}"`);
  }
  return items.filter((item) => {
    if (scope !== undefined) {
      const path = item.folderId === null ? undefined : folderOf.get(item.folderId);
      if (path === undefined || !isWithinFolder(path, scope)) {
        return false;
      }
    }
    if (filter.type !== undefined && item.type !== filter.type) {
      return false;
    }
    const uris = item.type === "login" ? item.login.uris.map((entry) => entry.uri.toLowerCase()) : [];
    if (filter.uri !== undefined) {
      const needle = filter.uri.toLowerCase();
      if (!uris.some((uri) => uri.includes(needle))) {
        return false;
      }
    }
    if (filter.q !== undefined) {
      const q = filter.q.toLowerCase();
      return searchText(item).some((value) => value.toLowerCase().includes(q));
    }
    return true;
  });
}

/** True when the folder name `path` is `scope` or is nested under it (`dev/api` under `dev`). */
function isWithinFolder(path: string, scope: string): boolean {
  return path === scope || path.startsWith(`${scope}/`);
}

/** The values `q` searches for one item. */
function searchText(item: Item): string[] {
  const out = [item.name];
  if (item.type === "login") {
    out.push(...item.login.uris.map((entry) => entry.uri));
    if (item.login.username !== null) {
      out.push(item.login.username);
    }
  }
  if (item.type === "card" || item.type === "identity" || item.type === "bankAccount" || item.type === "driversLicense" || item.type === "passport") {
    const detail = (item as unknown as Record<string, Record<string, unknown>>)[item.type]!;
    for (const field of TEXT_FIELDS[item.type].public) {
      const value = detail[field];
      if (typeof value === "string") {
        out.push(value);
      }
    }
  }
  for (const field of item.fields) {
    if (field.type === "text") {
      out.push(field.value);
    }
  }
  return out;
}

/** Replace or append an item in the catalog by id. */
export function upsertItem(items: Item[], item: Item): Item[] {
  const index = items.findIndex((entry) => entry.id === item.id);
  if (index === -1) {
    return [...items, item];
  }
  const next = items.slice();
  next[index] = item;
  return next;
}

/**
 * Cipher JSON for `bw create item`. A login without a password gets a generated one; an SSH
 * key item without key material gets a new Ed25519 key.
 */
export function cipherForCreate(input: CreateItemInput): Cipher {
  const cipher: Cipher = {
    type: TYPE_CODES[input.type],
    name: input.name,
    folderId: input.folderId ?? null,
    favorite: input.favorite === true,
    notes: input.notes !== undefined && input.notes.length > 0 ? input.notes : null,
    reprompt: 0,
    fields: fieldsForWrite(input.fields ?? [], [], input.type),
  };
  if (input.type === "login") {
    const login = input.login ?? {};
    if (login.password !== undefined && (login.length !== undefined || login.special !== undefined)) {
      throw new ChaaviError(422, "invalid_request", "length and special apply only when password is omitted");
    }
    cipher.login = {
      username: emptyToNull(login.username),
      password:
        login.password ??
        generateLoginPassword({
          length: login.length ?? DEFAULT_PASSWORD_LENGTH,
          special: login.special ?? true,
        }),
      totp: checkedTotp(login.totp),
      uris: (login.uris ?? []).map(rawUri),
    };
    return cipher;
  }
  if (input.type === "note") {
    cipher.secureNote = { type: 0 };
    return cipher;
  }
  if (input.type === "sshKey") {
    cipher.sshKey = sshKeyForCreate(input.sshKey ?? {});
    return cipher;
  }
  const data: Record<string, unknown> = {};
  applyText(data, input.type, (input as unknown as Record<string, Record<string, string | undefined> | undefined>)[input.type] ?? {});
  cipher[input.type] = data;
  return cipher;
}

/**
 * Apply `PATCH /v1/items/:id` to a cipher fetched from `bw get item`, returning the cipher
 * for `bw edit item`. The type object must match the item's type.
 */
export function applyUpdate(cipher: Cipher, input: UpdateItemInput): Cipher {
  const type = itemTypeOf(cipher);
  for (const key of ["login", "card", "identity", "sshKey", "bankAccount", "driversLicense", "passport"] as const) {
    if (input[key] !== undefined && key !== type) {
      throw new ChaaviError(422, "invalid_request", `${key} fields do not apply to a ${type} item`);
    }
  }
  const next: Cipher = structuredClone(cipher);
  if (input.name !== undefined) {
    next.name = input.name;
  }
  if (input.folderId !== undefined) {
    next.folderId = input.folderId;
  }
  if (input.favorite !== undefined) {
    next.favorite = input.favorite;
  }
  if (input.notes !== undefined) {
    next.notes = emptyToNull(input.notes);
  }
  if (input.fields !== undefined) {
    next.fields = fieldsForWrite(input.fields, rawFields(cipher), type);
  }
  if (input.login !== undefined) {
    const login = typeData(next, "login");
    if (input.login.username !== undefined) {
      login.username = emptyToNull(input.login.username);
    }
    if (input.login.password !== undefined) {
      login.password = emptyToNull(input.login.password);
    }
    if (input.login.totp !== undefined) {
      login.totp = checkedTotp(input.login.totp);
    }
    if (input.login.uris !== undefined) {
      login.uris = input.login.uris.map(rawUri);
    }
  }
  if (input.sshKey !== undefined) {
    const sshKey = typeData(next, "sshKey");
    for (const key of ["privateKey", "publicKey", "keyFingerprint"] as const) {
      const value = input.sshKey[key];
      if (value !== undefined) {
        if (value.length === 0) {
          throw new ChaaviError(422, "invalid_request", `sshKey.${key} cannot be cleared`);
        }
        sshKey[key] = value;
      }
    }
  }
  for (const key of ["card", "identity", "bankAccount", "driversLicense", "passport"] as const) {
    const values = input[key];
    if (values !== undefined) {
      applyText(typeData(next, key), key, values);
    }
  }
  return next;
}

/** Item types that hold each named secret. */
const SECRET_OWNERS: Record<Exclude<SecretField, "notes">, readonly ItemType[]> = {
  password: ["login"],
  totp: ["login"],
  number: ["card"],
  code: ["card"],
  ssn: ["identity"],
  passportNumber: ["identity", "passport"],
  licenseNumber: ["identity", "driversLicense"],
  privateKey: ["sshKey"],
  accountNumber: ["bankAccount"],
  pin: ["bankAccount"],
  iban: ["bankAccount"],
  nationalIdentificationNumber: ["passport"],
};

/** One secret of an item, decrypted, for `POST /v1/items/:id/reveal`. */
export function revealFromCipher(cipher: Cipher, request: RevealRequest): SecretValue {
  const type = itemTypeOf(cipher);
  if (request.field === "custom") {
    const field = uniqueField(cipher, request.name);
    if (Number(field.type) !== FIELD_HIDDEN) {
      throw new ChaaviError(422, "invalid_request", `field "${request.name}" is not hidden`);
    }
    return { value: required(field.value, `field "${request.name}" is empty`) };
  }
  if (request.field === "notes") {
    return { value: required(cipher.notes, "item has no notes") };
  }
  if (type === "note" || !SECRET_OWNERS[request.field].includes(type)) {
    throw new ChaaviError(422, "invalid_request", `a ${type} item has no ${request.field}`);
  }
  return { value: required(typeData(cipher, type)[request.field], `item has no ${request.field}`) };
}

/** Current one-time code of a login cipher. */
export function totpFromCipher(cipher: Cipher, nowMs: number): TotpCode {
  if (itemTypeOf(cipher) !== "login") {
    throw new ChaaviError(422, "invalid_request", "item is not a login");
  }
  return totpCode(required(typeData(cipher, "login").totp, "item has no authenticator key"), nowMs);
}

/** Username + password for a login cipher; a login without a username gives null. */
export function loginFromCipher(cipher: Cipher): LoginCredential {
  if (itemTypeOf(cipher) !== "login") {
    throw new ChaaviError(422, "invalid_request", "item is not a login");
  }
  const login = typeData(cipher, "login");
  return {
    username: text(login.username),
    password: required(login.password, "item has no password"),
  };
}

/** Decrypted card fields for a form fill; the number is required. */
export function cardFromCipher(cipher: Cipher): CardCredential {
  if (itemTypeOf(cipher) !== "card") {
    throw new ChaaviError(422, "invalid_request", "item is not a card");
  }
  const card = typeData(cipher, "card");
  return {
    cardholderName: text(card.cardholderName),
    brand: text(card.brand),
    number: required(card.number, "card has no number"),
    expMonth: text(card.expMonth),
    expYear: text(card.expYear),
    code: text(card.code),
  };
}

/**
 * The value of a Secure Note's one hidden `Secret` field: Ankur's convention for an agent
 * secret is a Secure Note named for the secret with its value there.
 */
export function noteSecretFromCipher(cipher: Cipher): SecretValue {
  if (itemTypeOf(cipher) !== "note") {
    throw new ChaaviError(422, "invalid_request", "item is not a secure note");
  }
  const field = uniqueField(cipher, SECRET_FIELD);
  if (Number(field.type) !== FIELD_HIDDEN) {
    throw new ChaaviError(422, "invalid_request", `field "${SECRET_FIELD}" is not hidden`);
  }
  return { value: required(field.value, `field "${SECRET_FIELD}" is empty`) };
}

/**
 * Set a Secure Note's hidden `Secret` field to `value`, keeping its other fields, and its
 * notes to `notes` when given.
 */
export function applySecret(cipher: Cipher, value: string, notes: string | undefined): Cipher {
  if (itemTypeOf(cipher) !== "note") {
    throw new ChaaviError(422, "invalid_request", "item is not a secure note");
  }
  const fields = rawFields(cipher);
  const matches = fields.filter((field) => field.name === SECRET_FIELD);
  if (matches.length > 1) {
    throw new ChaaviError(409, "conflict", `secure note has ${matches.length} fields named "${SECRET_FIELD}"`);
  }
  const secret: RawField = { name: SECRET_FIELD, value, type: FIELD_HIDDEN, linkedId: null };
  const next: Cipher = structuredClone(cipher);
  next.fields =
    matches.length === 1 ? fields.map((field) => (field.name === SECRET_FIELD ? secret : field)) : [...fields, secret];
  if (notes !== undefined) {
    next.notes = emptyToNull(notes);
  }
  return next;
}

/** A new Secure Note named `name` holding `value` in its hidden `Secret` field. */
export function secretNoteForCreate(name: string, value: string, notes: string | undefined): Cipher {
  return cipherForCreate({
    type: "note",
    name,
    notes,
    fields: [{ name: SECRET_FIELD, type: "hidden", value }],
  });
}

/**
 * First FIDO2 credential on a login cipher, encoded for Chrome
 * `WebAuthn.addCredential` (standard base64 PKCS#8 / credential id / user handle).
 */
export function passkeyFromCipher(cipher: Cipher): PasskeyCredential {
  if (itemTypeOf(cipher) !== "login") {
    throw new ChaaviError(422, "invalid_request", "item is not a login");
  }
  typeData(cipher, "login");
  const raw = fido2List(cipher)[0];
  if (raw === undefined) {
    throw new ChaaviError(422, "invalid_request", "item has no passkey");
  }
  const rpId = requiredString(raw.rpId, "passkey is missing rpId");
  const keyAlgorithm = typeof raw.keyAlgorithm === "string" ? raw.keyAlgorithm : "";
  const keyCurve = typeof raw.keyCurve === "string" ? raw.keyCurve : "";
  if (keyAlgorithm !== "ECDSA" || keyCurve !== "P-256") {
    throw new ChaaviError(422, "invalid_request", "passkey is not ECDSA P-256");
  }
  const privateKey = stdB64(decodeBitwardenBytes(raw.keyValue, "passkey private key"));
  const credentialId = stdB64(decodeCredentialId(raw.credentialId));
  const resident = parseDiscoverable(raw.discoverable);
  const userHandleRaw = decodeOptionalBytes(raw.userHandle);
  if (resident && userHandleRaw.length === 0) {
    throw new ChaaviError(422, "invalid_request", "passkey is missing userHandle");
  }
  return {
    credentialId,
    rpId,
    privateKey,
    userHandle: stdB64(userHandleRaw),
    signCount: parseCounter(raw.counter),
    resident,
  };
}

/** A 502 `corrupt_item` naming the vault item whose stored data is not a valid item. */
function corrupt(cipher: Cipher, problem: string): ChaaviError {
  const id = typeof cipher.id === "string" && cipher.id.length > 0 ? cipher.id : "without an id";
  return new ChaaviError(502, "corrupt_item", `vault item ${id} ${problem}`);
}

/** A non-empty string, else null. */
function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** A non-empty string, else a 422 with `message`. */
function required(value: unknown, message: string): string {
  const out = text(value);
  if (out === null) {
    throw new ChaaviError(422, "invalid_request", message);
  }
  return out;
}

function emptyToNull(value: string | undefined): string | null {
  return value === undefined || value.length === 0 ? null : value;
}

/** A TOTP key to store, checked to produce codes; empty clears it. */
function checkedTotp(seed: string | undefined): string | null {
  const value = emptyToNull(seed);
  if (value !== null) {
    totpCode(value, 0);
  }
  return value;
}

/** Custom fields on a cipher; anything that is not an object is dropped by `bw` itself. */
function rawFields(cipher: Cipher): RawField[] {
  if (!Array.isArray(cipher.fields)) {
    return [];
  }
  return cipher.fields.filter((entry): entry is RawField => typeof entry === "object" && entry !== null);
}

/** The one field named `name`; none or several is a 422. */
function uniqueField(cipher: Cipher, name: string): RawField {
  const matches = rawFields(cipher).filter((field) => field.name === name);
  if (matches.length === 0) {
    throw new ChaaviError(422, "invalid_request", `item has no field named "${name}"`);
  }
  if (matches.length > 1) {
    throw new ChaaviError(422, "invalid_request", `item has ${matches.length} fields named "${name}"`);
  }
  return matches[0]!;
}

/** A stored custom field as listed, hidden values withheld. */
function customField(field: RawField, type: ItemType): CustomField {
  const name = typeof field.name === "string" ? field.name : "";
  const kind = Number(field.type);
  if (kind === FIELD_TEXT) {
    return { name, type: "text", value: typeof field.value === "string" ? field.value : "" };
  }
  if (kind === FIELD_HIDDEN) {
    return { name, type: "hidden", hasValue: text(field.value) !== null };
  }
  if (kind === FIELD_BOOLEAN) {
    return { name, type: "boolean", value: field.value === "true" || field.value === true };
  }
  if (kind === FIELD_LINKED) {
    const id = Number(field.linkedId);
    const target = Object.entries(LINKED_IDS[type]).find(([, value]) => value === id);
    if (target === undefined) {
      throw unreachable(`linked field "${name}" has unknown target ${String(field.linkedId)}`);
    }
    return { name, type: "linked", linkedTo: target[0] as LinkedTarget };
  }
  throw unreachable(`field "${name}" has unknown type ${String(field.type)}`);
}

/**
 * Cipher fields for a write. Names must be unique. A hidden field without a value keeps the
 * stored value of the hidden field with its name in `existing`.
 */
function fieldsForWrite(inputs: CustomFieldInput[], existing: RawField[], type: ItemType): RawField[] {
  const names = new Set<string>();
  return inputs.map((input) => {
    if (names.has(input.name)) {
      throw new ChaaviError(422, "invalid_request", `field "${input.name}" appears twice`);
    }
    names.add(input.name);
    if (input.type === "text") {
      return { name: input.name, value: input.value, type: FIELD_TEXT, linkedId: null };
    }
    if (input.type === "boolean") {
      return { name: input.name, value: input.value ? "true" : "false", type: FIELD_BOOLEAN, linkedId: null };
    }
    if (input.type === "linked") {
      const id = LINKED_IDS[type][input.linkedTo];
      if (id === undefined) {
        throw new ChaaviError(422, "invalid_request", `a ${type} item cannot link a field to ${input.linkedTo}`);
      }
      return { name: input.name, value: null, type: FIELD_LINKED, linkedId: id };
    }
    if (input.value !== undefined) {
      return { name: input.name, value: input.value, type: FIELD_HIDDEN, linkedId: null };
    }
    const stored = existing.filter((field) => field.name === input.name && Number(field.type) === FIELD_HIDDEN);
    if (stored.length !== 1) {
      throw new ChaaviError(422, "invalid_request", `hidden field "${input.name}" has no stored value to keep; give value`);
    }
    return { name: input.name, value: stored[0]!.value ?? null, type: FIELD_HIDDEN, linkedId: null };
  });
}

/** Login websites as listed; a null match is the account default. */
function loginUris(login: Record<string, unknown>): LoginUri[] {
  const uris = login.uris;
  if (!Array.isArray(uris)) {
    return [];
  }
  const out: LoginUri[] = [];
  for (const entry of uris as Array<{ uri?: unknown; match?: unknown }>) {
    const uri = text(entry.uri);
    if (uri === null) {
      continue;
    }
    const code = entry.match === null || entry.match === undefined ? null : Number(entry.match);
    const match = Object.entries(MATCH_CODES).find(([, value]) => value === code);
    out.push({ uri, match: match === undefined ? "default" : (match[0] as UriMatch) });
  }
  return out;
}

/** A website for a write. */
function rawUri(entry: { uri: string; match?: UriMatch | undefined }): { uri: string; match: number | null } {
  const match = entry.match === undefined || entry.match === "default" ? null : MATCH_CODES[entry.match];
  return { uri: entry.uri, match };
}

/**
 * Write a flat item's string fields: empty clears. A card number drops its spaces and
 * dashes, and a card month is stored without a leading zero.
 */
function applyText(data: Record<string, unknown>, type: TextType, input: Record<string, string | undefined>): void {
  for (const key of [...TEXT_FIELDS[type].public, ...TEXT_FIELDS[type].secret]) {
    const value = input[key];
    if (value === undefined) {
      continue;
    }
    if (type === "card" && key === "number") {
      data[key] = emptyToNull(value.replace(/[\s-]/g, ""));
    } else if (type === "card" && key === "expMonth") {
      data[key] = value.length === 0 ? null : String(Number(value));
    } else {
      data[key] = emptyToNull(value);
    }
  }
}

/** Key material for a new SSH key item: all three given, or none to generate an Ed25519 key. */
function sshKeyForCreate(input: SshKeyInput): Record<string, unknown> {
  const given = [input.privateKey, input.publicKey, input.keyFingerprint].filter((value) => value !== undefined);
  if (given.length === 0) {
    return { ...generateSshKey() };
  }
  if (given.length !== 3) {
    throw new ChaaviError(422, "invalid_request", "give privateKey, publicKey and keyFingerprint together, or none to generate a key");
  }
  return { privateKey: input.privateKey, publicKey: input.publicKey, keyFingerprint: input.keyFingerprint };
}

type Fido2Raw = {
  credentialId?: unknown;
  keyAlgorithm?: unknown;
  keyCurve?: unknown;
  keyValue?: unknown;
  rpId?: unknown;
  userHandle?: unknown;
  userName?: unknown;
  counter?: unknown;
  discoverable?: unknown;
  creationDate?: unknown;
};

/** Non-empty FIDO2 credential objects on a login cipher. */
function fido2List(cipher: Cipher): Fido2Raw[] {
  const raw = cipher.login?.fido2Credentials;
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.filter((entry): entry is Fido2Raw => typeof entry === "object" && entry !== null);
}

/** A passkey as listed, without key material. */
function passkeyInfo(raw: Fido2Raw): PasskeyInfo {
  return {
    rpId: typeof raw.rpId === "string" ? raw.rpId : "",
    userName: text(raw.userName),
    creationDate: text(raw.creationDate),
  };
}

/** Decode Bitwarden's credentialId: UUID hex bytes, or FIDO2 base64url. */
function decodeCredentialId(value: unknown): Buffer {
  const raw = requiredString(value, "passkey is missing credentialId");
  const guid = guidBytes(raw);
  if (guid !== undefined) {
    return guid;
  }
  return decodeBitwardenBytes(raw, "passkey credentialId");
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** 16-byte form of a hyphenated UUID, or undefined when `value` is not one. */
function guidBytes(value: string): Buffer | undefined {
  if (!UUID_RE.test(value)) {
    return undefined;
  }
  return Buffer.from(value.replaceAll("-", ""), "hex");
}

/** Decode a Bitwarden FIDO2 string (URL-safe base64, optional padding). */
function decodeBitwardenBytes(value: unknown, label: string): Buffer {
  const raw = requiredString(value, `${label} is missing`);
  const buf = Buffer.from(raw, "base64url");
  if (buf.length === 0) {
    throw new ChaaviError(422, "invalid_request", `${label} is not valid base64`);
  }
  return buf;
}

/** Decode an optional Bitwarden FIDO2 string; empty when absent. */
function decodeOptionalBytes(value: unknown): Buffer {
  if (typeof value !== "string" || value.length === 0) {
    return Buffer.alloc(0);
  }
  const buf = Buffer.from(value, "base64url");
  if (buf.length === 0) {
    throw new ChaaviError(422, "invalid_request", "passkey userHandle is not valid base64");
  }
  return buf;
}

function requiredString(value: unknown, message: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ChaaviError(422, "invalid_request", message);
  }
  return value;
}

function stdB64(buf: Buffer): string {
  return buf.toString("base64");
}

function parseCounter(value: unknown): number {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) {
    return value;
  }
  if (typeof value === "string" && value.length > 0) {
    const n = Number(value);
    if (Number.isInteger(n) && n >= 0) {
      return n;
    }
  }
  throw new ChaaviError(422, "invalid_request", "passkey is missing counter");
}

function parseDiscoverable(value: unknown): boolean {
  if (value === true || value === "true") {
    return true;
  }
  if (value === false || value === "false") {
    return false;
  }
  throw new ChaaviError(422, "invalid_request", "passkey is missing discoverable");
}

/** Build a 502 vault_unreachable error (CLI/protocol failure). */
export function unreachable(message: string): ChaaviError {
  return new ChaaviError(502, "vault_unreachable", message);
}
