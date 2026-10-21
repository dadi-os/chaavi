/**
 * Vault record shapes for Thaali and Hath. Secret values never appear on an {@link Item};
 * they come back one at a time from the reveal routes.
 */

/** Every Bitwarden item type (cipher types 1–8). */
export type ItemType =
  | "login"
  | "note"
  | "card"
  | "identity"
  | "sshKey"
  | "bankAccount"
  | "driversLicense"
  | "passport";

/** How the Bitwarden extension matches a login URI; `default` follows the account setting. */
export type UriMatch = "default" | "domain" | "host" | "startsWith" | "exact" | "regex" | "never";

/** A login website. */
export type LoginUri = {
  uri: string;
  match: UriMatch;
};

/** Item property a linked custom field points at, by item type. */
export type LinkedTarget =
  | "username"
  | "password"
  | "cardholderName"
  | "expMonth"
  | "expYear"
  | "code"
  | "brand"
  | "number"
  | "title"
  | "firstName"
  | "middleName"
  | "lastName"
  | "fullName"
  | "address1"
  | "address2"
  | "address3"
  | "city"
  | "state"
  | "postalCode"
  | "country"
  | "company"
  | "email"
  | "phone"
  | "ssn"
  | "passportNumber"
  | "licenseNumber";

/** A custom field as listed: a hidden field says only whether it holds a value. */
export type CustomField =
  | { name: string; type: "text"; value: string }
  | { name: string; type: "hidden"; hasValue: boolean }
  | { name: string; type: "boolean"; value: boolean }
  | { name: string; type: "linked"; linkedTo: LinkedTarget };

/**
 * A custom field to write. A hidden field without `value` on update keeps the stored value
 * of the hidden field with the same name.
 */
export type CustomFieldInput =
  | { name: string; type: "text"; value: string }
  | { name: string; type: "hidden"; value?: string | undefined }
  | { name: string; type: "boolean"; value: boolean }
  | { name: string; type: "linked"; linkedTo: LinkedTarget };

/** A FIDO2 passkey on a login, without its key material. */
export type PasskeyInfo = {
  rpId: string;
  userName: string | null;
  creationDate: string | null;
};

/** Login fields that are not secret, plus which secrets it holds. */
export type LoginDetail = {
  username: string | null;
  uris: LoginUri[];
  hasPassword: boolean;
  hasTotp: boolean;
  passkeys: PasskeyInfo[];
};

/** Card fields that are not secret, plus which secrets it holds. */
export type CardDetail = {
  cardholderName: string | null;
  brand: string | null;
  /** `1`–`12`. */
  expMonth: string | null;
  /** Four digits. */
  expYear: string | null;
  hasNumber: boolean;
  hasCode: boolean;
};

/** Identity fields that are not secret, plus which secrets it holds. */
export type IdentityDetail = {
  title: string | null;
  firstName: string | null;
  middleName: string | null;
  lastName: string | null;
  address1: string | null;
  address2: string | null;
  address3: string | null;
  city: string | null;
  state: string | null;
  postalCode: string | null;
  country: string | null;
  company: string | null;
  email: string | null;
  phone: string | null;
  username: string | null;
  hasSsn: boolean;
  hasPassportNumber: boolean;
  hasLicenseNumber: boolean;
};

/** SSH key fields that are not secret. */
export type SshKeyDetail = {
  publicKey: string | null;
  keyFingerprint: string | null;
  hasPrivateKey: boolean;
};

/** Bank account fields that are not secret, plus which secrets it holds. */
export type BankAccountDetail = {
  bankName: string | null;
  nameOnAccount: string | null;
  /** Free text, e.g. checking or savings. */
  accountType: string | null;
  routingNumber: string | null;
  branchNumber: string | null;
  swiftCode: string | null;
  bankContactPhone: string | null;
  hasAccountNumber: boolean;
  hasPin: boolean;
  hasIban: boolean;
};

/** Driver's license fields that are not secret, plus which secrets it holds. */
export type DriversLicenseDetail = {
  firstName: string | null;
  middleName: string | null;
  lastName: string | null;
  dateOfBirth: string | null;
  issuingCountry: string | null;
  issuingState: string | null;
  issueDate: string | null;
  expirationDate: string | null;
  issuingAuthority: string | null;
  licenseClass: string | null;
  hasLicenseNumber: boolean;
};

/** Passport fields that are not secret, plus which secrets it holds. */
export type PassportDetail = {
  surname: string | null;
  givenName: string | null;
  dateOfBirth: string | null;
  sex: string | null;
  birthPlace: string | null;
  nationality: string | null;
  issuingCountry: string | null;
  passportType: string | null;
  issuingAuthority: string | null;
  issueDate: string | null;
  expirationDate: string | null;
  hasPassportNumber: boolean;
  hasNationalIdentificationNumber: boolean;
};

type ItemBase = {
  id: string;
  name: string;
  folderId: string | null;
  favorite: boolean;
  /** True when the item's notes are non-empty; the text itself is revealed on demand. */
  hasNotes: boolean;
  fields: CustomField[];
  revisionDate: string | null;
};

/** One vault item for list and detail. Never carries a secret value. */
export type Item = ItemBase &
  (
    | { type: "login"; login: LoginDetail }
    | { type: "note" }
    | { type: "card"; card: CardDetail }
    | { type: "identity"; identity: IdentityDetail }
    | { type: "sshKey"; sshKey: SshKeyDetail }
    | { type: "bankAccount"; bankAccount: BankAccountDetail }
    | { type: "driversLicense"; driversLicense: DriversLicenseDetail }
    | { type: "passport"; passport: PassportDetail }
  );

/** A vault folder. */
export type Folder = {
  id: string;
  name: string;
};

/** Optional list filters applied to the in-memory catalog. */
export type ItemFilter = {
  q?: string | undefined;
  uri?: string | undefined;
  type?: ItemType | undefined;
  /** A folder name; takes the items in that folder and in every folder nested under it (`Dev` takes `Dev/api`). */
  folder?: string | undefined;
};

/** Login fields on create. Omitted `password` is generated (`length` / `special`). */
export type LoginInput = {
  username?: string | undefined;
  password?: string | undefined;
  totp?: string | undefined;
  uris?: Array<{ uri: string; match?: UriMatch | undefined }> | undefined;
  length?: number | undefined;
  special?: boolean | undefined;
};

/** Card fields on write. */
export type CardInput = {
  cardholderName?: string | undefined;
  brand?: string | undefined;
  number?: string | undefined;
  expMonth?: string | undefined;
  expYear?: string | undefined;
  code?: string | undefined;
};

/** Identity fields on write. */
export type IdentityInput = {
  title?: string | undefined;
  firstName?: string | undefined;
  middleName?: string | undefined;
  lastName?: string | undefined;
  address1?: string | undefined;
  address2?: string | undefined;
  address3?: string | undefined;
  city?: string | undefined;
  state?: string | undefined;
  postalCode?: string | undefined;
  country?: string | undefined;
  company?: string | undefined;
  email?: string | undefined;
  phone?: string | undefined;
  username?: string | undefined;
  ssn?: string | undefined;
  passportNumber?: string | undefined;
  licenseNumber?: string | undefined;
};

/** SSH key fields on write; all three together, or none on create to generate an Ed25519 key. */
export type SshKeyInput = {
  privateKey?: string | undefined;
  publicKey?: string | undefined;
  keyFingerprint?: string | undefined;
};

/** Bank account fields on write; empty clears. */
export type BankAccountInput = Partial<
  Record<
    | "bankName"
    | "nameOnAccount"
    | "accountType"
    | "accountNumber"
    | "routingNumber"
    | "branchNumber"
    | "pin"
    | "swiftCode"
    | "iban"
    | "bankContactPhone",
    string | undefined
  >
>;

/** Driver's license fields on write; empty clears. */
export type DriversLicenseInput = Partial<
  Record<
    | "firstName"
    | "middleName"
    | "lastName"
    | "dateOfBirth"
    | "licenseNumber"
    | "issuingCountry"
    | "issuingState"
    | "issueDate"
    | "expirationDate"
    | "issuingAuthority"
    | "licenseClass",
    string | undefined
  >
>;

/** Passport fields on write; empty clears. */
export type PassportInput = Partial<
  Record<
    | "surname"
    | "givenName"
    | "dateOfBirth"
    | "sex"
    | "birthPlace"
    | "nationality"
    | "issuingCountry"
    | "passportNumber"
    | "passportType"
    | "nationalIdentificationNumber"
    | "issuingAuthority"
    | "issueDate"
    | "expirationDate",
    string | undefined
  >
>;

type CreateBase = {
  name: string;
  folderId?: string | null | undefined;
  favorite?: boolean | undefined;
  notes?: string | undefined;
  fields?: CustomFieldInput[] | undefined;
};

/** Body for `POST /v1/items`. */
export type CreateItemInput = CreateBase &
  (
    | { type: "login"; login?: LoginInput | undefined }
    | { type: "note" }
    | { type: "card"; card?: CardInput | undefined }
    | { type: "identity"; identity?: IdentityInput | undefined }
    | { type: "sshKey"; sshKey?: SshKeyInput | undefined }
    | { type: "bankAccount"; bankAccount?: BankAccountInput | undefined }
    | { type: "driversLicense"; driversLicense?: DriversLicenseInput | undefined }
    | { type: "passport"; passport?: PassportInput | undefined }
  );

/**
 * Body for `PATCH /v1/items/:id`. Only given keys change; an empty string clears an optional
 * value. `fields` replaces the whole list. The type object must match the item's type.
 * `folderId` alone moves the item.
 */
export type UpdateItemInput = {
  name?: string | undefined;
  folderId?: string | null | undefined;
  favorite?: boolean | undefined;
  notes?: string | undefined;
  fields?: CustomFieldInput[] | undefined;
  login?: Omit<LoginInput, "length" | "special"> | undefined;
  card?: CardInput | undefined;
  identity?: IdentityInput | undefined;
  sshKey?: SshKeyInput | undefined;
  bankAccount?: BankAccountInput | undefined;
  driversLicense?: DriversLicenseInput | undefined;
  passport?: PassportInput | undefined;
};

/** A secret an item can reveal, by item type. */
export type SecretField =
  | "password"
  | "totp"
  | "number"
  | "code"
  | "ssn"
  | "passportNumber"
  | "licenseNumber"
  | "privateKey"
  | "accountNumber"
  | "pin"
  | "iban"
  | "nationalIdentificationNumber"
  | "notes";

/** Body for `POST /v1/items/:id/reveal`: a named secret, or a hidden custom field by name. */
export type RevealRequest = { field: SecretField } | { field: "custom"; name: string };

/** One decrypted value. */
export type SecretValue = {
  value: string;
};

/** Current one-time code of a login (`POST /v1/items/:id/totp`). */
export type TotpCode = {
  code: string;
  /** Seconds per code. */
  period: number;
  /** Seconds until this code expires. */
  remaining: number;
};

/** Username + password for a login item (`POST /v1/items/:id/login`); a login may have no username. */
export type LoginCredential = {
  username: string | null;
  password: string;
};

/** Decrypted card for a fill (`POST /v1/items/:id/card`). */
export type CardCredential = {
  cardholderName: string | null;
  brand: string | null;
  number: string;
  expMonth: string | null;
  expYear: string | null;
  code: string | null;
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

/** Body for `PUT /v1/secrets/:name`. */
export type SaveSecretInput = {
  value: string;
  notes?: string | undefined;
};

/** Result of `PUT /v1/secrets/:name`. */
export type SavedSecret = {
  item: Item;
  /** True when no Secure Note had that name and one was created. */
  created: boolean;
};
