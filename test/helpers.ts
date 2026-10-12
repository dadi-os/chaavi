import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Config } from "../src/config.js";
import { HOST, LOG_LEVEL, PORT } from "../src/constants.js";
import type { Logger } from "../src/logging.js";
import type { BwExec } from "../src/vault/bw.js";
import type { Cipher } from "../src/vault/cipher.js";

const serviceRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/** Config for Fastify inject tests. Does not read process.env. */
export function makeConfig(): Config {
  return {
    serviceRoot,
    env: {
      vaultUrl: "http://127.0.0.1:80",
      host: HOST,
      port: PORT,
      logLevel: LOG_LEVEL,
      bw: {
        clientId: "test-client",
        clientSecret: "test-secret",
        password: "test-password",
        appDataDir: "/tmp/chaavi-test-bw",
      },
    },
    vault: { timeout_ms: 30_000, sync_interval_ms: 2_000 },
  };
}

/** Logger that keeps lines for assertions instead of printing them. */
export function memoryLogger(): Logger & { lines: Array<{ level: string; msg: string; attrs?: Record<string, unknown> }> } {
  const lines: Array<{ level: string; msg: string; attrs?: Record<string, unknown> }> = [];
  const push = (level: string) => (msg: string, attrs?: Record<string, unknown>) => {
    lines.push({ level, msg, ...(attrs !== undefined ? { attrs } : {}) });
  };
  return { lines, debug: push("debug"), info: push("info"), warn: push("warn"), error: push("error") };
}

/**
 * In-memory stand-in for the `bw` CLI: answers the commands BwVault runs (config, login,
 * unlock, sync, list, get, create, edit, delete for items and folders) the way the CLI does,
 * including "Not found." on stderr and the server moving a deleted folder's items out.
 */
export class FakeBw {
  ciphers: Cipher[] = [];
  folders: Array<{ id: string; name: string }> = [];
  /** Every argv run, without `--nointeraction` and the session. */
  calls: string[][] = [];
  #server = "";

  /** Replace the vault contents. */
  seed(ciphers: Cipher[], folders: Array<{ id: string; name: string }> = []): void {
    this.ciphers = structuredClone(ciphers);
    this.folders = structuredClone(folders);
  }

  /** The cipher with this id, as stored. */
  stored(id: string): Cipher {
    const cipher = this.ciphers.find((entry) => entry.id === id);
    if (cipher === undefined) {
      throw new Error(`no stored cipher ${id}`);
    }
    return cipher;
  }

  run = async (argv: string[]): Promise<BwExec> => {
    const args = argv.filter((arg, i) => arg !== "--nointeraction" && arg !== "--session" && argv[i - 1] !== "--session");
    this.calls.push(args);
    const [verb, noun, a, b] = args;
    const ok = (value: unknown): BwExec => ({ stdout: typeof value === "string" ? value : JSON.stringify(value), stderr: "", code: 0 });
    const notFound: BwExec = { stdout: "", stderr: "Not found.", code: 1 };
    if (verb === "config") {
      if (a !== undefined) {
        this.#server = a;
      }
      return a === undefined && noun === "server" ? ok(this.#server) : ok("");
    }
    if (verb === "login" || verb === "sync" || verb === "logout") {
      return ok("");
    }
    if (verb === "unlock") {
      return ok("fake-session-token");
    }
    if (verb === "list" && noun === "items") {
      return ok(this.ciphers);
    }
    if (verb === "list" && noun === "folders") {
      return ok([{ object: "folder", id: null, name: "No Folder" }, ...this.folders]);
    }
    if (verb === "get" && noun === "item") {
      const cipher = this.ciphers.find((entry) => entry.id === a);
      return cipher === undefined ? notFound : ok(cipher);
    }
    if (verb === "create" && noun === "item") {
      const cipher = { ...decode(a), id: randomUUID(), revisionDate: new Date().toISOString() };
      this.ciphers.push(cipher);
      return ok(cipher);
    }
    if (verb === "edit" && noun === "item") {
      const index = this.ciphers.findIndex((entry) => entry.id === a);
      if (index === -1) {
        return notFound;
      }
      const cipher = { ...decode(b), id: a, revisionDate: new Date().toISOString() };
      this.ciphers[index] = cipher;
      return ok(cipher);
    }
    if (verb === "delete" && noun === "item") {
      const before = this.ciphers.length;
      this.ciphers = this.ciphers.filter((entry) => entry.id !== a);
      return before === this.ciphers.length ? notFound : ok("");
    }
    if (verb === "create" && noun === "folder") {
      const folder = { id: randomUUID(), name: String((decode(a) as { name: unknown }).name) };
      this.folders.push(folder);
      return ok(folder);
    }
    if (verb === "edit" && noun === "folder") {
      const folder = this.folders.find((entry) => entry.id === a);
      if (folder === undefined) {
        return notFound;
      }
      folder.name = String((decode(b) as { name: unknown }).name);
      return ok(folder);
    }
    if (verb === "delete" && noun === "folder") {
      const before = this.folders.length;
      this.folders = this.folders.filter((entry) => entry.id !== a);
      for (const cipher of this.ciphers) {
        if (cipher.folderId === a) {
          cipher.folderId = null;
        }
      }
      return before === this.folders.length ? notFound : ok("");
    }
    return { stdout: "", stderr: `unexpected bw ${args.join(" ")}`, code: 1 };
  };
}

/** Decode the base64 JSON argument of `bw create` / `bw edit`. */
function decode(arg: string | undefined): Cipher {
  return JSON.parse(Buffer.from(arg ?? "", "base64").toString("utf8")) as Cipher;
}

export const LOGIN_ID = "11111111-1111-1111-1111-111111111111";
export const NOTE_ID = "22222222-2222-2222-2222-222222222222";
export const SSH_ID = "33333333-3333-3333-3333-333333333333";
export const PASSKEY_ID = "44444444-4444-4444-4444-444444444444";
export const CARD_ID = "55555555-5555-5555-5555-555555555555";
export const IDENTITY_ID = "66666666-6666-6666-6666-666666666666";
export const SECRET_NOTE_ID = "77777777-7777-7777-7777-777777777777";
export const BANK_ID = "12121212-1212-1212-1212-121212121212";
export const LICENSE_ID = "13131313-1313-1313-1313-131313131313";
export const PASSPORT_ID = "14141414-1414-1414-1414-141414141414";
export const MISSING_ID = "00000000-0000-0000-0000-000000000000";
export const DEV_FOLDER = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
export const FINANCE_FOLDER = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

/** RFC 6238 test key ("12345678901234567890") in base32. */
export const TOTP_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/**
 * Secret values in {@link sampleCiphers}, for asserting a response carries none of them. The
 * card's 3-digit code is left out: it would also match timestamps.
 */
export const SAMPLE_SECRETS = [
  "hunter2",
  TOTP_SEED,
  "wifi-note-body",
  "4111111111111111",
  "000-12-3456",
  "X1234567",
  "D-555",
  "-----BEGIN OPENSSH PRIVATE KEY-----",
  "hidden-recovery-code",
  "tok_live_abc",
  "passkey-private-key",
  "ACCT-000123456789",
  "PIN-4821",
  "GB00ACME12345600000001",
  "DL-D12345678",
  "PP-A12345678",
  "NIN-123-45-6789",
];

/** Folders for {@link sampleCiphers}. */
export function sampleFolders(): Array<{ id: string; name: string }> {
  return [
    { id: DEV_FOLDER, name: "Dev" },
    { id: FINANCE_FOLDER, name: "Finance" },
  ];
}

/**
 * Vault with one item of every type and every custom field kind: a login with TOTP and a
 * hidden field, a passkey login, a Wi-Fi note, a card, an identity, an SSH key, an agent
 * secret note, a bank account, a driver's license and a passport.
 */
export function sampleCiphers(): Cipher[] {
  return [
    {
      id: LOGIN_ID,
      type: 1,
      name: "GitHub",
      folderId: DEV_FOLDER,
      favorite: true,
      notes: null,
      fields: [
        { name: "Recovery", type: 1, value: "hidden-recovery-code", linkedId: null },
        { name: "Org", type: 0, value: "dadi", linkedId: null },
        { name: "Admin", type: 2, value: "true", linkedId: null },
        { name: "User", type: 3, value: null, linkedId: 100 },
      ],
      login: {
        username: "octocat",
        password: "hunter2",
        totp: TOTP_SEED,
        uris: [{ uri: "https://github.com", match: null }, { uri: "", match: null }],
      },
    },
    {
      id: PASSKEY_ID,
      type: 1,
      name: "Google",
      folderId: null,
      favorite: false,
      login: {
        username: "ada@example.com",
        password: null,
        uris: [{ uri: "https://accounts.google.com", match: 0 }],
        fido2Credentials: [
          { rpId: "google.com", userName: "ada@example.com", keyValue: "passkey-private-key", creationDate: "2026-01-01T00:00:00Z" },
        ],
      },
    },
    { id: NOTE_ID, type: 2, name: "Wifi", folderId: null, notes: "wifi-note-body", secureNote: { type: 0 }, fields: [] },
    {
      id: CARD_ID,
      type: 3,
      name: "Sapphire",
      folderId: FINANCE_FOLDER,
      card: { cardholderName: "Ada Lovelace", brand: "Visa", number: "4111111111111111", expMonth: "8", expYear: "2029", code: "123" },
      fields: [{ name: "Holder", type: 3, value: null, linkedId: 300 }],
    },
    {
      id: IDENTITY_ID,
      type: 4,
      name: "Personal",
      identity: {
        firstName: "Ada",
        lastName: "Lovelace",
        address1: "1 Example St",
        city: "East Lansing",
        state: "MI",
        postalCode: "48823",
        country: "US",
        email: "ada@example.com",
        ssn: "000-12-3456",
        passportNumber: "X1234567",
        licenseNumber: "D-555",
      },
    },
    {
      id: SSH_ID,
      type: 5,
      name: "Deploy key",
      sshKey: {
        privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
        publicKey: "ssh-ed25519 AAAAtest",
        keyFingerprint: "SHA256:test",
      },
    },
    {
      id: SECRET_NOTE_ID,
      type: 2,
      name: "Stripe API key",
      folderId: DEV_FOLDER,
      notes: "Live key for billing.",
      secureNote: { type: 0 },
      fields: [
        { name: "Account", type: 0, value: "acct_1", linkedId: null },
        { name: "Secret", type: 1, value: "tok_live_abc", linkedId: null },
      ],
    },
    {
      id: BANK_ID,
      type: 6,
      name: "Checking",
      folderId: FINANCE_FOLDER,
      bankAccount: {
        bankName: "Acme Bank",
        nameOnAccount: "Ada Lovelace",
        accountType: "checking",
        accountNumber: "ACCT-000123456789",
        routingNumber: "011000015",
        pin: "PIN-4821",
        swiftCode: "ACMEUS33",
        iban: "GB00ACME12345600000001",
      },
    },
    {
      id: LICENSE_ID,
      type: 7,
      name: "Michigan license",
      driversLicense: {
        firstName: "Ada",
        lastName: "Lovelace",
        licenseNumber: "DL-D12345678",
        issuingState: "MI",
        expirationDate: "2030-06-01",
        licenseClass: "C",
      },
    },
    {
      id: PASSPORT_ID,
      type: 8,
      name: "US passport",
      passport: {
        surname: "Lovelace",
        givenName: "Ada",
        nationality: "USA",
        passportNumber: "PP-A12345678",
        nationalIdentificationNumber: "NIN-123-45-6789",
        expirationDate: "2031-01-01",
      },
    },
  ];
}
