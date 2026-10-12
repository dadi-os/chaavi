import assert from "node:assert/strict";
import { createHash, createPrivateKey, generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { ChaaviError } from "../src/errors.js";
import {
  applySecret,
  applyUpdate,
  cipherForCreate,
  itemFromCipher,
  noteSecretFromCipher,
  passkeyFromCipher,
  upsertItem,
  type Cipher,
} from "../src/vault/cipher.js";
import { generateSshKey, sshFingerprint } from "../src/vault/ssh.js";
import { totpCode } from "../src/vault/totp.js";

const loginCipher: Cipher = {
  id: "login-1",
  name: "GitHub",
  type: 1,
  reprompt: 1,
  login: { username: "octocat", password: "s3cret", uris: [{ uri: "https://github.com", match: 3 }] },
};

const isChaavi = (type: string, message?: string) => (err: unknown) =>
  err instanceof ChaaviError && err.type === type && (message === undefined || err.message === message);

test("itemFromCipher maps a login's public fields and flags its secrets", () => {
  const item = itemFromCipher(loginCipher);
  assert.equal(item.type, "login");
  assert.deepEqual(item.type === "login" ? item.login : null, {
    username: "octocat",
    uris: [{ uri: "https://github.com", match: "exact" }],
    hasPassword: true,
    hasTotp: false,
    passkeys: [],
  });
  assert.equal(JSON.stringify(item).includes("s3cret"), false);
});

test("itemFromCipher rejects a linked field whose target is not on the item type", () => {
  assert.throws(
    () => itemFromCipher({ id: "n", type: 2, name: "x", fields: [{ name: "L", type: 3, linkedId: 101 }] }),
    isChaavi("vault_unreachable", 'linked field "L" has unknown target 101'),
  );
});

test("applyUpdate keeps keys it does not own, such as reprompt and passkeys", () => {
  const withPasskey: Cipher = {
    ...loginCipher,
    login: { ...loginCipher.login, fido2Credentials: [{ rpId: "github.com" }] },
  };
  const next = applyUpdate(withPasskey, { name: "Renamed", login: { password: "n3w" } });
  assert.equal(next.name, "Renamed");
  assert.equal(next.reprompt, 1);
  assert.deepEqual(next.login?.fido2Credentials, [{ rpId: "github.com" }]);
  assert.equal(next.login?.password, "n3w");
  assert.equal(withPasskey.login?.password, "s3cret");
});

test("cipherForCreate generates a 20-character password by default and links fields by type", () => {
  const cipher = cipherForCreate({
    type: "login",
    name: "New",
    fields: [{ name: "Who", type: "linked", linkedTo: "username" }],
  });
  assert.equal(String(cipher.login?.password).length, 20);
  assert.deepEqual(cipher.fields, [{ name: "Who", value: null, type: 3, linkedId: 100 }]);
  const card = cipherForCreate({ type: "card", name: "C", fields: [{ name: "N", type: "linked", linkedTo: "number" }] });
  assert.deepEqual(card.fields, [{ name: "N", value: null, type: 3, linkedId: 305 }]);
});

test("noteSecretFromCipher reads only a Secure Note's one hidden Secret field", () => {
  const note = (fields: unknown[]): Cipher => ({ id: "n", type: 2, name: "Key", fields });
  assert.deepEqual(noteSecretFromCipher(note([{ name: "Secret", type: 1, value: "v" }])), { value: "v" });
  assert.throws(() => noteSecretFromCipher(loginCipher), isChaavi("invalid_request", "item is not a secure note"));
  assert.throws(
    () => noteSecretFromCipher(note([{ name: "Secret", type: 0, value: "v" }])),
    isChaavi("invalid_request", 'field "Secret" is not hidden'),
  );
  assert.throws(
    () => noteSecretFromCipher(note([{ name: "secret", type: 1, value: "v" }])),
    isChaavi("invalid_request", 'item has no field named "Secret"'),
  );
  assert.throws(
    () => noteSecretFromCipher(note([{ name: "Secret", type: 1, value: "a" }, { name: "Secret", type: 1, value: "b" }])),
    isChaavi("invalid_request", 'item has 2 fields named "Secret"'),
  );
});

test("applySecret replaces or appends the Secret field and keeps the rest", () => {
  const note: Cipher = { id: "n", type: 2, name: "Key", notes: "keep", fields: [{ name: "Account", type: 0, value: "a" }] };
  const added = applySecret(note, "v1", undefined);
  assert.deepEqual(added.fields, [
    { name: "Account", type: 0, value: "a" },
    { name: "Secret", value: "v1", type: 1, linkedId: null },
  ]);
  assert.equal(added.notes, "keep");
  const replaced = applySecret(added, "v2", "");
  assert.deepEqual(noteSecretFromCipher(replaced), { value: "v2" });
  assert.equal(replaced.notes, null);
});

test("totpCode matches the RFC 6238 SHA1 vectors", () => {
  const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.deepEqual(totpCode(seed, 59_000), { code: "287082", period: 30, remaining: 1 });
  const uri = `otpauth://totp/Example:ada?secret=${seed}&digits=8&period=30&algorithm=SHA1`;
  assert.equal(totpCode(uri, 59_000).code, "94287082");
  assert.equal(totpCode(uri, 1_111_111_109_000).code, "07081804");
  assert.equal(totpCode(uri, 2_000_000_000_000).code, "69279037");
  assert.throws(() => totpCode("steam://ABC", 0), isChaavi("invalid_request", "Steam authenticator keys are not supported"));
  assert.throws(() => totpCode("not base32!", 0), isChaavi("invalid_request", "authenticator key is not valid base32"));
});

test("generateSshKey makes an OpenSSH Ed25519 key whose public key and fingerprint match", () => {
  const key = generateSshKey();
  const [kind, blob64] = key.publicKey.split(" ");
  assert.equal(kind, "ssh-ed25519");
  const blob = Buffer.from(blob64!, "base64");
  assert.equal(key.keyFingerprint, sshFingerprint(blob));
  assert.equal(
    key.keyFingerprint,
    `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/, "")}`,
  );
  const body = Buffer.from(
    key.privateKey.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""),
    "base64",
  );
  assert.equal(body.subarray(0, 15).toString("latin1"), "openssh-key-v1\0");
  assert.ok(body.includes(blob));
  const pub = blob.subarray(blob.length - 32);
  const seedAt = body.lastIndexOf(Buffer.concat([Buffer.from([0, 0, 0, 64])]));
  const seed = body.subarray(seedAt + 4, seedAt + 36);
  const rebuilt = createPrivateKey({
    key: { kty: "OKP", crv: "Ed25519", d: seed.toString("base64url"), x: pub.toString("base64url") },
    format: "jwk",
  });
  assert.equal(rebuilt.asymmetricKeyType, "ed25519");
  const derived = Buffer.from(
    (rebuilt.export({ format: "jwk" }) as { x: string }).x,
    "base64url",
  );
  assert.deepEqual(derived, pub);
});

test("passkeyFromCipher maps Bitwarden FIDO2 fields to CDP base64", () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  const credId = Buffer.from("cred-id-bytes");
  const user = Buffer.from("ada@example.com");
  const cipher: Cipher = {
    id: "pk-1",
    name: "Google",
    type: 1,
    login: {
      username: "ada",
      fido2Credentials: [
        {
          credentialId: credId.toString("base64url"),
          keyAlgorithm: "ECDSA",
          keyCurve: "P-256",
          keyValue: der.toString("base64url"),
          rpId: "google.com",
          userHandle: user.toString("base64url"),
          counter: "3",
          discoverable: "true",
        },
      ],
    },
  };
  const item = itemFromCipher(cipher);
  assert.equal(item.type === "login" ? item.login.passkeys[0]?.rpId : null, "google.com");
  assert.deepEqual(passkeyFromCipher(cipher), {
    credentialId: credId.toString("base64"),
    rpId: "google.com",
    privateKey: der.toString("base64"),
    userHandle: user.toString("base64"),
    signCount: 3,
    resident: true,
  });
});

test("passkeyFromCipher decodes a UUID credentialId as 16 bytes", () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  const guid = "550e8400-e29b-41d4-a716-446655440000";
  const cred = passkeyFromCipher({
    id: "pk-2",
    name: "Google",
    type: 1,
    login: {
      fido2Credentials: [
        {
          credentialId: guid,
          keyAlgorithm: "ECDSA",
          keyCurve: "P-256",
          keyValue: der.toString("base64url"),
          rpId: "google.com",
          userHandle: Buffer.from("user").toString("base64url"),
          counter: 0,
          discoverable: true,
        },
      ],
    },
  });
  assert.equal(cred.credentialId, Buffer.from("550e8400e29b41d4a716446655440000", "hex").toString("base64"));
});

test("passkeyFromCipher requires a login with a P-256 passkey, counter and discoverable", () => {
  assert.throws(() => passkeyFromCipher(loginCipher), isChaavi("invalid_request", "item has no passkey"));
  assert.throws(() => passkeyFromCipher({ id: "n", type: 2, name: "x" }), isChaavi("invalid_request", "item is not a login"));
  const base = (raw: Record<string, unknown>): Cipher => ({ id: "p", type: 1, name: "x", login: { fido2Credentials: [raw] } });
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = (privateKey.export({ type: "pkcs8", format: "der" }) as Buffer).toString("base64url");
  const good = {
    credentialId: Buffer.from("id").toString("base64url"),
    keyAlgorithm: "ECDSA",
    keyCurve: "P-256",
    keyValue: der,
    rpId: "example.com",
    userHandle: Buffer.from("u").toString("base64url"),
    counter: 1,
    discoverable: true,
  };
  assert.throws(() => passkeyFromCipher(base({ ...good, counter: undefined })), isChaavi("invalid_request", "passkey is missing counter"));
  assert.throws(
    () => passkeyFromCipher(base({ ...good, discoverable: undefined })),
    isChaavi("invalid_request", "passkey is missing discoverable"),
  );
  assert.throws(() => passkeyFromCipher(base({ ...good, keyCurve: "P-384" })), isChaavi("invalid_request", "passkey is not ECDSA P-256"));
});

test("upsertItem appends or replaces by id", () => {
  const login = itemFromCipher(loginCipher);
  const note = itemFromCipher({ id: "note-1", type: 2, name: "Wifi" });
  const two = upsertItem(upsertItem([], login), note);
  assert.deepEqual(two.map((item) => item.id), ["login-1", "note-1"]);
  const renamed = upsertItem(two, { ...login, name: "GitHub renamed" });
  assert.equal(renamed.length, 2);
  assert.equal(renamed[0]?.name, "GitHub renamed");
});
