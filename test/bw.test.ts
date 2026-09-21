import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { ChaaviError } from "../src/errors.js";
import type { ItemRecord } from "../src/types/domain.js";
import {
  filterItems,
  upsertItem,
  itemRecordFromCipher,
  loginFromCipher,
  passkeyFromCipher,
  secretFromCipher,
} from "../src/vault/bw.js";

const loginCipher = {
  id: "login-1",
  name: "GitHub",
  type: 1,
  login: {
    username: "octocat",
    password: "s3cret",
    uris: [{ uri: "https://github.com" }, { uri: "" }],
  },
};

const noteCipher = {
  id: "note-1",
  name: "Wifi",
  type: 2,
  notes: "hunter2",
};

const sshCipher = {
  id: "ssh-1",
  name: "Deploy key",
  type: 5,
  sshKey: { privateKey: "-----BEGIN PRIVATE KEY-----\nabc\n" },
};

test("itemRecordFromCipher maps login metadata without secrets", () => {
  const item = itemRecordFromCipher(loginCipher);
  assert.deepEqual(item, {
    id: "login-1",
    name: "GitHub",
    kind: "login",
    username: "octocat",
    uris: ["https://github.com"],
    hasPasskey: false,
  });
});

test("itemRecordFromCipher maps note and ssh kinds", () => {
  assert.equal(itemRecordFromCipher(noteCipher).kind, "note");
  assert.equal(itemRecordFromCipher(noteCipher).username, null);
  assert.deepEqual(itemRecordFromCipher(noteCipher).uris, []);
  assert.equal(itemRecordFromCipher(noteCipher).hasPasskey, false);
  assert.equal(itemRecordFromCipher(sshCipher).kind, "secret");
  assert.equal(itemRecordFromCipher(sshCipher).hasPasskey, false);
});

test("loginFromCipher requires a login with a password", () => {
  assert.deepEqual(loginFromCipher(loginCipher), {
    username: "octocat",
    password: "s3cret",
  });
  assert.throws(
    () => loginFromCipher(noteCipher),
    (err: unknown) => err instanceof ChaaviError && err.type === "invalid_request",
  );
});

test("passkeyFromCipher maps Bitwarden FIDO2 fields to CDP base64", () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  const credId = Buffer.from("cred-id-bytes");
  const user = Buffer.from("ada@example.com");
  const cipher = {
    id: "pk-1",
    name: "Google",
    type: 1,
    login: {
      username: "ada",
      fido2Credentials: [
        {
          credentialId: credId.toString("base64url"),
          keyType: "public-key",
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
  assert.equal(itemRecordFromCipher(cipher).hasPasskey, true);
  assert.deepEqual(passkeyFromCipher(cipher), {
    credentialId: credId.toString("base64"),
    rpId: "google.com",
    privateKey: der.toString("base64"),
    userHandle: user.toString("base64"),
    signCount: 3,
    resident: true,
  });
});

test("passkeyFromCipher decodes UUID credentialId as 16 bytes", () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  const guid = "550e8400-e29b-41d4-a716-446655440000";
  const cipher = {
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
  };
  const cred = passkeyFromCipher(cipher);
  assert.equal(cred.credentialId, Buffer.from("550e8400e29b41d4a716446655440000", "hex").toString("base64"));
});

test("passkeyFromCipher requires a login with a passkey", () => {
  assert.throws(
    () => passkeyFromCipher(loginCipher),
    (err: unknown) =>
      err instanceof ChaaviError &&
      err.type === "invalid_request" &&
      err.message === "item has no passkey",
  );
  assert.throws(
    () => passkeyFromCipher(noteCipher),
    (err: unknown) => err instanceof ChaaviError && err.type === "invalid_request",
  );
});

test("passkeyFromCipher rejects missing counter or discoverable", () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer;
  const base = {
    id: "pk-2",
    name: "Site",
    type: 1,
    login: {
      username: "ada",
      fido2Credentials: [
        {
          credentialId: Buffer.from("id").toString("base64url"),
          keyAlgorithm: "ECDSA",
          keyCurve: "P-256",
          keyValue: der.toString("base64url"),
          rpId: "example.com",
          userHandle: Buffer.from("u").toString("base64url"),
          counter: 1,
          discoverable: true,
        },
      ],
    },
  };
  const noCounter = structuredClone(base);
  delete (noCounter.login.fido2Credentials[0] as { counter?: number }).counter;
  assert.throws(
    () => passkeyFromCipher(noCounter),
    (err: unknown) =>
      err instanceof ChaaviError && err.message === "passkey is missing counter",
  );
  const noDiscoverable = structuredClone(base);
  delete (noDiscoverable.login.fido2Credentials[0] as { discoverable?: boolean }).discoverable;
  assert.throws(
    () => passkeyFromCipher(noDiscoverable),
    (err: unknown) =>
      err instanceof ChaaviError && err.message === "passkey is missing discoverable",
  );
});

test("secretFromCipher picks the single secret field by type", () => {
  assert.deepEqual(secretFromCipher(loginCipher), { value: "s3cret" });
  assert.deepEqual(secretFromCipher(noteCipher), { value: "hunter2" });
  assert.deepEqual(secretFromCipher(sshCipher), {
    value: "-----BEGIN PRIVATE KEY-----\nabc\n",
  });
  assert.throws(
    () => secretFromCipher({ id: "card-1", name: "Card", type: 3 }),
    (err: unknown) => err instanceof ChaaviError && err.type === "invalid_request",
  );
});

test("filterItems matches q, uri, and kind", () => {
  const items: ItemRecord[] = [
    itemRecordFromCipher(loginCipher),
    itemRecordFromCipher(noteCipher),
    itemRecordFromCipher(sshCipher),
  ];
  assert.equal(filterItems(items, { q: "git" }).length, 1);
  assert.equal(filterItems(items, { q: "octocat" })[0]?.id, "login-1");
  assert.equal(filterItems(items, { uri: "github.com" })[0]?.id, "login-1");
  assert.equal(filterItems(items, { kind: "note" })[0]?.id, "note-1");
  assert.equal(filterItems(items, { kind: "secret" })[0]?.id, "ssh-1");
  assert.equal(filterItems(items, { q: "nope" }).length, 0);
});

test("upsertItem appends or replaces by id", () => {
  const login = itemRecordFromCipher(loginCipher);
  const note = itemRecordFromCipher(noteCipher);
  const once = upsertItem([], login);
  assert.deepEqual(once, [login]);
  const two = upsertItem(once, note);
  assert.deepEqual(two, [login, note]);
  const renamed = { ...login, name: "GitHub renamed" };
  const updated = upsertItem(two, renamed);
  assert.equal(updated.length, 2);
  assert.equal(updated[0]?.name, "GitHub renamed");
  assert.equal(updated[1]?.id, "note-1");
});
