import assert from "node:assert/strict";
import { test } from "node:test";
import { ChaaviError } from "../src/errors.js";
import type { ItemRecord } from "../src/types/domain.js";
import {
  filterItems,
  itemRecordFromCipher,
  loginFromCipher,
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
  });
});

test("itemRecordFromCipher maps note and ssh kinds", () => {
  assert.equal(itemRecordFromCipher(noteCipher).kind, "note");
  assert.equal(itemRecordFromCipher(noteCipher).username, null);
  assert.deepEqual(itemRecordFromCipher(noteCipher).uris, []);
  assert.equal(itemRecordFromCipher(sshCipher).kind, "secret");
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
