// Contract and interop tests for Chaavi's /v1 API against a running Chaavi (this fork).
// The official Bitwarden CLI is the oracle: what `bw` writes must read the same through /v1,
// and what /v1 writes must read the same through `bw`.
//
// Run against a throwaway vault started with SIGNUPS_ALLOWED=true and
// CHAAVI_EMAIL / CHAAVI_PASSWORD equal to EMAIL / PASSWORD below:
//   CHAAVI_URL=http://localhost:8099 npm test

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const BASE = process.env.CHAAVI_URL ?? "http://localhost:8099";
// Test-only account for a throwaway vault.
const EMAIL = "interop@chaavi.test";
const PASSWORD = "interop-only master password 7";
const ITERATIONS = 600000;

const here = path.dirname(fileURLToPath(import.meta.url));
const BW = path.join(here, "node_modules", "@bitwarden", "cli", "build", "bw.js");
const appData = fs.mkdtempSync(path.join(os.tmpdir(), "chaavi-bw-"));
let session = "";

// ---- Bitwarden client crypto, independent of the Rust code under test ----

const masterKey = crypto.pbkdf2Sync(PASSWORD, EMAIL, ITERATIONS, 32, "sha256");
const expand = (info) => crypto.createHmac("sha256", masterKey).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
const stretched = { enc: expand("enc"), mac: expand("mac") };

function encrypt(plain, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key.enc, iv);
  const data = Buffer.concat([cipher.update(plain), cipher.final()]);
  const mac = crypto.createHmac("sha256", key.mac).update(Buffer.concat([iv, data])).digest();
  return `2.${iv.toString("base64")}|${data.toString("base64")}|${mac.toString("base64")}`;
}

/** Register the test account the way the web vault does (no mail: the token comes back). */
async function register() {
  const verify = await fetch(`${BASE}/identity/accounts/register/send-verification-email`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: EMAIL, name: "Interop", receiveMarketingEmails: false }),
  });
  const token = (await verify.text()).replace(/^"|"$/g, "");
  if (!verify.ok) {
    if (/already exists/i.test(token)) {
      return;
    }
    throw new Error(`register verification failed ${verify.status}: ${token}`);
  }
  const userKey = crypto.randomBytes(64);
  const key = { enc: userKey.subarray(0, 32), mac: userKey.subarray(32) };
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const body = {
    email: EMAIL,
    emailVerificationToken: token,
    masterPasswordHash: crypto.pbkdf2Sync(masterKey, PASSWORD, 1, 32, "sha256").toString("base64"),
    masterPasswordHint: null,
    key: encrypt(userKey, stretched),
    kdf: 0,
    kdfIterations: ITERATIONS,
    keys: {
      publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
      encryptedPrivateKey: encrypt(privateKey.export({ type: "pkcs8", format: "der" }), key),
    },
  };
  const res = await fetch(`${BASE}/identity/accounts/register/finish`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok && !/already exists/i.test(text)) {
    throw new Error(`register failed ${res.status}: ${text}`);
  }
}

// ---- the oracle ----

function bw(args, { input, raw = false } = {}) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, BITWARDENCLI_APPDATA_DIR: appData, BW_SESSION: session, NODE_NO_WARNINGS: "1" };
    const child = execFile(process.execPath, [BW, "--nointeraction", ...args], { env, maxBuffer: 16 << 20 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`bw ${args[0]} ${args[1] ?? ""} failed: ${stderr || err.message}`));
        return;
      }
      resolve(raw ? stdout : stdout.trim() === "" ? null : JSON.parse(stdout));
    });
    if (input !== undefined) {
      child.stdin.end(input);
    }
  });
}

const encodeJson = (value) => Buffer.from(JSON.stringify(value)).toString("base64");

/** An item as bw sees it after pulling the server (bw reads its local cache otherwise). */
async function oracleItem(id) {
  await bw(["sync"], { raw: true });
  return bw(["get", "item", id]);
}

// ---- the API under test ----

async function api(method, url, body) {
  const res = await fetch(`${BASE}${url}`, {
    method,
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text === "" ? null : JSON.parse(text), text, headers: res.headers };
}

async function listed(id) {
  const { body } = await api("GET", "/v1/items");
  return body.items.find((item) => item.id === id);
}

const TOTP = "JBSWY3DPEHPK3PXP";

test("setup: register, log in with bw, account is ready", async () => {
  await register();
  await bw(["config", "server", BASE], { raw: true });
  session = (await bw(["login", EMAIL, PASSWORD, "--raw"], { raw: true })).trim();
  assert.ok(session.length > 20);
  const health = await api("GET", "/health");
  assert.deepEqual(health.body, { status: "ok", vault: "ready" });
  assert.ok(health.headers.get("x-request-id"));
});

let folderId;
let bwLoginId;

test("items bw writes list and reveal through /v1 without leaking secrets", async () => {
  folderId = (await bw(["create", "folder", encodeJson({ name: "Dev" })])).id;
  const login = await bw([
    "create",
    "item",
    encodeJson({
      type: 1,
      name: "GitHub",
      notes: "recovery codes in the safe",
      folderId,
      favorite: true,
      fields: [
        { name: "Team", value: "core", type: 0 },
        { name: "Pin", value: "4321", type: 1 },
        { name: "Admin", value: "true", type: 2 },
        { name: "User link", value: null, type: 3, linkedId: 100 },
      ],
      login: {
        username: "ankur",
        password: "gh-password-1",
        totp: TOTP,
        uris: [{ uri: "https://github.com/login", match: 1 }, { uri: "https://gist.github.com", match: null }],
      },
    }),
  ]);
  bwLoginId = login.id;

  const item = await listed(login.id);
  assert.deepEqual(
    { ...item, revisionDate: undefined },
    {
      id: login.id,
      name: "GitHub",
      folderId,
      favorite: true,
      hasNotes: true,
      fields: [
        { name: "Team", type: "text", value: "core" },
        { name: "Pin", type: "hidden", hasValue: true },
        { name: "Admin", type: "boolean", value: true },
        { name: "User link", type: "linked", linkedTo: "username" },
      ],
      revisionDate: undefined,
      type: "login",
      login: {
        username: "ankur",
        uris: [
          { uri: "https://github.com/login", match: "host" },
          { uri: "https://gist.github.com", match: "default" },
        ],
        hasPassword: true,
        hasTotp: true,
        passkeys: [],
      },
    },
  );
  assert.equal(item.revisionDate, login.revisionDate);
  const list = await api("GET", "/v1/items");
  for (const secret of ["gh-password-1", "4321", TOTP, "recovery codes"]) {
    assert.equal(list.text.includes(secret), false, `list leaked ${secret}`);
  }

  assert.deepEqual((await api("POST", `/v1/items/${login.id}/login`)).body, { username: "ankur", password: "gh-password-1" });
  assert.deepEqual((await api("POST", `/v1/items/${login.id}/reveal`, { field: "password" })).body, { value: "gh-password-1" });
  assert.deepEqual((await api("POST", `/v1/items/${login.id}/reveal`, { field: "notes" })).body, { value: "recovery codes in the safe" });
  assert.deepEqual((await api("POST", `/v1/items/${login.id}/reveal`, { field: "custom", name: "Pin" })).body, { value: "4321" });
  const totp = await api("POST", `/v1/items/${login.id}/totp`);
  const oracle = (await bw(["get", "totp", login.id], { raw: true })).trim();
  assert.equal(totp.status, 200);
  assert.match(totp.body.code, /^\d{6}$/);
  if (totp.body.remaining > 2) {
    assert.equal(totp.body.code, oracle);
  }
});

test("cards, identities, notes and SSH keys from bw map like the adapter", async () => {
  const card = await bw([
    "create",
    "item",
    encodeJson({ type: 3, name: "Visa", card: { cardholderName: "A Desai", brand: "Visa", number: "4111111111111111", expMonth: "8", expYear: "2030", code: "123" } }),
  ]);
  const identity = await bw([
    "create",
    "item",
    encodeJson({ type: 4, name: "Me", identity: { firstName: "Ankur", lastName: "Desai", city: "Boston", ssn: "123-45-6789" } }),
  ]);
  const note = await bw(["create", "item", encodeJson({ type: 2, name: "Plain note", notes: "hello", secureNote: { type: 0 } })]);
  const ssh = await bw([
    "create",
    "item",
    encodeJson({ type: 5, name: "Server key", sshKey: { privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n", publicKey: "ssh-ed25519 AAAA", keyFingerprint: "SHA256:abc" } }),
  ]);

  const cardItem = await listed(card.id);
  assert.deepEqual(cardItem.card, { cardholderName: "A Desai", brand: "Visa", expMonth: "8", expYear: "2030", hasNumber: true, hasCode: true });
  assert.deepEqual((await api("POST", `/v1/items/${card.id}/card`)).body, {
    cardholderName: "A Desai",
    brand: "Visa",
    number: "4111111111111111",
    expMonth: "8",
    expYear: "2030",
    code: "123",
  });
  const identityItem = await listed(identity.id);
  assert.equal(identityItem.identity.firstName, "Ankur");
  assert.equal(identityItem.identity.hasSsn, true);
  assert.equal(identityItem.identity.ssn, undefined);
  assert.deepEqual((await api("POST", `/v1/items/${identity.id}/reveal`, { field: "ssn" })).body, { value: "123-45-6789" });
  assert.equal((await listed(note.id)).type, "note");
  const sshItem = await listed(ssh.id);
  assert.deepEqual(sshItem.sshKey, { publicKey: "ssh-ed25519 AAAA", keyFingerprint: "SHA256:abc", hasPrivateKey: true });

  const filtered = await api("GET", "/v1/items?type=card");
  assert.deepEqual(filtered.body.items.map((i) => i.id), [card.id]);
  const byUri = await api("GET", "/v1/items?uri=gist");
  assert.deepEqual(byUri.body.items.map((i) => i.id), [bwLoginId]);
  const byQ = await api("GET", "/v1/items?q=boston");
  assert.deepEqual(byQ.body.items.map((i) => i.id), [identity.id]);
});

test("a login /v1 creates reads back identically through bw", async () => {
  const created = await api("POST", "/v1/items", {
    type: "login",
    name: "Made by Chaavi",
    folderId,
    notes: "n1",
    fields: [{ name: "Recovery", type: "hidden", value: "rc-1" }],
    login: { username: "agent", uris: [{ uri: "https://example.com", match: "exact" }], length: 24, special: false },
  });
  assert.equal(created.status, 201);
  const id = created.body.id;
  const fill = (await api("POST", `/v1/items/${id}/login`)).body;
  assert.equal(fill.password.length, 24);

  const oracle = await oracleItem(id);
  assert.equal(oracle.name, "Made by Chaavi");
  assert.equal(oracle.folderId, folderId);
  assert.equal(oracle.notes, "n1");
  assert.equal(oracle.login.username, "agent");
  assert.equal(oracle.login.password, fill.password);
  assert.equal(oracle.login.uris[0].uri, "https://example.com");
  assert.equal(oracle.login.uris[0].match, 3);
  assert.deepEqual(oracle.fields.map((f) => [f.name, f.value, f.type]), [["Recovery", "rc-1", 1]]);
});

test("PATCH changes only what it names, keeps hidden values, and records password history", async () => {
  const patched = await api("PATCH", `/v1/items/${bwLoginId}`, {
    login: { password: "gh-password-2" },
    favorite: false,
    folderId: null,
    fields: [{ name: "Pin", type: "hidden" }, { name: "Team", type: "text", value: "platform" }],
  });
  assert.equal(patched.status, 200, patched.text);
  assert.equal(patched.body.favorite, false);
  assert.equal(patched.body.folderId, null);

  const oracle = await oracleItem(bwLoginId);
  assert.equal(oracle.login.password, "gh-password-2");
  assert.equal(oracle.login.username, "ankur");
  assert.equal(oracle.login.totp, TOTP);
  assert.equal(oracle.notes, "recovery codes in the safe");
  assert.deepEqual(oracle.fields.map((f) => [f.name, f.value]), [["Pin", "4321"], ["Team", "platform"]]);
  assert.equal(oracle.passwordHistory[0].password, "gh-password-1");
  assert.ok(oracle.passwordHistory.some((h) => h.password === "Admin: true") === false);

  const wrong = await api("PATCH", `/v1/items/${bwLoginId}`, { card: { brand: "Visa" } });
  assert.equal(wrong.status, 422);
  assert.equal(wrong.body.error.type, "invalid_request");
});

test("secrets: PUT creates then updates the named Secure Note, reveal reads it, bw agrees", async () => {
  const first = await api("PUT", "/v1/secrets/Stripe%20API%20key", { value: "sk_test_1", notes: "test mode" });
  assert.equal(first.status, 201, first.text);
  assert.equal(first.body.created, true);
  const second = await api("PUT", "/v1/secrets/stripe api key", { value: "sk_test_2" });
  assert.equal(second.status, 200);
  assert.equal(second.body.created, false);
  assert.equal(second.body.item.id, first.body.item.id);
  assert.deepEqual((await api("POST", "/v1/secrets/STRIPE%20API%20KEY/reveal")).body, { value: "sk_test_2" });

  const oracle = await oracleItem(first.body.item.id);
  assert.equal(oracle.type, 2);
  assert.equal(oracle.notes, "test mode");
  assert.deepEqual(oracle.fields.map((f) => [f.name, f.value, f.type]), [["Secret", "sk_test_2", 1]]);
  assert.equal((await api("POST", "/v1/secrets/nope/reveal")).status, 404);
});

test("new item types round-trip through bw (bank account)", async () => {
  const created = await api("POST", "/v1/items", {
    type: "bankAccount",
    name: "Checking",
    bankAccount: { bankName: "Chase", accountNumber: "000123456789", routingNumber: "021000021" },
  });
  assert.equal(created.status, 201, created.text);
  assert.deepEqual((await api("POST", `/v1/items/${created.body.id}/reveal`, { field: "accountNumber" })).body, { value: "000123456789" });
  const oracle = await oracleItem(created.body.id);
  assert.equal(oracle.type, 6);
  assert.equal(oracle.bankAccount.bankName, "Chase");
  assert.equal(oracle.bankAccount.accountNumber, "000123456789");
});

test("an SSH key /v1 generates is a valid OpenSSH key bw can read", async () => {
  const created = await api("POST", "/v1/items", { type: "sshKey", name: "Generated" });
  assert.equal(created.status, 201, created.text);
  const oracle = await oracleItem(created.body.id);
  assert.equal(oracle.sshKey.keyFingerprint, created.body.sshKey.keyFingerprint);

  // Read the openssh-key-v1 container by hand and prove the pair: sign with the seed, verify
  // with the public key bw lists.
  const pem = oracle.sshKey.privateKey.trim().split("\n");
  assert.equal(pem[0], "-----BEGIN OPENSSH PRIVATE KEY-----");
  const body = Buffer.from(pem.slice(1, -1).join(""), "base64");
  let at = 0;
  const take = () => {
    const len = body.readUInt32BE(at);
    const out = body.subarray(at + 4, at + 4 + len);
    at += 4 + len;
    return out;
  };
  assert.equal(body.subarray(0, 15).toString("latin1"), "openssh-key-v1\0");
  at = 15;
  assert.equal(take().toString(), "none");
  assert.equal(take().toString(), "none");
  take();
  assert.equal(body.readUInt32BE(at), 1);
  at += 4;
  const publicBlob = take();
  assert.equal(`ssh-ed25519 ${publicBlob.toString("base64")}`, oracle.sshKey.publicKey);
  const fingerprint = `SHA256:${crypto.createHash("sha256").update(publicBlob).digest("base64").replace(/=+$/, "")}`;
  assert.equal(fingerprint, oracle.sshKey.keyFingerprint);
  const section = take();
  assert.equal(section.readUInt32BE(0), section.readUInt32BE(4));
  const read = (buf, offset) => [buf.subarray(offset + 4, offset + 4 + buf.readUInt32BE(offset)), offset + 4 + buf.readUInt32BE(offset)];
  let [type, next] = read(section, 8);
  assert.equal(type.toString(), "ssh-ed25519");
  let pub;
  [pub, next] = read(section, next);
  let secret;
  [secret] = read(section, next);
  assert.equal(secret.length, 64);
  assert.deepEqual(secret.subarray(32), pub);
  const jwk = { kty: "OKP", crv: "Ed25519", d: secret.subarray(0, 32).toString("base64url"), x: pub.toString("base64url") };
  const signature = crypto.sign(null, Buffer.from("chaavi"), crypto.createPrivateKey({ key: jwk, format: "jwk" }));
  const publicKey = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicBlob.subarray(publicBlob.length - 32).toString("base64url") }, format: "jwk" });
  assert.ok(crypto.verify(null, Buffer.from("chaavi"), publicKey, signature));
});

test("GET /v1/items?folder= takes subfolders, ignores case, and an unknown folder is a 404", async () => {
  const ids = async (query) => (await api("GET", `/v1/items${query}`)).body.items.map((item) => item.id);
  const nested = await api("POST", "/v1/folders", { name: "Dev/api" });
  const note = await api("POST", "/v1/items", { type: "note", name: "In nested", folderId: nested.body.id });
  assert.deepEqual(await ids("?folder=Dev/api"), [note.body.id]);
  const dev = await ids("?folder=dev");
  assert.ok(dev.includes(note.body.id));
  assert.ok(dev.length > 1, "Dev holds the login made earlier too");
  assert.deepEqual(await ids("?folder=DEV&type=note"), [note.body.id]);
  const missing = await api("GET", "/v1/items?folder=Nope");
  assert.equal(missing.status, 404);
  assert.equal(missing.body.error.type, "not_found");
  assert.equal((await api("GET", "/v1/items?folder=%20")).status, 422);
});

test("GET /v1/events announces a change made through /v1 and one made by a Bitwarden client", async () => {
  const controller = new AbortController();
  const res = await fetch(`${BASE}/v1/events`, { signal: controller.signal });
  assert.equal(res.headers.get("content-type"), "text/event-stream");
  let received = "";
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  void (async () => {
    try {
      for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) {
        received += decoder.decode(chunk.value);
      }
    } catch {
      // aborted below
    }
  })();
  const changes = () => received.split("\n").filter((line) => line.startsWith("data:")).map((line) => JSON.parse(line.slice(5)));
  const waitFor = async (count) => {
    for (let waited = 0; waited < 8000 && changes().length < count; waited += 200) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    assert.ok(changes().length >= count, `expected ${count} change events, got ${changes().length}`);
  };
  await new Promise((resolve) => setTimeout(resolve, 1500));
  assert.equal(changes().length, 0, "a quiet vault is quiet");
  assert.match(received, /^: ?connected/);

  await api("POST", "/v1/items", { type: "note", name: "Event from Chaavi" });
  await waitFor(1);
  assert.equal(changes()[0].type, "changed");
  assert.ok(!Number.isNaN(Date.parse(changes()[0].at)));

  await bw(["create", "item", encodeJson({ type: 2, name: "Event from bw", secureNote: { type: 0 } })]);
  await waitFor(2);
  controller.abort();
});

test("folders: create, rename, delete through /v1; bw sees each", async () => {
  const created = await api("POST", "/v1/folders", { name: "  Finance  " });
  assert.equal(created.status, 201);
  assert.equal(created.body.name, "Finance");
  const renamed = await api("PATCH", `/v1/folders/${created.body.id}`, { name: "Money" });
  assert.deepEqual(renamed.body, { id: created.body.id, name: "Money" });
  await bw(["sync"], { raw: true });
  const folders = await bw(["list", "folders"]);
  assert.ok(folders.some((f) => f.id === created.body.id && f.name === "Money"));
  const listedFolders = (await api("GET", "/v1/folders")).body.folders;
  assert.deepEqual(
    listedFolders.map((f) => f.name),
    folders.filter((f) => f.id !== null && f.id !== "").map((f) => f.name),
  );
  assert.equal((await api("DELETE", `/v1/folders/${created.body.id}`)).status, 204);
  await bw(["sync"], { raw: true });
  assert.equal((await bw(["list", "folders"])).some((f) => f.id === created.body.id), false);
});

test("DELETE moves an item to the trash, where bw finds it", async () => {
  const created = await api("POST", "/v1/items", { type: "note", name: "Disposable" });
  assert.equal((await api("DELETE", `/v1/items/${created.body.id}`)).status, 204);
  assert.equal(await listed(created.body.id), undefined);
  assert.equal((await api("GET", `/v1/items/${created.body.id}`)).status, 404);
  await bw(["sync"], { raw: true });
  const trash = await bw(["list", "items", "--trash"]);
  assert.ok(trash.some((i) => i.id === created.body.id));
});

test("list order matches bw list items", async () => {
  await bw(["sync"], { raw: true });
  const oracle = await bw(["list", "items"]);
  const mine = (await api("GET", "/v1/items")).body.items;
  assert.deepEqual(mine.map((i) => i.name), oracle.map((i) => i.name));
});

test("errors keep the contract shape and codes", async () => {
  const missing = await api("GET", "/v1/items/00000000-0000-4000-8000-000000000000");
  assert.deepEqual(missing.body, { error: { type: "not_found", message: "item not found" } });
  assert.equal(missing.status, 404);
  assert.equal((await api("GET", "/v1/items/not-a-uuid")).status, 422);
  assert.equal((await api("GET", "/v1/items?bogus=1")).status, 422);
  assert.equal((await api("POST", `/v1/items/${bwLoginId}/card`)).status, 422);
  const badFolder = await api("POST", "/v1/items", { type: "note", name: "x", folderId: "00000000-0000-4000-8000-000000000000" });
  assert.equal(badFolder.status, 422);
  assert.equal(badFolder.body.error.message, "folderId does not name a folder");
  assert.equal((await api("POST", "/v1/items", { type: "note", name: "x", extra: 1 })).status, 422);
  assert.equal((await api("POST", "/v1/generate", { length: 8 })).status, 422);
  assert.equal((await api("POST", "/v1/generate")).body.password.length, 20);
});
