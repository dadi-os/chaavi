import assert from "node:assert/strict";
import { after, beforeEach, test } from "node:test";
import { buildApp } from "../src/app.js";
import { BwVault } from "../src/vault/bw.js";
import {
  BANK_ID,
  CARD_ID,
  DEV_FOLDER,
  FINANCE_FOLDER,
  FakeBw,
  IDENTITY_ID,
  LICENSE_ID,
  LOGIN_ID,
  MISSING_ID,
  NOTE_ID,
  PASSKEY_ID,
  PASSPORT_ID,
  SAMPLE_SECRETS,
  SECRET_NOTE_ID,
  SSH_ID,
  TOTP_SEED,
  makeConfig,
  memoryLogger,
  sampleCiphers,
  sampleFolders,
} from "./helpers.js";

const fake = new FakeBw();
const log = memoryLogger();
const readyConfig = makeConfig();
const vault = new BwVault(readyConfig, log, fake.run);
const app = await buildApp(readyConfig, { vault });

const emptyConfig = makeConfig();
emptyConfig.env.vaultUrl = "";
emptyConfig.env.bw = { clientId: "", clientSecret: "", password: "", appDataDir: "" };
const unconfigured = await buildApp(emptyConfig, { vault });

beforeEach(async () => {
  fake.seed(sampleCiphers(), sampleFolders());
  await vault.refreshCatalog();
});

after(async () => {
  await app.close();
  await unconfigured.close();
});

/** Assert a response body carries none of the sample secret values. */
function assertNoSecrets(body: string): void {
  for (const secret of SAMPLE_SECRETS) {
    assert.equal(body.includes(secret), false, `response leaked ${secret}`);
  }
}

test("GET /health reports ready vs unconfigured without calling the vault", async () => {
  const up = await app.inject({ method: "GET", url: "/health" });
  assert.deepEqual(up.json(), { status: "ok", vault: "ready" });
  const down = await unconfigured.inject({ method: "GET", url: "/health" });
  assert.deepEqual(down.json(), { status: "ok", vault: "unconfigured" });
});

test("GET /v1/items is 503 and names the first empty vault variable", async () => {
  const config = makeConfig();
  config.env.bw = { ...config.env.bw, clientSecret: "" };
  const bare = await buildApp(config, {
    vault: new BwVault(config, memoryLogger(), async () => {
      throw new Error("bw must not run");
    }),
  });
  try {
    const res = await bare.inject({ method: "GET", url: "/v1/items" });
    assert.equal(res.statusCode, 503);
    assert.deepEqual(res.json().error, { type: "vault_unconfigured", message: "BW_CLIENTSECRET is not set" });
  } finally {
    await bare.close();
  }
});

test("GET /v1/items lists every type with its public fields and no secret value", async () => {
  const res = await app.inject({ method: "GET", url: "/v1/items" });
  assert.equal(res.statusCode, 200);
  assertNoSecrets(res.body);
  const items = res.json().items as Array<Record<string, any>>;
  assert.deepEqual(items.map((item) => item.type).sort(), [
    "bankAccount",
    "card",
    "driversLicense",
    "identity",
    "login",
    "login",
    "note",
    "note",
    "passport",
    "sshKey",
  ]);

  const github = items.find((item) => item.id === LOGIN_ID)!;
  assert.equal(github.folderId, DEV_FOLDER);
  assert.equal(github.favorite, true);
  assert.deepEqual(github.login, {
    username: "octocat",
    uris: [{ uri: "https://github.com", match: "default" }],
    hasPassword: true,
    hasTotp: true,
    passkeys: [],
  });
  assert.deepEqual(github.fields, [
    { name: "Recovery", type: "hidden", hasValue: true },
    { name: "Org", type: "text", value: "dadi" },
    { name: "Admin", type: "boolean", value: true },
    { name: "User", type: "linked", linkedTo: "username" },
  ]);

  const google = items.find((item) => item.id === PASSKEY_ID)!;
  assert.deepEqual(google.login.passkeys, [
    { rpId: "google.com", userName: "ada@example.com", creationDate: "2026-01-01T00:00:00Z" },
  ]);
  assert.equal(google.login.uris[0].match, "domain");
  assert.equal(google.login.hasPassword, false);

  const card = items.find((item) => item.id === CARD_ID)!;
  assert.deepEqual(card.card, {
    cardholderName: "Ada Lovelace",
    brand: "Visa",
    expMonth: "8",
    expYear: "2029",
    hasNumber: true,
    hasCode: true,
  });
  assert.deepEqual(card.fields, [{ name: "Holder", type: "linked", linkedTo: "cardholderName" }]);

  const identity = items.find((item) => item.id === IDENTITY_ID)!;
  assert.equal(identity.identity.city, "East Lansing");
  assert.equal(identity.identity.hasSsn, true);
  assert.equal(identity.identity.hasPassportNumber, true);
  assert.equal(identity.identity.hasLicenseNumber, true);

  const ssh = items.find((item) => item.id === SSH_ID)!;
  assert.deepEqual(ssh.sshKey, { publicKey: "ssh-ed25519 AAAAtest", keyFingerprint: "SHA256:test", hasPrivateKey: true });

  const bank = items.find((item) => item.id === BANK_ID)!;
  assert.deepEqual(bank.bankAccount, {
    bankName: "Acme Bank",
    nameOnAccount: "Ada Lovelace",
    accountType: "checking",
    routingNumber: "011000015",
    branchNumber: null,
    swiftCode: "ACMEUS33",
    bankContactPhone: null,
    hasAccountNumber: true,
    hasPin: true,
    hasIban: true,
  });
  const license = items.find((item) => item.id === LICENSE_ID)!;
  assert.equal(license.driversLicense.issuingState, "MI");
  assert.equal(license.driversLicense.hasLicenseNumber, true);
  const passport = items.find((item) => item.id === PASSPORT_ID)!;
  assert.equal(passport.passport.nationality, "USA");
  assert.equal(passport.passport.hasPassportNumber, true);
  assert.equal(passport.passport.hasNationalIdentificationNumber, true);

  const note = items.find((item) => item.id === NOTE_ID)!;
  assert.equal(note.hasNotes, true);
  assert.equal("notes" in note, false);
});

test("GET /v1/items filters by q, uri and type", async () => {
  const ids = async (query: string) =>
    ((await app.inject({ method: "GET", url: `/v1/items${query}` })).json().items as Array<{ id: string }>).map((item) => item.id);
  assert.deepEqual(await ids("?q=octo"), [LOGIN_ID]);
  assert.deepEqual(await ids("?q=visa"), [CARD_ID]);
  assert.deepEqual(await ids("?q=dadi"), [LOGIN_ID]);
  assert.deepEqual(await ids("?q=lovelace"), [CARD_ID, IDENTITY_ID, BANK_ID, LICENSE_ID, PASSPORT_ID]);
  assert.deepEqual(await ids("?q=acme"), [BANK_ID]);
  assert.deepEqual(await ids("?type=passport"), [PASSPORT_ID]);
  assert.deepEqual(await ids("?uri=github.com"), [LOGIN_ID]);
  assert.deepEqual(await ids("?type=sshKey"), [SSH_ID]);
  assert.deepEqual(await ids("?type=note"), [NOTE_ID, SECRET_NOTE_ID]);
  assert.deepEqual(await ids("?q=nope"), []);
  const bad = await app.inject({ method: "GET", url: "/v1/items?kind=login" });
  assert.equal(bad.statusCode, 422);
  assert.equal(bad.json().error.type, "invalid_request");
});

test("GET /v1/items/:id returns one item without secrets; unknown is 404", async () => {
  const res = await app.inject({ method: "GET", url: `/v1/items/${IDENTITY_ID}` });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().identity.firstName, "Ada");
  assertNoSecrets(res.body);
  const missing = await app.inject({ method: "GET", url: `/v1/items/${MISSING_ID}` });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.json().error.type, "not_found");
  const notUuid = await app.inject({ method: "GET", url: "/v1/items/nope" });
  assert.equal(notUuid.statusCode, 422);
});

test("POST /v1/items creates a login with a generated password it never returns", async () => {
  const res = await app.inject({
    method: "POST",
    url: "/v1/items",
    payload: {
      type: "login",
      name: "Greenhouse",
      folderId: DEV_FOLDER,
      login: { username: "ada@example.com", uris: [{ uri: "https://job-boards.greenhouse.io", match: "host" }], length: 24 },
      fields: [{ name: "Pin", type: "hidden", value: "4242" }],
    },
  });
  assert.equal(res.statusCode, 201);
  const item = res.json();
  assert.equal(item.type, "login");
  assert.equal(item.folderId, DEV_FOLDER);
  assert.deepEqual(item.login.uris, [{ uri: "https://job-boards.greenhouse.io", match: "host" }]);
  assert.equal(item.login.hasPassword, true);
  assert.deepEqual(item.fields, [{ name: "Pin", type: "hidden", hasValue: true }]);
  assert.equal(res.body.includes("4242"), false);
  const stored = fake.stored(item.id);
  assert.equal(String(stored.login?.password).length, 24);

  const listed = await app.inject({ method: "GET", url: `/v1/items/${item.id}` });
  assert.equal(listed.statusCode, 200);
});

test("POST /v1/items creates a note, card, identity and generated SSH key", async () => {
  const note = await app.inject({ method: "POST", url: "/v1/items", payload: { type: "note", name: "Lockbox", notes: "code is in the drawer" } });
  assert.equal(note.statusCode, 201);
  assert.equal(note.json().hasNotes, true);
  assert.equal(note.body.includes("drawer"), false);
  assert.deepEqual(fake.stored(note.json().id).secureNote, { type: 0 });

  const card = await app.inject({
    method: "POST",
    url: "/v1/items",
    payload: { type: "card", name: "Amex", card: { cardholderName: "Ada", brand: "Amex", number: "3782 822463 10005", expMonth: "02", expYear: "2028", code: "4321" } },
  });
  assert.equal(card.statusCode, 201);
  assert.equal(card.json().card.expMonth, "2");
  assert.equal(card.body.includes("378282246310005"), false);
  assert.equal((fake.stored(card.json().id).card as Record<string, unknown>).number, "378282246310005");

  const identity = await app.inject({
    method: "POST",
    url: "/v1/items",
    payload: { type: "identity", name: "Work", identity: { firstName: "Ada", company: "Analytical", ssn: "111-22-3333" } },
  });
  assert.equal(identity.statusCode, 201);
  assert.equal(identity.json().identity.company, "Analytical");
  assert.equal(identity.json().identity.hasSsn, true);
  assert.equal(identity.body.includes("111-22-3333"), false);

  const bank = await app.inject({
    method: "POST",
    url: "/v1/items",
    payload: { type: "bankAccount", name: "Savings", bankAccount: { bankName: "Acme", accountNumber: "999000111", pin: "0000" } },
  });
  assert.equal(bank.statusCode, 201);
  assert.equal(bank.json().bankAccount.bankName, "Acme");
  assert.equal(bank.json().bankAccount.hasAccountNumber, true);
  assert.equal(bank.body.includes("999000111"), false);
  assert.equal((fake.stored(bank.json().id).bankAccount as Record<string, unknown>).accountNumber, "999000111");

  const license = await app.inject({
    method: "POST",
    url: "/v1/items",
    payload: { type: "driversLicense", name: "License", driversLicense: { lastName: "Lovelace", licenseNumber: "L-1" } },
  });
  assert.equal(license.statusCode, 201);
  assert.equal(license.json().driversLicense.hasLicenseNumber, true);

  const passport = await app.inject({
    method: "POST",
    url: "/v1/items",
    payload: { type: "passport", name: "Passport", passport: { surname: "Lovelace", passportNumber: "P-1" } },
  });
  assert.equal(passport.statusCode, 201);
  assert.equal(passport.json().passport.surname, "Lovelace");
  assert.equal(passport.body.includes("P-1"), false);

  const ssh = await app.inject({ method: "POST", url: "/v1/items", payload: { type: "sshKey", name: "New key" } });
  assert.equal(ssh.statusCode, 201);
  assert.match(ssh.json().sshKey.publicKey, /^ssh-ed25519 /);
  assert.match(ssh.json().sshKey.keyFingerprint, /^SHA256:/);
  assert.equal(ssh.body.includes("PRIVATE KEY"), false);
  assert.match(String((fake.stored(ssh.json().id).sshKey as Record<string, unknown>).privateKey), /^-----BEGIN OPENSSH PRIVATE KEY-----/);
});

test("POST /v1/items rejects invalid bodies with invalid_request", async () => {
  const cases: unknown[] = [
    { type: "login", name: "x", surprise: true },
    { type: "bank", name: "x" },
    { type: "login", name: "x", login: { password: "given-password", length: 20 } },
    { type: "card", name: "x", card: { number: "12" } },
    { type: "card", name: "x", card: { expMonth: "13" } },
    { type: "note", name: "x", fields: [{ name: "a", type: "text", value: "1" }, { name: "a", type: "text", value: "2" }] },
    { type: "note", name: "x", fields: [{ name: "a", type: "linked", linkedTo: "password" }] },
    { type: "card", name: "x", fields: [{ name: "a", type: "linked", linkedTo: "password" }] },
    { type: "note", name: "x", fields: [{ name: "a", type: "hidden" }] },
    { type: "note", name: "x", folderId: MISSING_ID },
    { type: "login", name: "x", login: { totp: "not base32 !!" } },
    { type: "sshKey", name: "x", sshKey: { privateKey: "only this" } },
  ];
  for (const payload of cases) {
    const res = await app.inject({ method: "POST", url: "/v1/items", payload: payload as Record<string, unknown> });
    assert.equal(res.statusCode, 422, JSON.stringify(payload));
    assert.equal(res.json().error.type, "invalid_request");
  }
});

test("PATCH /v1/items/:id edits fields, keeps an untouched hidden value, moves and stars", async () => {
  const res = await app.inject({
    method: "PATCH",
    url: `/v1/items/${LOGIN_ID}`,
    payload: {
      name: "GitHub Work",
      login: { username: "octo", uris: [{ uri: "https://github.com/login" }] },
      fields: [
        { name: "Recovery", type: "hidden" },
        { name: "Org", type: "text", value: "fliks" },
      ],
    },
  });
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().name, "GitHub Work");
  assert.equal(res.json().login.username, "octo");
  assert.deepEqual(res.json().fields, [
    { name: "Recovery", type: "hidden", hasValue: true },
    { name: "Org", type: "text", value: "fliks" },
  ]);
  assertNoSecrets(res.body);
  const recovery = await app.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/reveal`, payload: { field: "custom", name: "Recovery" } });
  assert.deepEqual(recovery.json(), { value: "hidden-recovery-code" });
  assert.equal(fake.stored(LOGIN_ID).login?.password, "hunter2");

  const moved = await app.inject({ method: "PATCH", url: `/v1/items/${CARD_ID}`, payload: { folderId: DEV_FOLDER, favorite: true } });
  assert.equal(moved.statusCode, 200);
  assert.equal(moved.json().folderId, DEV_FOLDER);
  assert.equal(moved.json().favorite, true);
  const listed = await app.inject({ method: "GET", url: `/v1/items/${CARD_ID}` });
  assert.equal(listed.json().folderId, DEV_FOLDER);

  const out = await app.inject({ method: "PATCH", url: `/v1/items/${CARD_ID}`, payload: { folderId: null } });
  assert.equal(out.json().folderId, null);

  const cleared = await app.inject({ method: "PATCH", url: `/v1/items/${CARD_ID}`, payload: { card: { code: "" } } });
  assert.equal(cleared.json().card.hasCode, false);

  const bank = await app.inject({ method: "PATCH", url: `/v1/items/${BANK_ID}`, payload: { bankAccount: { bankName: "Acme Credit Union", pin: "" } } });
  assert.equal(bank.statusCode, 200);
  assert.equal(bank.json().bankAccount.bankName, "Acme Credit Union");
  assert.equal(bank.json().bankAccount.hasPin, false);
  assert.equal(bank.json().bankAccount.hasAccountNumber, true);
});

test("PATCH /v1/items/:id refuses a mismatched type, an empty body, and unknown ids", async () => {
  const mismatch = await app.inject({ method: "PATCH", url: `/v1/items/${LOGIN_ID}`, payload: { card: { brand: "Visa" } } });
  assert.equal(mismatch.statusCode, 422);
  assert.equal(mismatch.json().error.message, "card fields do not apply to a login item");
  const empty = await app.inject({ method: "PATCH", url: `/v1/items/${LOGIN_ID}`, payload: {} });
  assert.equal(empty.statusCode, 422);
  const newHidden = await app.inject({
    method: "PATCH",
    url: `/v1/items/${LOGIN_ID}`,
    payload: { fields: [{ name: "Brand new", type: "hidden" }] },
  });
  assert.equal(newHidden.statusCode, 422);
  const folder = await app.inject({ method: "PATCH", url: `/v1/items/${LOGIN_ID}`, payload: { folderId: MISSING_ID } });
  assert.equal(folder.statusCode, 422);
  const missing = await app.inject({ method: "PATCH", url: `/v1/items/${MISSING_ID}`, payload: { name: "x" } });
  assert.equal(missing.statusCode, 404);
});

test("DELETE /v1/items/:id deletes any type", async () => {
  for (const id of [CARD_ID, NOTE_ID, SSH_ID]) {
    const res = await app.inject({ method: "DELETE", url: `/v1/items/${id}` });
    assert.equal(res.statusCode, 204);
    const gone = await app.inject({ method: "GET", url: `/v1/items/${id}` });
    assert.equal(gone.statusCode, 404);
  }
  const missing = await app.inject({ method: "DELETE", url: `/v1/items/${MISSING_ID}` });
  assert.equal(missing.statusCode, 404);
});

test("POST /v1/items/:id/reveal returns one secret and refuses what the item lacks", async () => {
  const reveal = (id: string, payload: Record<string, unknown>) =>
    app.inject({ method: "POST", url: `/v1/items/${id}/reveal`, payload });
  assert.deepEqual((await reveal(LOGIN_ID, { field: "password" })).json(), { value: "hunter2" });
  assert.deepEqual((await reveal(LOGIN_ID, { field: "totp" })).json(), { value: TOTP_SEED });
  assert.deepEqual((await reveal(NOTE_ID, { field: "notes" })).json(), { value: "wifi-note-body" });
  assert.deepEqual((await reveal(CARD_ID, { field: "number" })).json(), { value: "4111111111111111" });
  assert.deepEqual((await reveal(CARD_ID, { field: "code" })).json(), { value: "123" });
  assert.deepEqual((await reveal(IDENTITY_ID, { field: "ssn" })).json(), { value: "000-12-3456" });
  assert.deepEqual((await reveal(IDENTITY_ID, { field: "licenseNumber" })).json(), { value: "D-555" });
  assert.match((await reveal(SSH_ID, { field: "privateKey" })).json().value, /OPENSSH PRIVATE KEY/);
  assert.deepEqual((await reveal(SECRET_NOTE_ID, { field: "custom", name: "Secret" })).json(), { value: "tok_live_abc" });
  assert.deepEqual((await reveal(BANK_ID, { field: "accountNumber" })).json(), { value: "ACCT-000123456789" });
  assert.deepEqual((await reveal(BANK_ID, { field: "iban" })).json(), { value: "GB00ACME12345600000001" });
  assert.deepEqual((await reveal(LICENSE_ID, { field: "licenseNumber" })).json(), { value: "DL-D12345678" });
  assert.deepEqual((await reveal(PASSPORT_ID, { field: "passportNumber" })).json(), { value: "PP-A12345678" });
  assert.deepEqual((await reveal(PASSPORT_ID, { field: "nationalIdentificationNumber" })).json(), { value: "NIN-123-45-6789" });

  const refusals: Array<[string, Record<string, unknown>, string]> = [
    [CARD_ID, { field: "password" }, "a card item has no password"],
    [PASSKEY_ID, { field: "password" }, "item has no password"],
    [LOGIN_ID, { field: "custom", name: "Org" }, 'field "Org" is not hidden'],
    [LOGIN_ID, { field: "custom", name: "Nope" }, 'item has no field named "Nope"'],
    [CARD_ID, { field: "notes" }, "item has no notes"],
    [PASSPORT_ID, { field: "licenseNumber" }, "a passport item has no licenseNumber"],
    [LICENSE_ID, { field: "pin" }, "a driversLicense item has no pin"],
  ];
  for (const [id, payload, message] of refusals) {
    const res = await reveal(id, payload);
    assert.equal(res.statusCode, 422);
    assert.deepEqual(res.json().error, { type: "invalid_request", message });
  }
  assert.equal((await reveal(LOGIN_ID, { field: "everything" })).statusCode, 422);
  assert.equal((await reveal(MISSING_ID, { field: "password" })).statusCode, 404);
});

test("POST /v1/items/:id/totp returns the current code", async () => {
  const res = await app.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/totp` });
  assert.equal(res.statusCode, 200);
  assert.match(res.json().code, /^\d{6}$/);
  assert.equal(res.json().period, 30);
  assert.ok(res.json().remaining >= 1 && res.json().remaining <= 30);
  const none = await app.inject({ method: "POST", url: `/v1/items/${PASSKEY_ID}/totp` });
  assert.equal(none.statusCode, 422);
  assert.equal(none.json().error.message, "item has no authenticator key");
});

test("POST /v1/items/:id/login, /card and /passkey decrypt for fills", async () => {
  const login = await app.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/login` });
  assert.deepEqual(login.json(), { username: "octocat", password: "hunter2" });
  const card = await app.inject({ method: "POST", url: `/v1/items/${CARD_ID}/card` });
  assert.deepEqual(card.json(), {
    cardholderName: "Ada Lovelace",
    brand: "Visa",
    number: "4111111111111111",
    expMonth: "8",
    expYear: "2029",
    code: "123",
  });
  const notCard = await app.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/card` });
  assert.equal(notCard.statusCode, 422);
  assert.equal(notCard.json().error.message, "item is not a card");
  const noPasskey = await app.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/passkey` });
  assert.equal(noPasskey.json().error.message, "item has no passkey");
  const notLogin = await app.inject({ method: "POST", url: `/v1/items/${NOTE_ID}/login` });
  assert.equal(notLogin.json().error.message, "item is not a login");
});

test("folders: list without No Folder, create, rename, and delete moving items out", async () => {
  const listed = await app.inject({ method: "GET", url: "/v1/folders" });
  assert.deepEqual(listed.json(), { folders: sampleFolders() });

  const created = await app.inject({ method: "POST", url: "/v1/folders", payload: { name: "  School " } });
  assert.equal(created.statusCode, 201);
  assert.equal(created.json().name, "School");

  const renamed = await app.inject({ method: "PATCH", url: `/v1/folders/${FINANCE_FOLDER}`, payload: { name: "Money" } });
  assert.deepEqual(renamed.json(), { id: FINANCE_FOLDER, name: "Money" });

  const deleted = await app.inject({ method: "DELETE", url: `/v1/folders/${DEV_FOLDER}` });
  assert.equal(deleted.statusCode, 204);
  const after = await app.inject({ method: "GET", url: "/v1/folders" });
  assert.deepEqual(
    (after.json().folders as Array<{ name: string }>).map((folder) => folder.name),
    ["Money", "School"],
  );
  const github = await app.inject({ method: "GET", url: `/v1/items/${LOGIN_ID}` });
  assert.equal(github.json().folderId, null);

  const missing = await app.inject({ method: "PATCH", url: `/v1/folders/${MISSING_ID}`, payload: { name: "x" } });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.json().error.message, "folder not found");
  const blank = await app.inject({ method: "POST", url: "/v1/folders", payload: { name: "   " } });
  assert.equal(blank.statusCode, 422);
});

test("secrets resolve the hidden Secret field of the Secure Note named for them", async () => {
  const hit = await app.inject({ method: "POST", url: `/v1/secrets/${encodeURIComponent("stripe api key")}/reveal` });
  assert.deepEqual(hit.json(), { value: "tok_live_abc" });

  const missing = await app.inject({ method: "POST", url: "/v1/secrets/Nope/reveal" });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.json().error.message, 'no secure note is named "Nope"');

  const noField = await app.inject({ method: "POST", url: "/v1/secrets/Wifi/reveal" });
  assert.equal(noField.statusCode, 422);
  assert.equal(noField.json().error.message, 'item has no field named "Secret"');

  const loginNamed = await app.inject({ method: "POST", url: "/v1/secrets/GitHub/reveal" });
  assert.equal(loginNamed.statusCode, 404);
});

test("PUT /v1/secrets/:name creates the note, then updates its Secret and keeps other fields", async () => {
  const created = await app.inject({
    method: "PUT",
    url: `/v1/secrets/${encodeURIComponent("Gmail app password")}`,
    payload: { value: "abcd efgh ijkl mnop", notes: "for the mail worker" },
  });
  assert.equal(created.statusCode, 201);
  assert.equal(created.json().created, true);
  assert.equal(created.json().item.type, "note");
  assert.deepEqual(created.json().item.fields, [{ name: "Secret", type: "hidden", hasValue: true }]);
  assert.equal(created.body.includes("abcd efgh"), false);
  const revealed = await app.inject({ method: "POST", url: `/v1/secrets/${encodeURIComponent("Gmail app password")}/reveal` });
  assert.deepEqual(revealed.json(), { value: "abcd efgh ijkl mnop" });

  const updated = await app.inject({ method: "PUT", url: `/v1/secrets/${encodeURIComponent("Stripe API key")}`, payload: { value: "tok_live_new" } });
  assert.equal(updated.statusCode, 200);
  assert.equal(updated.json().created, false);
  assert.equal(updated.json().item.id, SECRET_NOTE_ID);
  assert.deepEqual(updated.json().item.fields, [
    { name: "Account", type: "text", value: "acct_1" },
    { name: "Secret", type: "hidden", hasValue: true },
  ]);
  assert.equal(fake.stored(SECRET_NOTE_ID).notes, "Live key for billing.");
  const again = await app.inject({ method: "POST", url: `/v1/secrets/${encodeURIComponent("Stripe API key")}/reveal` });
  assert.deepEqual(again.json(), { value: "tok_live_new" });
});

test("two Secure Notes with one name are a conflict for save and reveal", async () => {
  await app.inject({ method: "POST", url: "/v1/items", payload: { type: "note", name: "STRIPE API KEY" } });
  const save = await app.inject({ method: "PUT", url: `/v1/secrets/${encodeURIComponent("Stripe API key")}`, payload: { value: "x" } });
  assert.equal(save.statusCode, 409);
  assert.equal(save.json().error.type, "conflict");
  const reveal = await app.inject({ method: "POST", url: `/v1/secrets/${encodeURIComponent("Stripe API key")}/reveal` });
  assert.equal(reveal.statusCode, 409);
});

test("POST /v1/generate returns a fresh password of the asked length", async () => {
  const res = await app.inject({ method: "POST", url: "/v1/generate", payload: { length: 32, special: false } });
  assert.equal(res.statusCode, 200);
  assert.match(res.json().password, /^[A-Za-z0-9]{32}$/);
  const bad = await app.inject({ method: "POST", url: "/v1/generate", payload: { length: 5 } });
  assert.equal(bad.statusCode, 422);
});

test("a cipher that is not a valid item fails the sync with corrupt_item naming it", async () => {
  const bad = "99999999-9999-9999-9999-999999999999";
  for (const cipher of [
    { id: bad, type: 9, name: "Future type" },
    { id: bad, type: 3, name: "Card without card data", card: null },
    { id: bad, type: 1, name: "Login without login data" },
  ]) {
    fake.seed([...sampleCiphers(), cipher], sampleFolders());
    await assert.rejects(vault.refreshCatalog(), (err: unknown) => {
      const error = err as { type?: string; message?: string };
      return error.type === "corrupt_item" && String(error.message).startsWith(`vault item ${bad} `);
    });
  }
});

test("POST /v1/items/:id/login gives a null username for a login without one", async () => {
  fake.seed(
    [{ id: LOGIN_ID, type: 1, name: "PIN only", login: { username: null, password: "hunter2", uris: [] } }],
    sampleFolders(),
  );
  await vault.refreshCatalog();
  const res = await app.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/login` });
  assert.deepEqual(res.json(), { username: null, password: "hunter2" });
});

test("a bw failure reports the CLI's own first stderr line as vault_unreachable", async () => {
  const failing = new BwVault(readyConfig, memoryLogger(), async (argv) => {
    if (argv.includes("create")) {
      return { stdout: "", stderr: "SSH key public key is required.\n    at stack", code: 1 };
    }
    return fake.run(argv);
  });
  await failing.refreshCatalog();
  await assert.rejects(failing.createItem({ type: "note", name: "x" }), {
    type: "vault_unreachable",
    message: "vault command failed: SSH key public key is required.",
  });
});
