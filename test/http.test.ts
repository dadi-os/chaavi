import assert from "node:assert/strict";
import { after, test } from "node:test";
import { buildApp } from "../src/app.js";
import { BwVault } from "../src/vault/bw.js";
import {
  FakeVault,
  LOGIN_ID,
  MISSING_ID,
  NOTE_ID,
  PASSKEY_ID,
  SAMPLE_PASSKEY,
  SSH_ID,
  makeConfig,
  sampleItems,
} from "./helpers.js";

const fake = new FakeVault();
fake.seed(sampleItems());

const readyConfig = makeConfig();
const emptyConfig = makeConfig();
emptyConfig.env.vaultUrl = "";
emptyConfig.env.bw = { clientId: "", clientSecret: "", password: "", appDataDir: "" };

const app = await buildApp(readyConfig, { vault: fake });
const unconfigured = await buildApp(emptyConfig, { vault: fake });

after(async () => {
  await app.close();
  await unconfigured.close();
});

test("GET /health reports ready vs unconfigured without calling the vault", async () => {
  const up = await app.inject({ method: "GET", url: "/health" });
  assert.equal(up.statusCode, 200);
  assert.deepEqual(up.json(), { status: "ok", vault: "ready" });

  const down = await unconfigured.inject({ method: "GET", url: "/health" });
  assert.equal(down.statusCode, 200);
  assert.deepEqual(down.json(), { status: "ok", vault: "unconfigured" });
});

test("GET /v1/items is 503 and names the first empty vault variable", async () => {
  const config = makeConfig();
  config.env.vaultUrl = "https://chaavi.dadi";
  config.env.bw = { ...config.env.bw, clientSecret: "" };
  const bare = await buildApp(config, { vault: new BwVault(config) });
  try {
    const res = await bare.inject({ method: "GET", url: "/v1/items" });
    assert.equal(res.statusCode, 503);
    assert.equal(res.json().error.type, "vault_unconfigured");
    assert.equal(res.json().error.message, "BW_CLIENTSECRET is not set");
  } finally {
    await bare.close();
  }
});

test("GET /v1/items returns metadata only", async () => {
  const res = await app.inject({ method: "GET", url: "/v1/items" });
  assert.equal(res.statusCode, 200);
  const body = res.json() as { items: Array<Record<string, unknown>> };
  assert.equal(body.items.length, 4);
  for (const item of body.items) {
    assert.equal("password" in item, false);
    assert.equal("notes" in item, false);
    assert.equal("totp" in item, false);
    assert.equal("value" in item, false);
    assert.equal("privateKey" in item, false);
    assert.equal("credentialId" in item, false);
    assert.equal(typeof item.hasPasskey, "boolean");
    assert.ok(typeof item.id === "string");
    assert.ok(typeof item.name === "string");
    assert.ok(item.kind === "login" || item.kind === "note" || item.kind === "secret");
    assert.ok(item.username === null || typeof item.username === "string");
    assert.ok(Array.isArray(item.uris));
  }
  const github = body.items.find((item) => item.id === LOGIN_ID);
  assert.ok(github);
  assert.equal(github.name, "GitHub");
  assert.equal(github.kind, "login");
  assert.equal(github.username, "octocat");
  assert.equal(github.hasPasskey, false);
  assert.deepEqual(github.uris, ["https://github.com"]);
  const google = body.items.find((item) => item.id === PASSKEY_ID);
  assert.ok(google);
  assert.equal(google.hasPasskey, true);
});

test("GET /v1/items filters q/uri/kind", async () => {
  const byName = await app.inject({ method: "GET", url: "/v1/items?q=git" });
  assert.equal(byName.statusCode, 200);
  assert.equal(byName.json().items.length, 1);
  assert.equal(byName.json().items[0].id, LOGIN_ID);

  const byUser = await app.inject({ method: "GET", url: "/v1/items?q=octocat" });
  assert.equal(byUser.json().items.length, 1);
  assert.equal(byUser.json().items[0].id, LOGIN_ID);

  const byUriQ = await app.inject({ method: "GET", url: "/v1/items?q=github.com" });
  assert.equal(byUriQ.json().items.length, 1);

  const byUri = await app.inject({ method: "GET", url: "/v1/items?uri=github.com" });
  assert.equal(byUri.json().items.length, 1);
  assert.equal(byUri.json().items[0].id, LOGIN_ID);

  const notes = await app.inject({ method: "GET", url: "/v1/items?kind=note" });
  assert.equal(notes.json().items.length, 1);
  assert.equal(notes.json().items[0].id, NOTE_ID);

  const secrets = await app.inject({ method: "GET", url: "/v1/items?kind=secret" });
  assert.equal(secrets.json().items.length, 1);
  assert.equal(secrets.json().items[0].id, SSH_ID);

  const none = await app.inject({ method: "GET", url: "/v1/items?q=nope" });
  assert.equal(none.json().items.length, 0);
});

test("GET /v1/items/:id missing is 404", async () => {
  const res = await app.inject({ method: "GET", url: `/v1/items/${MISSING_ID}` });
  assert.equal(res.statusCode, 404);
  assert.equal(res.json().error.type, "not_found");
});

test("GET /v1/items/:id returns metadata only", async () => {
  const res = await app.inject({ method: "GET", url: `/v1/items/${LOGIN_ID}` });
  assert.equal(res.statusCode, 200);
  const item = res.json() as Record<string, unknown>;
  assert.equal("password" in item, false);
  assert.equal("notes" in item, false);
  assert.equal(item.id, LOGIN_ID);
  assert.equal(item.username, "octocat");
});

test("POST /v1/items/:id/login returns username/password; not-a-login is invalid_request", async () => {
  const login = await app.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/login` });
  assert.equal(login.statusCode, 200);
  assert.deepEqual(login.json(), { username: "octocat", password: "hunter2" });

  const note = await app.inject({ method: "POST", url: `/v1/items/${NOTE_ID}/login` });
  assert.equal(note.statusCode, 422);
  assert.equal(note.json().error.type, "invalid_request");
  assert.equal(note.json().error.message, "item is not a login");

  const missing = await app.inject({ method: "POST", url: `/v1/items/${MISSING_ID}/login` });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.json().error.type, "not_found");
});

test("POST /v1/logins creates a login without returning the password", async () => {
  const res = await app.inject({
    method: "POST",
    url: "/v1/logins",
    payload: {
      name: "Greenhouse",
      username: "ada@example.com",
      uri: "https://job-boards.greenhouse.io",
    },
  });
  assert.equal(res.statusCode, 200);
  const item = res.json() as Record<string, unknown>;
  assert.equal(typeof item.id, "string");
  assert.equal(item.name, "Greenhouse");
  assert.equal(item.kind, "login");
  assert.equal(item.username, "ada@example.com");
  assert.deepEqual(item.uris, ["https://job-boards.greenhouse.io"]);
  assert.equal(item.hasPasskey, false);
  assert.equal("password" in item, false);

  const login = await app.inject({ method: "POST", url: `/v1/items/${item.id}/login` });
  assert.equal(login.statusCode, 200);
  assert.equal(login.json().username, "ada@example.com");
  assert.equal(typeof login.json().password, "string");
  assert.ok(String(login.json().password).length >= 12);
});

test("POST /v1/logins unknown field is 422", async () => {
  const res = await app.inject({
    method: "POST",
    url: "/v1/logins",
    payload: { name: "x", username: "ada", password: "nope" },
  });
  assert.equal(res.statusCode, 422);
  assert.equal(res.json().error.type, "invalid_request");
});

test("POST /v1/items/:id/passkey returns CDP fields; missing passkey is invalid_request", async () => {
  const passkey = await app.inject({ method: "POST", url: `/v1/items/${PASSKEY_ID}/passkey` });
  assert.equal(passkey.statusCode, 200);
  assert.deepEqual(passkey.json(), SAMPLE_PASSKEY);

  const login = await app.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/passkey` });
  assert.equal(login.statusCode, 422);
  assert.equal(login.json().error.type, "invalid_request");
  assert.equal(login.json().error.message, "item has no passkey");

  const note = await app.inject({ method: "POST", url: `/v1/items/${NOTE_ID}/passkey` });
  assert.equal(note.statusCode, 422);
  assert.equal(note.json().error.type, "invalid_request");

  const missing = await app.inject({ method: "POST", url: `/v1/items/${MISSING_ID}/passkey` });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.json().error.type, "not_found");
});

test("POST /v1/items/:id/secret returns value", async () => {
  const login = await app.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/secret` });
  assert.equal(login.statusCode, 200);
  assert.deepEqual(login.json(), { value: "hunter2" });

  const note = await app.inject({ method: "POST", url: `/v1/items/${NOTE_ID}/secret` });
  assert.equal(note.statusCode, 200);
  assert.deepEqual(note.json(), { value: "hunter2-note" });

  const ssh = await app.inject({ method: "POST", url: `/v1/items/${SSH_ID}/secret` });
  assert.equal(ssh.statusCode, 200);
  assert.equal(typeof ssh.json().value, "string");
  assert.ok(String(ssh.json().value).includes("BEGIN OPENSSH"));
});

test("POST login with empty password is invalid_request", async () => {
  fake.seed([
    {
      record: {
        id: LOGIN_ID,
        name: "Empty",
        kind: "login",
        username: "x",
        uris: [],
        hasPasskey: false,
      },
      password: "",
    },
  ]);
  try {
    const res = await app.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/login` });
    assert.equal(res.statusCode, 422);
    assert.equal(res.json().error.type, "invalid_request");
  } finally {
    fake.seed(sampleItems());
  }
});

test("unknown query field is 422", async () => {
  const res = await app.inject({ method: "GET", url: "/v1/items?foo=1" });
  assert.equal(res.statusCode, 422);
  assert.equal(res.json().error.type, "invalid_request");
});
