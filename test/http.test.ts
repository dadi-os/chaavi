import assert from "node:assert/strict";
import { after, test } from "node:test";
import { buildApp } from "../src/app.js";
import {
  FakeVault,
  LOGIN_ID,
  MISSING_ID,
  NOTE_ID,
  SSH_ID,
  makeConfig,
  sampleItems,
} from "./helpers.js";

const fake = new FakeVault();
fake.seed(sampleItems());

const ready = await buildApp(makeConfig({ configured: true }), { vault: fake });
const unconfigured = await buildApp(makeConfig({ configured: false }), { vault: fake });

after(async () => {
  await ready.close();
  await unconfigured.close();
});

test("GET /health unconfigured vs ready", async () => {
  const down = await unconfigured.inject({ method: "GET", url: "/health" });
  assert.equal(down.statusCode, 200);
  assert.deepEqual(down.json(), { status: "ok", vault: "unconfigured" });

  const up = await ready.inject({ method: "GET", url: "/health" });
  assert.equal(up.statusCode, 200);
  assert.deepEqual(up.json(), { status: "ok", vault: "ready" });
});

test("GET /v1/items 503 when unconfigured", async () => {
  const res = await unconfigured.inject({ method: "GET", url: "/v1/items" });
  assert.equal(res.statusCode, 503);
  assert.equal(res.json().error.type, "vault_unconfigured");
});

test("GET /v1/items returns metadata only", async () => {
  const res = await ready.inject({ method: "GET", url: "/v1/items" });
  assert.equal(res.statusCode, 200);
  const body = res.json() as { items: Array<Record<string, unknown>> };
  assert.equal(body.items.length, 3);
  for (const item of body.items) {
    assert.equal("password" in item, false);
    assert.equal("notes" in item, false);
    assert.equal("totp" in item, false);
    assert.equal("value" in item, false);
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
  assert.deepEqual(github.uris, ["https://github.com"]);
});

test("GET /v1/items filters q/uri/kind", async () => {
  const byName = await ready.inject({ method: "GET", url: "/v1/items?q=git" });
  assert.equal(byName.statusCode, 200);
  assert.equal(byName.json().items.length, 1);
  assert.equal(byName.json().items[0].id, LOGIN_ID);

  const byUser = await ready.inject({ method: "GET", url: "/v1/items?q=octocat" });
  assert.equal(byUser.json().items.length, 1);
  assert.equal(byUser.json().items[0].id, LOGIN_ID);

  const byUriQ = await ready.inject({ method: "GET", url: "/v1/items?q=github.com" });
  assert.equal(byUriQ.json().items.length, 1);

  const byUri = await ready.inject({ method: "GET", url: "/v1/items?uri=github.com" });
  assert.equal(byUri.json().items.length, 1);
  assert.equal(byUri.json().items[0].id, LOGIN_ID);

  const notes = await ready.inject({ method: "GET", url: "/v1/items?kind=note" });
  assert.equal(notes.json().items.length, 1);
  assert.equal(notes.json().items[0].id, NOTE_ID);

  const secrets = await ready.inject({ method: "GET", url: "/v1/items?kind=secret" });
  assert.equal(secrets.json().items.length, 1);
  assert.equal(secrets.json().items[0].id, SSH_ID);

  const none = await ready.inject({ method: "GET", url: "/v1/items?q=nope" });
  assert.equal(none.json().items.length, 0);
});

test("GET /v1/items/:id missing is 404", async () => {
  const res = await ready.inject({ method: "GET", url: `/v1/items/${MISSING_ID}` });
  assert.equal(res.statusCode, 404);
  assert.equal(res.json().error.type, "not_found");
});

test("GET /v1/items/:id returns metadata only", async () => {
  const res = await ready.inject({ method: "GET", url: `/v1/items/${LOGIN_ID}` });
  assert.equal(res.statusCode, 200);
  const item = res.json() as Record<string, unknown>;
  assert.equal("password" in item, false);
  assert.equal("notes" in item, false);
  assert.equal(item.id, LOGIN_ID);
  assert.equal(item.username, "octocat");
});

test("POST /v1/items/:id/login returns username/password; not-a-login is invalid_request", async () => {
  const login = await ready.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/login` });
  assert.equal(login.statusCode, 200);
  assert.deepEqual(login.json(), { username: "octocat", password: "hunter2" });

  const note = await ready.inject({ method: "POST", url: `/v1/items/${NOTE_ID}/login` });
  assert.equal(note.statusCode, 422);
  assert.equal(note.json().error.type, "invalid_request");
  assert.equal(note.json().error.message, "item is not a login");

  const missing = await ready.inject({ method: "POST", url: `/v1/items/${MISSING_ID}/login` });
  assert.equal(missing.statusCode, 404);
  assert.equal(missing.json().error.type, "not_found");
});

test("POST /v1/items/:id/secret returns value", async () => {
  const login = await ready.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/secret` });
  assert.equal(login.statusCode, 200);
  assert.deepEqual(login.json(), { value: "hunter2" });

  const note = await ready.inject({ method: "POST", url: `/v1/items/${NOTE_ID}/secret` });
  assert.equal(note.statusCode, 200);
  assert.deepEqual(note.json(), { value: "hunter2-note" });

  const ssh = await ready.inject({ method: "POST", url: `/v1/items/${SSH_ID}/secret` });
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
      },
      password: "",
    },
  ]);
  try {
    const res = await ready.inject({ method: "POST", url: `/v1/items/${LOGIN_ID}/login` });
    assert.equal(res.statusCode, 422);
    assert.equal(res.json().error.type, "invalid_request");
  } finally {
    fake.seed(sampleItems());
  }
});

test("unknown query field is 422", async () => {
  const res = await ready.inject({ method: "GET", url: "/v1/items?foo=1" });
  assert.equal(res.statusCode, 422);
  assert.equal(res.json().error.type, "invalid_request");
});
