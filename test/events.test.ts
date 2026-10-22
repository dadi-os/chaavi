import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";
import { test } from "node:test";
import { buildApp } from "../src/app.js";
import { BwVault } from "../src/vault/bw.js";
import { FakeBw, makeConfig, memoryLogger, sampleCiphers, sampleFolders } from "./helpers.js";

test("the catalog announces a change when a write or a sync alters it, and stays quiet when a sync finds nothing new", async () => {
  const fake = new FakeBw();
  fake.seed(sampleCiphers(), sampleFolders());
  const vault = new BwVault(makeConfig(), memoryLogger(), fake.run);
  await vault.refreshCatalog();
  let changes = 0;
  vault.onChange(() => {
    changes += 1;
  });

  await vault.refreshCatalog();
  assert.equal(changes, 0);

  await vault.createFolder("Travel");
  assert.equal(changes, 1);

  fake.seed(sampleCiphers(), sampleFolders());
  await vault.refreshCatalog();
  assert.equal(changes, 2);
});

test("GET /v1/events streams a change to a subscriber when the catalog changes", async (t) => {
  const fake = new FakeBw();
  fake.seed(sampleCiphers(), sampleFolders());
  const config = makeConfig();
  const vault = new BwVault(config, memoryLogger(), fake.run);
  await vault.refreshCatalog();
  const app = await buildApp(config, { vault });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const url = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;

  const res = await fetch(`${url}/v1/events`);
  assert.equal(res.headers.get("content-type"), "text/event-stream");
  const reader = res.body!.getReader();
  t.after(async () => {
    await reader.cancel();
    await app.close();
  });
  const decoder = new TextDecoder();
  let received = "";
  void (async () => {
    for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) {
      received += decoder.decode(chunk.value);
    }
  })();

  await vault.createFolder("Travel");
  await sleep(50);

  const events = received.split("\n\n").filter((part) => part.startsWith("data: "));
  assert.equal(events.length, 1);
  assert.equal(JSON.parse(events[0]!.slice(6)).type, "changed");
});
