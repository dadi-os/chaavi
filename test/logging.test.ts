import assert from "node:assert/strict";
import { test } from "node:test";
import Fastify from "fastify";
import { registerRequestLogging } from "../src/logging.js";

test("request logging hooks run for routes on the app", async (t) => {
  const app = Fastify();
  t.after(() => app.close());
  await registerRequestLogging(app);
  app.get("/probe", async () => ({ ok: true }));

  const res = await app.inject({ method: "GET", url: "/probe", headers: { "x-request-id": "req-probe" } });

  assert.equal(res.statusCode, 200);
  assert.equal(res.headers["x-request-id"], "req-probe");
});
