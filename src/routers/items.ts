/** Item catalog, login CRUD, and secret reveal. Missing vault env fails inside the vault call. */

import type { FastifyInstance } from "fastify";
import { createLoginBody, idParam, itemsQuery, parse, updateLoginBody } from "./schemas.js";

/** Item catalog, login create/update/delete, and secret reveal. */
export async function registerItems(app: FastifyInstance): Promise<void> {
  app.get("/v1/items", async (request) => {
    const query = parse(itemsQuery, request.query);
    const items = await app.vault.listItems(query);
    return { items };
  });

  app.post("/v1/logins", async (request) => {
    const body = parse(createLoginBody, request.body);
    return app.vault.createLogin(body);
  });

  app.get("/v1/items/:id", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getItem(id);
  });

  app.patch("/v1/items/:id", async (request) => {
    const { id } = parse(idParam, request.params);
    const body = parse(updateLoginBody, request.body);
    return app.vault.updateLogin(id, body);
  });

  app.delete("/v1/items/:id", async (request, reply) => {
    const { id } = parse(idParam, request.params);
    await app.vault.deleteItem(id);
    return reply.status(204).send();
  });

  app.post("/v1/items/:id/login", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getLogin(id);
  });

  app.post("/v1/items/:id/passkey", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getPasskey(id);
  });

  app.post("/v1/items/:id/secret", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getSecret(id);
  });
}
