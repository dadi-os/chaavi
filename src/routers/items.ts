/** Item catalog, CRUD for every item type, and decrypt-on-reveal. */

import type { FastifyInstance } from "fastify";
import { createItemBody, idParam, itemsQuery, parse, revealBody, updateItemBody } from "./schemas.js";

/** Item list/detail (never secret values), create/update/delete, and the reveal routes. */
export async function registerItems(app: FastifyInstance): Promise<void> {
  app.get("/v1/items", async (request) => {
    const query = parse(itemsQuery, request.query);
    return { items: await app.vault.listItems(query) };
  });

  app.post("/v1/items", async (request, reply) => {
    const body = parse(createItemBody, request.body);
    return reply.status(201).send(await app.vault.createItem(body));
  });

  app.get("/v1/items/:id", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getItem(id);
  });

  app.patch("/v1/items/:id", async (request) => {
    const { id } = parse(idParam, request.params);
    const body = parse(updateItemBody, request.body);
    return app.vault.updateItem(id, body);
  });

  app.delete("/v1/items/:id", async (request, reply) => {
    const { id } = parse(idParam, request.params);
    await app.vault.deleteItem(id);
    return reply.status(204).send();
  });

  app.post("/v1/items/:id/reveal", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.reveal(id, parse(revealBody, request.body));
  });

  app.post("/v1/items/:id/totp", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getTotp(id);
  });

  app.post("/v1/items/:id/login", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getLogin(id);
  });

  app.post("/v1/items/:id/card", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getCard(id);
  });

  app.post("/v1/items/:id/passkey", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getPasskey(id);
  });
}
