/** Item catalog and secret-reveal routes under `/v1`. */

import type { FastifyInstance } from "fastify";
import { idParam, itemsQuery, parse } from "./schemas.js";

/** Item catalog and secret reveal. Missing vault env fails inside the vault call. */
export async function registerItems(app: FastifyInstance): Promise<void> {
  app.get("/v1/items", async (request) => {
    const query = parse(itemsQuery, request.query);
    const items = await app.vault.listItems(query);
    return { items };
  });

  app.get("/v1/items/:id", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getItem(id);
  });

  app.post("/v1/items/:id/login", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getLogin(id);
  });

  app.post("/v1/items/:id/secret", async (request) => {
    const { id } = parse(idParam, request.params);
    return app.vault.getSecret(id);
  });
}
