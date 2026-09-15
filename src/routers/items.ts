/** Item catalog and secret-reveal routes under `/v1`. */

import type { FastifyInstance } from "fastify";
import { ChaaviError } from "../errors.js";
import type { Vault } from "../vault/index.js";
import { idParam, itemsQuery, parse } from "./schemas.js";

/** Throw `503 vault_unconfigured` when BW_* are unset; otherwise the decorated vault. */
function configuredVault(app: FastifyInstance): Vault {
  if (app.config.env.bw === undefined) {
    throw new ChaaviError(503, "vault_unconfigured", "vault is not configured");
  }
  return app.vault;
}

export async function registerItems(app: FastifyInstance): Promise<void> {
  app.get("/v1/items", async (request) => {
    const query = parse(itemsQuery, request.query);
    const items = await configuredVault(app).listItems(query);
    return { items };
  });

  app.get("/v1/items/:id", async (request) => {
    const { id } = parse(idParam, request.params);
    return configuredVault(app).getItem(id);
  });

  app.post("/v1/items/:id/login", async (request) => {
    const { id } = parse(idParam, request.params);
    return configuredVault(app).getLogin(id);
  });

  app.post("/v1/items/:id/secret", async (request) => {
    const { id } = parse(idParam, request.params);
    return configuredVault(app).getSecret(id);
  });
}
