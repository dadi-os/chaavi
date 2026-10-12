/** Folder list and CRUD. Moving an item is `PATCH /v1/items/:id` with `folderId`. */

import type { FastifyInstance } from "fastify";
import { folderBody, idParam, parse } from "./schemas.js";

/** Folder list, create, rename and delete. */
export async function registerFolders(app: FastifyInstance): Promise<void> {
  app.get("/v1/folders", async () => ({ folders: await app.vault.listFolders() }));

  app.post("/v1/folders", async (request, reply) => {
    const { name } = parse(folderBody, request.body);
    return reply.status(201).send(await app.vault.createFolder(name));
  });

  app.patch("/v1/folders/:id", async (request) => {
    const { id } = parse(idParam, request.params);
    const { name } = parse(folderBody, request.body);
    return app.vault.renameFolder(id, name);
  });

  app.delete("/v1/folders/:id", async (request, reply) => {
    const { id } = parse(idParam, request.params);
    await app.vault.deleteFolder(id);
    return reply.status(204).send();
  });
}
