/** Mount domain HTTP routes. */

import type { FastifyInstance } from "fastify";
import { registerFolders } from "./folders.js";
import { registerItems } from "./items.js";
import { registerSecrets } from "./secrets.js";

export async function registerRoutes(app: FastifyInstance): Promise<void> {
  await registerItems(app);
  await registerFolders(app);
  await registerSecrets(app);
}
