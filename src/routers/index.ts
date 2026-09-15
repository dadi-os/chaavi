/** Mount domain HTTP routes. */

import type { FastifyInstance } from "fastify";
import { registerItems } from "./items.js";

export async function registerRoutes(app: FastifyInstance): Promise<void> {
  await registerItems(app);
}
