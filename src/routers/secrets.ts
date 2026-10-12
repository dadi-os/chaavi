/**
 * Agent secrets by name and generated passwords. A secret is a Secure Note named for it with
 * its value in a hidden custom field called `Secret`.
 */

import type { FastifyInstance } from "fastify";
import { DEFAULT_PASSWORD_LENGTH, generateLoginPassword } from "../vault/password.js";
import { generateBody, parse, saveSecretBody, secretNameParam } from "./schemas.js";

/** Save and reveal a named secret; generate a password without storing it. */
export async function registerSecrets(app: FastifyInstance): Promise<void> {
  app.put("/v1/secrets/:name", async (request, reply) => {
    const { name } = parse(secretNameParam, request.params);
    const body = parse(saveSecretBody, request.body);
    const saved = await app.vault.saveSecret(name, body);
    return reply.status(saved.created ? 201 : 200).send(saved);
  });

  app.post("/v1/secrets/:name/reveal", async (request) => {
    const { name } = parse(secretNameParam, request.params);
    return app.vault.revealSecret(name);
  });

  app.post("/v1/generate", async (request) => {
    const body = parse(generateBody, request.body ?? {});
    return {
      password: generateLoginPassword({
        length: body.length ?? DEFAULT_PASSWORD_LENGTH,
        special: body.special ?? true,
      }),
    };
  });
}
