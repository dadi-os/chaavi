import Fastify, { LogController, type FastifyInstance } from "fastify";
import { missingVaultCredential, type Config } from "./config.js";
import { ChaaviError } from "./errors.js";
import { registerRequestLogging } from "./logging.js";
import { registerRoutes } from "./routers/index.js";
import type { Vault } from "./vault/index.js";

declare module "fastify" {
  interface FastifyInstance {
    config: Config;
    vault: Vault;
  }
}

/** Build the Chaavi Fastify app with nas-aligned request logging. */
export async function buildApp(
  config: Config,
  deps: { vault: Vault },
): Promise<FastifyInstance> {
  const app = Fastify({
    logController: new LogController({ disableRequestLogging: true }),
    logger: {
      level: config.env.logLevel,
      base: { service: "chaavi" },
      timestamp: () => `,"time":"${new Date().toISOString()}"`,
      formatters: {
        level(label) {
          return { level: label };
        },
      },
    },
  });
  await registerRequestLogging(app);
  app.decorate("config", config);
  app.decorate("vault", deps.vault);

  app.setErrorHandler((err, request, reply) => {
    if (err instanceof ChaaviError) {
      request.log.warn(
        { code: err.type, request_id: request.requestId, status: err.statusCode },
        err.message,
      );
      return reply.status(err.statusCode).send({
        error: { type: err.type, message: err.message },
      });
    }
    const statusCode =
      typeof err === "object" &&
      err !== null &&
      "statusCode" in err &&
      typeof err.statusCode === "number"
        ? err.statusCode
        : 500;
    const message = err instanceof Error ? err.message : "internal error";
    if (statusCode >= 400 && statusCode < 500) {
      request.log.warn(
        { code: "invalid_request", request_id: request.requestId, status: statusCode },
        message,
      );
      return reply.status(statusCode).send({
        error: { type: "invalid_request", message },
      });
    }
    request.log.error(
      { code: "internal_error", request_id: request.requestId, status: 500, err },
      "internal error",
    );
    return reply.status(500).send({
      error: { type: "internal_error", message: "internal error" },
    });
  });

  app.get("/health", async () => ({
    status: "ok",
    vault: missingVaultCredential(config) === undefined ? "ready" : "unconfigured",
  }));
  await app.register(registerRoutes);
  return app;
}
