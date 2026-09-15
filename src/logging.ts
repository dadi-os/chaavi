/**
 * Process logger (boot) and Fastify request logging aligned with the
 * Nas JSON contract (`service=chaavi`).
 */

import type { FastifyInstance, FastifyPluginAsync } from "fastify";
import { randomBytes } from "node:crypto";

export type LogAttrs = Record<string, unknown>;

export type Logger = {
  debug(msg: string, attrs?: LogAttrs): void;
  info(msg: string, attrs?: LogAttrs): void;
  warn(msg: string, attrs?: LogAttrs): void;
  error(msg: string, attrs?: LogAttrs): void;
};

function emit(level: string, msg: string, attrs?: LogAttrs): void {
  const line: Record<string, unknown> = {
    time: new Date().toISOString(),
    level,
    service: "chaavi",
    msg,
  };
  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) {
      if (value !== undefined) {
        line[key] = value;
      }
    }
  }
  console.log(JSON.stringify(line));
}

/** Create the process logger used outside Fastify (boot / shutdown). */
export function createLogger(): Logger {
  return {
    debug(msg, attrs) {
      emit("debug", msg, attrs);
    },
    info(msg, attrs) {
      emit("info", msg, attrs);
    },
    warn(msg, attrs) {
      emit("warn", msg, attrs);
    },
    error(msg, attrs) {
      emit("error", msg, attrs);
    },
  };
}

declare module "fastify" {
  interface FastifyRequest {
    /** Correlation id for this request (from X-Request-Id or generated). */
    requestId: string;
    /** High-resolution start time for duration_ms. */
    requestStartedAt: bigint;
  }
}

/**
 * Registers onRequest / onResponse hooks that emit one structured request line
 * per call: request_id, method, path, status, duration_ms.
 */
export const requestLoggingPlugin: FastifyPluginAsync = async (app) => {
  app.decorateRequest("requestId", "");
  app.decorateRequest("requestStartedAt", 0n);

  app.addHook("onRequest", async (request) => {
    const incoming = request.headers["x-request-id"];
    request.requestId =
      typeof incoming === "string" && incoming.trim() !== ""
        ? incoming.trim()
        : randomBytes(8).toString("hex");
    request.requestStartedAt = process.hrtime.bigint();
  });

  app.addHook("onResponse", async (request, reply) => {
    const durationMs = Number(process.hrtime.bigint() - request.requestStartedAt) / 1e6;
    const status = reply.statusCode;
    const payload = {
      request_id: request.requestId,
      method: request.method,
      path: request.url.split("?")[0] ?? request.url,
      status,
      duration_ms: Math.round(durationMs),
    };
    if (status >= 500) {
      request.log.error(payload, "request");
      return;
    }
    if (status >= 400) {
      request.log.warn(payload, "request");
      return;
    }
    request.log.info(payload, "request");
  });

  app.addHook("onSend", async (request, reply, payload) => {
    reply.header("X-Request-Id", request.requestId);
    return payload;
  });
};

/** Register the nas-aligned request logging plugin on an app. */
export async function registerRequestLogging(app: FastifyInstance): Promise<void> {
  await app.register(requestLoggingPlugin);
}
