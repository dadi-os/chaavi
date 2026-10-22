/** `GET /v1/events` — Server-Sent Events stream that emits `{ type: "changed", at }` whenever the catalog's items or folders change. */

import type { ServerResponse } from "node:http";
import type { FastifyInstance } from "fastify";

const HEARTBEAT_MS = 20_000;

export async function registerEvents(app: FastifyInstance): Promise<void> {
  const streams = new Set<ServerResponse>();

  app.get("/v1/events", (request, reply) => {
    reply.hijack();
    const stream = reply.raw;
    stream.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    stream.write(": connected\n\n");
    streams.add(stream);
    const unsubscribe = app.vault.onChange(() => {
      stream.write(`data: ${JSON.stringify({ type: "changed", at: new Date().toISOString() })}\n\n`);
    });
    const heartbeat = setInterval(() => stream.write(": ping\n\n"), HEARTBEAT_MS);

    request.raw.on("close", () => {
      clearInterval(heartbeat);
      unsubscribe();
      streams.delete(stream);
    });
  });

  app.addHook("onClose", async () => {
    for (const stream of streams) {
      stream.end();
    }
  });
}
