/**
 * Process entry: listen, then shut down on SIGINT/SIGTERM.
 * Vault unlock is lazy on first `/v1` use; health never talks to Vaultwarden.
 */

import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createLogger } from "./logging.js";
import { BwVault, UnconfiguredVault } from "./vault/index.js";

const log = createLogger();
const config = loadConfig();
const vault = config.env.bw !== undefined ? new BwVault(config) : new UnconfiguredVault();
const app = await buildApp(config, { vault });

const shutdown = async (signal: string) => {
  log.info("shutting down", { signal });
  await app.close();
};

process.on("SIGINT", () => {
  void shutdown("SIGINT").then(() => process.exit(0));
});
process.on("SIGTERM", () => {
  void shutdown("SIGTERM").then(() => process.exit(0));
});

await app.listen({ host: config.env.host, port: config.env.port });
log.info("chaavi listening", { host: config.env.host, port: config.env.port });
