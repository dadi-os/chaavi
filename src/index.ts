/**
 * Process entry: start vault (catalog + sync loop), listen, shut down cleanly.
 * Vault unlock and first sync run before listen when BW_* are set; health never
 * talks to Vaultwarden.
 */

import { buildApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createLogger } from "./logging.js";
import { BwVault } from "./vault/index.js";

const log = createLogger();
const config = loadConfig();
const vault = new BwVault(config, log);
await vault.start();
const app = await buildApp(config, { vault });

const shutdown = async (signal: string) => {
  log.info("shutting down", { signal });
  await vault.stop();
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
