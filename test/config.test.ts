import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadConfig, resetConfigCache } from "../src/config.js";

const BW_KEYS = [
  "VAULT_URL",
  "BW_CLIENTID",
  "BW_CLIENTSECRET",
  "BW_PASSWORD",
  "BITWARDENCLI_APPDATA_DIR",
] as const;

/** Run `fn` with a temporary env snapshot; restore and drop the config cache after. */
function withEnv(vars: Record<string, string | undefined>, fn: () => void): void {
  const previous: Record<string, string | undefined> = {};
  for (const key of BW_KEYS) {
    previous[key] = process.env[key];
  }
  for (const [key, value] of Object.entries(vars)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  resetConfigCache();
  try {
    fn();
  } finally {
    for (const key of BW_KEYS) {
      const value = previous[key];
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
    resetConfigCache();
  }
}

test("loadConfig requires VAULT_URL", () => {
  withEnv(
    {
      VAULT_URL: undefined,
      BW_CLIENTID: undefined,
      BW_CLIENTSECRET: undefined,
      BW_PASSWORD: undefined,
      BITWARDENCLI_APPDATA_DIR: undefined,
    },
    () => {
      assert.throws(() => loadConfig(), /VAULT_URL is required/);
    },
  );
});

test("loadConfig treats empty VAULT_URL as missing", () => {
  withEnv(
    {
      VAULT_URL: "",
      BW_CLIENTID: undefined,
      BW_CLIENTSECRET: undefined,
      BW_PASSWORD: undefined,
    },
    () => {
      assert.throws(() => loadConfig(), /VAULT_URL is required/);
    },
  );
});

test("loadConfig accepts all-empty BW_* as unconfigured", () => {
  withEnv(
    {
      VAULT_URL: "http://127.0.0.1:80",
      BW_CLIENTID: "",
      BW_CLIENTSECRET: undefined,
      BW_PASSWORD: "",
      BITWARDENCLI_APPDATA_DIR: undefined,
    },
    () => {
      const config = loadConfig();
      assert.equal(config.env.vaultUrl, "http://127.0.0.1:80");
      assert.equal(config.env.bw, undefined);
      assert.equal(config.vault.timeout_ms, 30_000);
    },
  );
});

test("loadConfig throws on partial BW_*", () => {
  withEnv(
    {
      VAULT_URL: "http://127.0.0.1:80",
      BW_CLIENTID: "user.abc",
      BW_CLIENTSECRET: undefined,
      BW_PASSWORD: undefined,
    },
    () => {
      assert.throws(() => loadConfig(), /partial Bitwarden credentials/);
    },
  );
});

test("loadConfig requires BITWARDENCLI_APPDATA_DIR when BW_* are set", () => {
  withEnv(
    {
      VAULT_URL: "http://127.0.0.1:80",
      BW_CLIENTID: "user.abc",
      BW_CLIENTSECRET: "secret",
      BW_PASSWORD: "pass",
      BITWARDENCLI_APPDATA_DIR: undefined,
    },
    () => {
      assert.throws(
        () => loadConfig(),
        /BITWARDENCLI_APPDATA_DIR is required when the vault is configured/,
      );
    },
  );
});

test("loadConfig returns bw credentials when all set", () => {
  const appDataDir = mkdtempSync(join(tmpdir(), "chaavi-bw-"));
  withEnv(
    {
      VAULT_URL: "http://chaavi-vault:80",
      BW_CLIENTID: "user.abc",
      BW_CLIENTSECRET: "secret",
      BW_PASSWORD: "pass",
      BITWARDENCLI_APPDATA_DIR: appDataDir,
    },
    () => {
      const config = loadConfig();
      assert.equal(config.env.vaultUrl, "http://chaavi-vault:80");
      assert.ok(config.env.bw);
      assert.equal(config.env.bw.clientId, "user.abc");
      assert.equal(config.env.bw.clientSecret, "secret");
      assert.equal(config.env.bw.password, "pass");
      assert.equal(config.env.bw.appDataDir, appDataDir);
    },
  );
});
