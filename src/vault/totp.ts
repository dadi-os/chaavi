/** RFC 6238 one-time codes from a login's stored authenticator key. Never log a seed or code. */

import { createHmac } from "node:crypto";
import { ChaaviError } from "../errors.js";
import type { TotpCode } from "../types/domain.js";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

type TotpParams = {
  key: Buffer;
  period: number;
  digits: number;
  algorithm: "sha1" | "sha256" | "sha512";
};

/**
 * totpCode computes the code for `seed` at `nowMs`. `seed` is a base32 key or an
 * `otpauth://totp/…` URI; the URI's own period, digits and algorithm apply, and an omitted
 * one takes the otpauth spec's value (30 s, 6 digits, SHA1).
 */
export function totpCode(seed: string, nowMs: number): TotpCode {
  const params = parseSeed(seed);
  const seconds = Math.floor(nowMs / 1000);
  const counter = Math.floor(seconds / params.period);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac(params.algorithm, params.key).update(message).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const binary = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** params.digits;
  return {
    code: String(binary).padStart(params.digits, "0"),
    period: params.period,
    remaining: params.period - (seconds % params.period),
  };
}

/** Read a base32 key or otpauth URI into HMAC parameters. */
function parseSeed(seed: string): TotpParams {
  const trimmed = seed.trim();
  if (/^steam:\/\//i.test(trimmed)) {
    throw new ChaaviError(422, "invalid_request", "Steam authenticator keys are not supported");
  }
  if (!/^otpauth:\/\//i.test(trimmed)) {
    return { key: decodeBase32(trimmed), period: 30, digits: 6, algorithm: "sha1" };
  }
  const url = new URL(trimmed);
  if (url.hostname.toLowerCase() !== "totp") {
    throw new ChaaviError(422, "invalid_request", "authenticator key is not a TOTP otpauth URI");
  }
  const secret = url.searchParams.get("secret");
  if (secret === null || secret.length === 0) {
    throw new ChaaviError(422, "invalid_request", "authenticator URI has no secret");
  }
  return {
    key: decodeBase32(secret),
    period: positiveInt(url.searchParams.get("period"), 30, "period"),
    digits: positiveInt(url.searchParams.get("digits"), 6, "digits"),
    algorithm: algorithmOf(url.searchParams.get("algorithm")),
  };
}

/** An otpauth integer parameter; absent takes the spec's value. */
function positiveInt(raw: string | null, specValue: number, name: string): number {
  if (raw === null) {
    return specValue;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 300) {
    throw new ChaaviError(422, "invalid_request", `authenticator URI has an invalid ${name}`);
  }
  return n;
}

/** The otpauth algorithm parameter as a node digest name; absent is SHA1 per the spec. */
function algorithmOf(raw: string | null): TotpParams["algorithm"] {
  if (raw === null) {
    return "sha1";
  }
  const upper = raw.toUpperCase();
  if (upper === "SHA1") {
    return "sha1";
  }
  if (upper === "SHA256") {
    return "sha256";
  }
  if (upper === "SHA512") {
    return "sha512";
  }
  throw new ChaaviError(422, "invalid_request", `authenticator algorithm ${raw} is not supported`);
}

/** RFC 4648 base32, ignoring spaces, hyphens, case and padding. */
function decodeBase32(text: string): Buffer {
  const clean = text.replace(/[\s=-]/g, "").toUpperCase();
  if (clean.length === 0) {
    throw new ChaaviError(422, "invalid_request", "authenticator key is empty");
  }
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of clean) {
    const index = BASE32.indexOf(char);
    if (index === -1) {
      throw new ChaaviError(422, "invalid_request", "authenticator key is not valid base32");
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}
