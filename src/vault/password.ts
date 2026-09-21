/** Generated login passwords. Never log the return value. */

import { randomInt } from "node:crypto";
import { ChaaviError } from "../errors.js";

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SPECIAL = "!@#$%^&*";

/** Default generated login length. */
export const DEFAULT_PASSWORD_LENGTH = 20;

/** Inclusive bounds for create-login `length`. */
export const PASSWORD_LENGTH_MIN = 12;
export const PASSWORD_LENGTH_MAX = 64;

/**
 * generateLoginPassword returns a password of `length` with at least one
 * character from each required class (lower, upper, digit, and special when
 * requested).
 */
export function generateLoginPassword(opts: { length: number; special: boolean }): string {
  if (opts.length < PASSWORD_LENGTH_MIN || opts.length > PASSWORD_LENGTH_MAX) {
    throw new ChaaviError(422, "invalid_request", "length is out of range");
  }
  const classes = [LOWER, UPPER, DIGITS];
  if (opts.special) {
    classes.push(SPECIAL);
  }
  const pool = classes.join("");
  const chars: string[] = classes.map((set) => set[randomInt(set.length)]!);
  while (chars.length < opts.length) {
    chars.push(pool[randomInt(pool.length)]!);
  }
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    const current = chars[i]!;
    chars[i] = chars[j]!;
    chars[j] = current;
  }
  return chars.join("");
}
