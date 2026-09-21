import assert from "node:assert/strict";
import { test } from "node:test";
import { ChaaviError } from "../src/errors.js";
import {
  DEFAULT_PASSWORD_LENGTH,
  generateLoginPassword,
  PASSWORD_LENGTH_MAX,
  PASSWORD_LENGTH_MIN,
} from "../src/vault/password.js";

const SPECIAL = /[!@#$%^&*]/;

test("generateLoginPassword meets class requirements", () => {
  const value = generateLoginPassword({ length: DEFAULT_PASSWORD_LENGTH, special: true });
  assert.equal(value.length, DEFAULT_PASSWORD_LENGTH);
  assert.match(value, /[a-z]/);
  assert.match(value, /[A-Z]/);
  assert.match(value, /[0-9]/);
  assert.match(value, SPECIAL);
});

test("generateLoginPassword can omit special characters", () => {
  const value = generateLoginPassword({ length: 12, special: false });
  assert.equal(value.length, 12);
  assert.equal(SPECIAL.test(value), false);
});

test("generateLoginPassword rejects out of range length", () => {
  assert.throws(
    () => generateLoginPassword({ length: PASSWORD_LENGTH_MIN - 1, special: true }),
    (err: unknown) => err instanceof ChaaviError && err.type === "invalid_request",
  );
  assert.throws(
    () => generateLoginPassword({ length: PASSWORD_LENGTH_MAX + 1, special: true }),
    (err: unknown) => err instanceof ChaaviError && err.type === "invalid_request",
  );
});
