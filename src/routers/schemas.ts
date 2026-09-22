/** Request param / query zod schemas and parse helpers. */

import { z, type ZodError, type ZodType } from "zod";
import { ChaaviError } from "../errors.js";

/** Parse with zod; map failures to `422 invalid_request`. */
export function parse<T>(schema: ZodType<T>, data: unknown): T {
  const parsed = schema.safeParse(data);
  if (!parsed.success) {
    throw new ChaaviError(422, "invalid_request", formatZod(parsed.error));
  }
  return parsed.data;
}

/** Flatten zod issues into a single semicolon-joined message. */
export function formatZod(error: ZodError): string {
  return error.issues
    .map((issue) => {
      const loc = issue.path.join(".");
      return loc ? `${loc}: ${issue.message}` : issue.message;
    })
    .join("; ");
}

export const idParam = z.object({ id: z.string().uuid() }).strict();

export const createLoginBody = z
  .object({
    name: z.string().min(1).max(200),
    username: z.string().min(1).max(320),
    uri: z.string().min(1).max(2000).optional(),
    password: z.string().min(1).max(500).optional(),
    length: z.number().int().min(12).max(64).optional(),
    special: z.boolean().optional(),
  })
  .strict()
  .superRefine((body, ctx) => {
    if (body.password !== undefined && (body.length !== undefined || body.special !== undefined)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "length and special apply only when password is omitted",
      });
    }
  });

export const updateLoginBody = z
  .object({
    name: z.string().min(1).max(200).optional(),
    username: z.string().min(1).max(320).optional(),
    uri: z.string().max(2000).optional(),
    password: z.string().min(1).max(500).optional(),
  })
  .strict()
  .superRefine((body, ctx) => {
    if (
      body.name === undefined &&
      body.username === undefined &&
      body.uri === undefined &&
      body.password === undefined
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "at least one of name, username, uri, password is required",
      });
    }
  });

export const itemsQuery = z
  .object({
    q: z.string().min(1).optional(),
    uri: z.string().min(1).optional(),
    kind: z.enum(["login", "note", "secret"]).optional(),
  })
  .strict();
