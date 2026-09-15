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

export const itemsQuery = z
  .object({
    q: z.string().min(1).optional(),
    uri: z.string().min(1).optional(),
    kind: z.enum(["login", "note", "secret"]).optional(),
  })
  .strict();
