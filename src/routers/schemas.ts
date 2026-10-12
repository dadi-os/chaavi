/** Request param / query / body zod schemas and parse helpers. */

import { z, type ZodError, type ZodType } from "zod";
import { ChaaviError } from "../errors.js";
import { PASSWORD_LENGTH_MAX, PASSWORD_LENGTH_MIN } from "../vault/password.js";

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

export const secretNameParam = z.object({ name: z.string().min(1).max(200) }).strict();

const itemType = z.enum(["login", "note", "card", "identity", "sshKey"]);

const linkedTarget = z.enum([
  "username",
  "password",
  "cardholderName",
  "expMonth",
  "expYear",
  "code",
  "brand",
  "number",
  "title",
  "firstName",
  "middleName",
  "lastName",
  "fullName",
  "address1",
  "address2",
  "address3",
  "city",
  "state",
  "postalCode",
  "country",
  "company",
  "email",
  "phone",
  "ssn",
  "passportNumber",
  "licenseNumber",
]);

const fieldName = z.string().min(1).max(200);

const customField = z.discriminatedUnion("type", [
  z.object({ name: fieldName, type: z.literal("text"), value: z.string().max(5000) }).strict(),
  z.object({ name: fieldName, type: z.literal("hidden"), value: z.string().min(1).max(5000).optional() }).strict(),
  z.object({ name: fieldName, type: z.literal("boolean"), value: z.boolean() }).strict(),
  z.object({ name: fieldName, type: z.literal("linked"), linkedTo: linkedTarget }).strict(),
]);

const uri = z
  .object({
    uri: z.string().min(1).max(2000),
    match: z.enum(["default", "domain", "host", "startsWith", "exact", "regex", "never"]).optional(),
  })
  .strict();

const loginFields = {
  username: z.string().max(320).optional(),
  password: z.string().min(1).max(500).optional(),
  totp: z.string().max(2000).optional(),
  uris: z.array(uri).max(20).optional(),
};

const optionalText = (max: number) => z.string().max(max).optional();

const card = z
  .object({
    cardholderName: optionalText(200),
    brand: optionalText(50),
    number: z
      .string()
      .regex(/^$|^(?:\d[\s-]?){12,19}$/, "number must be 12 to 19 digits")
      .optional(),
    expMonth: z
      .string()
      .regex(/^$|^(0?[1-9]|1[0-2])$/, "expMonth must be 1 to 12")
      .optional(),
    expYear: z
      .string()
      .regex(/^$|^\d{4}$/, "expYear must be four digits")
      .optional(),
    code: z
      .string()
      .regex(/^$|^\d{3,4}$/, "code must be 3 or 4 digits")
      .optional(),
  })
  .strict();

const identity = z
  .object({
    title: optionalText(30),
    firstName: optionalText(200),
    middleName: optionalText(200),
    lastName: optionalText(200),
    address1: optionalText(200),
    address2: optionalText(200),
    address3: optionalText(200),
    city: optionalText(100),
    state: optionalText(100),
    postalCode: optionalText(30),
    country: optionalText(100),
    company: optionalText(200),
    email: optionalText(320),
    phone: optionalText(50),
    username: optionalText(320),
    ssn: optionalText(50),
    passportNumber: optionalText(50),
    licenseNumber: optionalText(50),
  })
  .strict();

const sshKey = z
  .object({
    privateKey: z.string().max(20000).optional(),
    publicKey: z.string().max(5000).optional(),
    keyFingerprint: z.string().max(200).optional(),
  })
  .strict();

const baseFields = {
  name: z.string().min(1).max(200),
  folderId: z.string().uuid().nullable().optional(),
  favorite: z.boolean().optional(),
  notes: z.string().max(10000).optional(),
  fields: z.array(customField).max(50).optional(),
};

export const createItemBody = z.discriminatedUnion("type", [
  z
    .object({
      ...baseFields,
      type: z.literal("login"),
      login: z
        .object({
          ...loginFields,
          length: z.number().int().min(PASSWORD_LENGTH_MIN).max(PASSWORD_LENGTH_MAX).optional(),
          special: z.boolean().optional(),
        })
        .strict()
        .optional(),
    })
    .strict(),
  z.object({ ...baseFields, type: z.literal("note") }).strict(),
  z.object({ ...baseFields, type: z.literal("card"), card: card.optional() }).strict(),
  z.object({ ...baseFields, type: z.literal("identity"), identity: identity.optional() }).strict(),
  z.object({ ...baseFields, type: z.literal("sshKey"), sshKey: sshKey.optional() }).strict(),
]);

export const updateItemBody = z
  .object({
    name: baseFields.name.optional(),
    folderId: baseFields.folderId,
    favorite: baseFields.favorite,
    notes: baseFields.notes,
    fields: baseFields.fields,
    login: z.object(loginFields).strict().optional(),
    card: card.optional(),
    identity: identity.optional(),
    sshKey: sshKey.optional(),
  })
  .strict()
  .refine((body) => Object.values(body).some((value) => value !== undefined), {
    message: "give at least one field to change",
  });

export const revealBody = z.union([
  z
    .object({
      field: z.enum(["password", "totp", "number", "code", "ssn", "passportNumber", "licenseNumber", "privateKey", "notes"]),
    })
    .strict(),
  z.object({ field: z.literal("custom"), name: fieldName }).strict(),
]);

export const folderBody = z.object({ name: z.string().trim().min(1).max(100) }).strict();

export const saveSecretBody = z
  .object({
    value: z.string().min(1).max(10000),
    notes: z.string().max(10000).optional(),
  })
  .strict();

export const generateBody = z
  .object({
    length: z.number().int().min(PASSWORD_LENGTH_MIN).max(PASSWORD_LENGTH_MAX).optional(),
    special: z.boolean().optional(),
  })
  .strict();

export const itemsQuery = z
  .object({
    q: z.string().min(1).optional(),
    uri: z.string().min(1).optional(),
    type: itemType.optional(),
  })
  .strict();
