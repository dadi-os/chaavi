/** HTTP errors in the contract shape `{error: {type, message}}`. */

export class ChaaviError extends Error {
  readonly statusCode: number;
  readonly type: string;

  constructor(statusCode: number, type: string, message: string) {
    super(message);
    this.name = "ChaaviError";
    this.statusCode = statusCode;
    this.type = type;
  }
}
