/** Ed25519 SSH keys in OpenSSH format for new SSH key items. Never log the private key. */

import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";

const KEY_TYPE = "ssh-ed25519";

/** A generated key as Bitwarden stores it. */
export type GeneratedSshKey = {
  privateKey: string;
  publicKey: string;
  keyFingerprint: string;
};

/**
 * generateSshKey makes an Ed25519 key pair: the private key as an unencrypted
 * `openssh-key-v1` PEM, the public key as an authorized_keys line, and its SHA256 fingerprint.
 */
export function generateSshKey(): GeneratedSshKey {
  const pair = generateKeyPairSync("ed25519");
  const pub = jwkBytes(pair.publicKey.export({ format: "jwk" }).x);
  const seed = jwkBytes(pair.privateKey.export({ format: "jwk" }).d);
  const publicBlob = Buffer.concat([sshString(KEY_TYPE), sshString(pub)]);
  const check = randomBytes(4);
  const privateSection = padToBlock(
    Buffer.concat([
      check,
      check,
      sshString(KEY_TYPE),
      sshString(pub),
      sshString(Buffer.concat([seed, pub])),
      sshString(""),
    ]),
  );
  const body = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "latin1"),
    sshString("none"),
    sshString("none"),
    sshString(""),
    uint32(1),
    sshString(publicBlob),
    sshString(privateSection),
  ]);
  const lines = body.toString("base64").match(/.{1,70}/g)!;
  return {
    privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join("\n")}\n-----END OPENSSH PRIVATE KEY-----\n`,
    publicKey: `${KEY_TYPE} ${publicBlob.toString("base64")}`,
    keyFingerprint: sshFingerprint(publicBlob),
  };
}

/** sshFingerprint is OpenSSH's `SHA256:` fingerprint of a public key blob. */
export function sshFingerprint(publicBlob: Buffer): string {
  return `SHA256:${createHash("sha256").update(publicBlob).digest("base64").replace(/=+$/, "")}`;
}

/** Decode a JWK base64url member that node always sets for OKP keys. */
function jwkBytes(value: string | undefined): Buffer {
  if (value === undefined) {
    throw new Error("ed25519 JWK export is missing key bytes");
  }
  return Buffer.from(value, "base64url");
}

/** SSH wire `string`: a uint32 length, then the bytes. */
function sshString(value: string | Buffer): Buffer {
  const bytes = typeof value === "string" ? Buffer.from(value, "latin1") : value;
  return Buffer.concat([uint32(bytes.length), bytes]);
}

function uint32(n: number): Buffer {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(n);
  return out;
}

/** Pad the private section to the 8-byte cipher block with 1, 2, 3, … as OpenSSH does. */
function padToBlock(section: Buffer): Buffer {
  const pad: number[] = [];
  for (let i = 1; (section.length + pad.length) % 8 !== 0; i++) {
    pad.push(i);
  }
  return Buffer.concat([section, Buffer.from(pad)]);
}
