import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

const request = JSON.parse(readFileSync(0, "utf8"));
const key = Buffer.from(request.key, "hex");
if (key.length !== 32) throw new Error("invalid isolated session key");
const aad = Buffer.from(request.label, "utf8");

if (request.mode === "seal") {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(request.value), "utf8")),
    cipher.final(),
  ]);
  process.stdout.write(Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]).toString("base64"));
} else if (request.mode === "open") {
  const blob = Buffer.from(request.value, "base64");
  if (blob.length < 29 || blob.length > 4096) throw new Error("invalid sealed control message");
  const decipher = createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
  decipher.setAAD(aad);
  decipher.setAuthTag(blob.subarray(12, 28));
  process.stdout.write(Buffer.concat([decipher.update(blob.subarray(28)), decipher.final()]).toString("utf8"));
} else {
  throw new Error("invalid crypto action");
}
