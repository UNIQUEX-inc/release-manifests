#!/usr/bin/env node
// Verify a signed release manifest against a pinned public key (no dependencies).
//   node scripts/verify-manifest.mjs <product>/release-manifest.json [public-keys/<keyId>.pem]
// Exit 0 when the signature verifies with the key whose file name equals signature.keyId; exit 1 otherwise.
import { readFileSync } from "node:fs";
import { createPublicKey, verify } from "node:crypto";
import { signedBytes } from "./sign-manifest.mjs";

const [file, keyFile] = process.argv.slice(2);
if (!file) { console.error("usage: verify-manifest.mjs <manifest> [public-key.pem]"); process.exit(2); }
const manifest = JSON.parse(readFileSync(file, "utf8"));
const sig = manifest.signature;
if (!sig || sig.algorithm !== "ed25519" || sig.signed !== "manifest-sha256" || typeof sig.keyId !== "string" || typeof sig.value !== "string") {
  console.error("invalid_signature: missing or malformed signature block"); process.exit(1);
}
const pem = keyFile ?? new URL(`../public-keys/${sig.keyId}.pem`, import.meta.url).pathname;
const value = Buffer.from(sig.value, "base64");
const ok = value.byteLength === 64 && verify(null, signedBytes(manifest), createPublicKey(readFileSync(pem, "utf8")), value);
console.log(ok ? `ok ${manifest.product} ${manifest.latest} keyId=${sig.keyId}` : `INVALID ${file}`);
process.exit(ok ? 0 : 1);
