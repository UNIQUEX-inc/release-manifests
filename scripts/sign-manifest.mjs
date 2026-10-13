#!/usr/bin/env node
// Sign a release manifest with a Cloud KMS ed25519 key (CHG-1248; specification: Core docs/design/specifications/release-manifest.md 3.1).
//
//   node scripts/sign-manifest.mjs --input manifests/<product>/release-manifest.json --output <product>/release-manifest.json \
//     --key-version projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n> --key-id <keyId> --public-key public-keys/<keyId>.pem
//
// The access token comes from the environment (KMS_ACCESS_TOKEN; the workflow passes the Workload Identity token). No JSON key, no gcloud.
// Signed bytes: UTF-8 of `release-manifest-sha256:<sha256 hex of the RFC 8785 (JCS) form of the manifest without `signature`>`.
// The signature is verified locally against the pinned public key before the output is written, so a wrong key version
// or key id can never be published.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createHash, createPublicKey, verify } from "node:crypto";

const STATEMENT_PREFIX = "release-manifest-sha256:";
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

export function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") { if (!Number.isFinite(value)) throw new Error("not_canonicalizable"); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map((v) => (v === undefined || typeof v === "function" ? "null" : canonicalize(v))).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined && typeof value[k] !== "function").sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(",")}}`;
  }
  throw new Error("not_canonicalizable");
}

export function signedBytes(manifest) {
  const { signature, ...rest } = manifest;
  const hex = createHash("sha256").update(Buffer.from(canonicalize(rest), "utf8")).digest("hex");
  return Buffer.from(`${STATEMENT_PREFIX}${hex}`, "utf8");
}

function arg(name, required = true) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1 || !process.argv[i + 1]) { if (required) throw new Error(`missing --${name}`); return undefined; }
  return process.argv[i + 1];
}

function checkShape(manifest, product) {
  const fail = (m) => { throw new Error(`manifest rejected: ${m}`); };
  if (manifest.schemaVersion !== "release-manifest/v1") fail("schemaVersion must be release-manifest/v1");
  if (manifest.product !== product) fail(`product must equal the directory name (${product})`);
  if (!SEMVER.test(manifest.latest ?? "") || !SEMVER.test(manifest.minimumSupported ?? "")) fail("latest/minimumSupported must be semver");
  if (typeof manifest.required !== "boolean") fail("required must be boolean");
  if (!["security", "data", "feature"].includes(manifest.severity)) fail("severity must be security|data|feature");
  if (manifest.required && (!["security", "data"].includes(manifest.severity) || !manifest.deadline)) fail("required:true needs severity security|data and a deadline");
  if (Number.isNaN(Date.parse(manifest.publishedAt ?? ""))) fail("publishedAt must be an ISO 8601 time");
  if (Date.parse(manifest.publishedAt) > Date.now() + 60_000) fail("publishedAt is in the future");
}

async function kmsSign(keyVersion, data, token) {
  const res = await fetch(`https://cloudkms.googleapis.com/v1/${keyVersion}:asymmetricSign`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ data: data.toString("base64") }),
  });
  if (!res.ok) throw new Error(`KMS asymmetricSign failed: HTTP ${res.status}`);
  const body = await res.json();
  if (typeof body.signature !== "string") throw new Error("KMS asymmetricSign returned no signature");
  return Buffer.from(body.signature, "base64");
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const input = arg("input"), output = arg("output"), keyVersion = arg("key-version"), keyId = arg("key-id"), publicKeyFile = arg("public-key");
  const token = process.env.KMS_ACCESS_TOKEN;
  if (!token) throw new Error("KMS_ACCESS_TOKEN is not set");
  if (!KEY_ID.test(keyId)) throw new Error("invalid key id");
  const product = output.split("/").slice(-2, -1)[0];
  const { signature: _ignored, ...manifest } = JSON.parse(readFileSync(input, "utf8"));
  checkShape(manifest, product);
  const bytes = signedBytes(manifest);
  const sig = await kmsSign(keyVersion, bytes, token);
  const publicKey = createPublicKey(readFileSync(publicKeyFile, "utf8"));
  if (sig.byteLength !== 64 || !verify(null, bytes, publicKey, sig)) throw new Error("signature does not verify against the pinned public key; nothing written");
  const signed = { ...manifest, signature: { algorithm: "ed25519", keyId, signed: "manifest-sha256", value: sig.toString("base64") } };
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(signed, null, 2)}\n`);
  console.log(`signed ${product} ${manifest.latest} (required=${manifest.required}) with ${keyId} -> ${output}`);
}
