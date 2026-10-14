#!/usr/bin/env node
// Structural check of release manifests on pull requests (CHG-1300). No signing, no network, no dependencies.
//   node scripts/check-manifest.mjs [repo-root]
// Mirrors the constraints of Core core/schema/release-manifest.schema.json (release-manifest/v1) that matter before publishing.
// Checks manifests/<product>/release-manifest.json (unsigned, input) and <product>/release-manifest.json (signed, published; the
// signature must verify against public-keys/<keyId>.pem). Exit 0 when every file passes, 1 otherwise.
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicKey, verify } from "node:crypto";
import { signedBytes } from "./sign-manifest.mjs";

export const PRODUCTS = ["service-console", "harness-cli", "sdom-cli", "mf-migration-kit", "agentmux", "feedback-web", "tetsudai-runner"];
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const DATE_TIME = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$/;
const NO_CONTROL = /^[^\u0000-\u001f\u007f-\u009f]+$/;
const TOP_KEYS = ["schemaVersion", "product", "latest", "minimumSupported", "required", "deadline", "severity", "summary", "notesUrl", "publishedAt", "rollback", "update", "afterUpdate", "history", "signature"];

const cmp = (a, b) => { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i]; return 0; };
const text = (v, max) => typeof v === "string" && v.length >= 1 && v.length <= max && NO_CONTROL.test(v);
const line = (v, jaMax, enMax) => v && typeof v === "object" && text(v.ja, jaMax) && (v.en === undefined || text(v.en, enMax)) && Object.keys(v).every((k) => k === "ja" || k === "en");

// Returns a list of error codes (empty when valid). `signed` requires a signature block.
export function checkManifest(m, { product, signed }) {
  const e = [];
  if (!m || typeof m !== "object" || Array.isArray(m)) return ["manifest_not_object"];
  for (const k of Object.keys(m)) if (!TOP_KEYS.includes(k)) e.push(`unknown_field:${k}`);
  if (m.schemaVersion !== "release-manifest/v1") e.push("schema_version");
  if (!PRODUCTS.includes(m.product)) e.push("product_unknown");
  if (product && m.product !== product) e.push("product_directory_mismatch");
  for (const k of ["latest", "minimumSupported"]) if (typeof m[k] !== "string" || !VERSION.test(m[k])) e.push(`version_invalid:${k}`);
  if (VERSION.test(m.latest ?? "") && VERSION.test(m.minimumSupported ?? "") && cmp(m.minimumSupported, m.latest) > 0) e.push("minimum_exceeds_latest");
  if (typeof m.required !== "boolean") e.push("required_not_boolean");
  if (!["security", "data", "feature"].includes(m.severity)) e.push("severity_invalid");
  if (m.required === true) {
    if (m.deadline === undefined) e.push("deadline_missing");
    if (!["security", "data"].includes(m.severity)) e.push("required_needs_security_or_data");
  } else if (m.required === false && m.deadline !== undefined) e.push("deadline_without_required");
  if (m.deadline !== undefined && (typeof m.deadline !== "string" || !DATE_TIME.test(m.deadline))) e.push("deadline_invalid");
  if (typeof m.publishedAt !== "string" || !DATE_TIME.test(m.publishedAt)) e.push("published_at_invalid");
  else if (Date.parse(m.publishedAt) > Date.now() + 5 * 60_000) e.push("published_at_in_future");
  if (!line(m.summary, 120, 160)) e.push("summary_invalid");
  if (!m.rollback || typeof m.rollback !== "object" || !text(m.rollback.ja, 300)) e.push("rollback_invalid");
  if (m.notesUrl !== undefined && !(typeof m.notesUrl === "string" && /^https:\/\/[^\s]+$/.test(m.notesUrl))) e.push("notes_url_invalid");
  if (m.update !== undefined && !(m.update && text(m.update.command, 300))) e.push("update_command_invalid");
  if (m.history !== undefined) {
    if (!Array.isArray(m.history)) e.push("history_invalid");
    else m.history.forEach((h, i) => { if (!(typeof h?.version === "string" && VERSION.test(h.version) && DATE_TIME.test(h.publishedAt ?? "") && h.summary?.ja)) e.push(`history_invalid:${i}`); });
  }
  if (signed && !m.signature) e.push("signature_missing");
  return e;
}

export function checkSignature(m, publicKeyPem) {
  const s = m.signature;
  if (!s || s.algorithm !== "ed25519" || s.signed !== "manifest-sha256" || typeof s.keyId !== "string" || typeof s.value !== "string") return ["signature_malformed"];
  const value = Buffer.from(s.value, "base64");
  return value.byteLength === 64 && verify(null, signedBytes(m), createPublicKey(publicKeyPem), value) ? [] : ["signature_invalid"];
}

function run(root) {
  const failures = [];
  const files = [];
  const dirs = (base) => (existsSync(base) ? readdirSync(base).filter((d) => statSync(join(base, d)).isDirectory()) : []);
  for (const p of dirs(join(root, "manifests"))) { const f = join(root, "manifests", p, "release-manifest.json"); if (existsSync(f)) files.push({ f, product: p, signed: false, name: `manifests/${p}` }); }
  for (const p of readdirSync(root).filter((d) => PRODUCTS.includes(d))) { const f = join(root, p, "release-manifest.json"); if (existsSync(f)) files.push({ f, product: p, signed: true, name: p }); }
  for (const { f, product, signed, name } of files) {
    let m;
    try { m = JSON.parse(readFileSync(f, "utf8")); } catch { failures.push(`${name}: json_invalid`); continue; }
    const errors = checkManifest(m, { product, signed });
    if (signed && m.signature && !errors.length) {
      const pem = join(root, "public-keys", `${m.signature.keyId}.pem`);
      errors.push(...(existsSync(pem) ? checkSignature(m, readFileSync(pem, "utf8")) : ["public_key_missing"]));
    }
    for (const x of errors) failures.push(`${name}: ${x}`);
  }
  return { count: files.length, failures };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { count, failures } = run(process.argv[2] ?? process.cwd());
  for (const x of failures) console.error(`NG ${x}`);
  console.log(`checked ${count} manifest file(s), ${failures.length} problem(s)`);
  process.exit(failures.length ? 1 : 0);
}
