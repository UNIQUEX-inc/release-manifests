import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkManifest, checkSignature } from "../scripts/check-manifest.mjs";

const base = () => ({ schemaVersion: "release-manifest/v1", product: "harness-cli", latest: "0.2.0", minimumSupported: "0.1.0", required: false,
  severity: "feature", summary: { ja: "更新があります" }, publishedAt: "2026-10-13T00:00:00Z", rollback: { ja: "0.1.0 へ戻せます" } });
const codes = (m, o = {}) => checkManifest(m, { product: "harness-cli", signed: false, ...o });

test("a minimal feature manifest passes", () => assert.deepEqual(codes(base()), []));
test("the checked-in mf-migration-kit input passes", () => {
  const m = JSON.parse(readFileSync(new URL("../manifests/mf-migration-kit/release-manifest.json", import.meta.url), "utf8"));
  assert.deepEqual(checkManifest(m, { product: "mf-migration-kit", signed: false }), []);
});
test("the published mf-migration-kit manifest verifies against its pinned key", () => {
  const m = JSON.parse(readFileSync(new URL("../mf-migration-kit/release-manifest.json", import.meta.url), "utf8"));
  const pem = readFileSync(new URL(`../public-keys/${m.signature.keyId}.pem`, import.meta.url), "utf8");
  assert.deepEqual(checkManifest(m, { product: "mf-migration-kit", signed: true }), []);
  assert.deepEqual(checkSignature(m, pem), []);
  m.latest = "9.9.9";
  assert.deepEqual(checkSignature(m, pem), ["signature_invalid"]);
});
test("required:true needs a deadline and security/data severity", () => {
  assert.deepEqual(codes({ ...base(), required: true }).sort(), ["deadline_missing", "required_needs_security_or_data"]);
  assert.deepEqual(codes({ ...base(), required: true, severity: "security", deadline: "2026-10-30T00:00:00Z" }), []);
});
test("a deadline without required:true is rejected", () => assert.deepEqual(codes({ ...base(), deadline: "2026-10-30T00:00:00Z" }), ["deadline_without_required"]));
test("minimumSupported must not exceed latest", () => assert.deepEqual(codes({ ...base(), minimumSupported: "0.3.0" }), ["minimum_exceeds_latest"]));
test("product must match its directory and be known", () => {
  assert.deepEqual(codes(base(), { product: "agentmux" }), ["product_directory_mismatch"]);
  assert.ok(codes({ ...base(), product: "nope" }).includes("product_unknown"));
});
test("bad versions, dates and unknown fields are rejected", () => {
  assert.deepEqual(codes({ ...base(), latest: "1.0.0-beta" }), ["version_invalid:latest"]);
  assert.deepEqual(codes({ ...base(), publishedAt: "2026-10-13" }), ["published_at_invalid"]);
  assert.deepEqual(codes({ ...base(), extra: 1 }), ["unknown_field:extra"]);
});
test("a signed file without a signature block is rejected", () => assert.deepEqual(codes(base(), { signed: true }), ["signature_missing"]));
test("a malformed signature is reported without throwing", () => assert.deepEqual(checkSignature({ ...base(), signature: { algorithm: "rsa" } }, ""), ["signature_malformed"]));
