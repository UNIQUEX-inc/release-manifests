# release-manifests

UNIQUEX のセルフホスト製品（harness CLI・sdom CLI・mf-migration-kit・SDK・Console・agentmux・ランナー）が「新しい版があるか・強制か」を確かめる
**台帳（release manifest）** を、署名して固定 URL で配信するリポジトリです。台帳には製品名・版・要点だけが入り、秘密は含みません。

仕様の正本は Core の `docs/design/specifications/release-manifest.md`（3.1 署名、4.1 固定 URL、4.2 発行）です（REQ-1234、CHG-1248）。

## 置き場所の規則

| 場所 | 何 | 誰が書く |
|---|---|---|
| `manifests/<product>/release-manifest.json` | **未署名**の台帳（入力）。`signature` は無視される | 製品の発行 workflow、または人の PR |
| `<product>/release-manifest.json` | **署名済み**の台帳（出力） | この repo の workflow だけ（`github-actions[bot]` の commit） |
| `public-keys/<keyId>.pem` | 署名鍵の公開鍵（CI の自己検証用。製品が同梱する正本は Core の `distribution/release-manifests/public-keys/`） | CHG-1248 と鍵の交換のとき |

固定 URL（仕様 4.1【決定 A】）: `https://uniquex-inc.github.io/release-manifests/<product>/release-manifest.json`
（GitHub Pages、main の `/`。`access-control-allow-origin: *` なのでブラウザの SDK からも取れる）。

`<product>` は台帳の `product` と一致させる（小文字・数字・`._-`）。製品のディレクトリは最初の台帳を出すときに作る。

## 発行の決定（仕様 4.2【決定】）

- **`required: false`** の台帳は **CI の自動発行**。`manifests/**` が main に入ると workflow が署名して公開する（environment `auto-publish`、承認なし）。
- **`required: true`**（強制アップデート。`severity` は `security` か `data`、`deadline` 必須）の台帳は **人の承認が必須**。
  workflow は environment `required-update` の required reviewers の承認を待ってから署名する。強制は顧客の業務を止めるため。

## 署名の手順（`.github/workflows/sign-and-publish.yml`）

1. `manifests/<product>/release-manifest.json` の `signature` を除いた台帳を **RFC 8785（JCS）** で正規化する
   （鍵は UTF-16 コード単位の昇順、空白なし、`JSON.stringify` と同じ表現、`undefined` は落とす）。
2. その UTF-8 の sha256（hex）を宣言文 `release-manifest-sha256:<hex>` にし、UTF-8 のバイト列を **Cloud KMS の `asymmetricSign`**（ed25519、PureEdDSA）に渡す。
   KMS には Workload Identity Federation で入る（JSON 鍵なし。付いている役割はその鍵 1 本の `roles/cloudkms.signer` だけ。この repo の `main` から出た token だけ通る）。
3. 返った 64 バイトの署名を、`public-keys/<keyId>.pem` で**その場で検証**する。通らなければ何も書かない。
4. `signature: { algorithm: "ed25519", keyId, signed: "manifest-sha256", value: <base64> }` を付けて `<product>/release-manifest.json` に commit する。
5. GitHub Pages が配信する。製品は次の確認で拾う。

手動で出すときは Actions の `Sign and publish release manifests` を `product` を指定して dispatch する。

| keyId | KMS の鍵の版 | 作成 |
|---|---|---|
| `release-manifest-2026` | `projects/uniquex-service-mgmt-prod/locations/asia-northeast1/keyRings/release-manifests/cryptoKeys/release-manifest-signing/cryptoKeyVersions/1` | 2026-10-13 |

repository variable: `GCP_WORKLOAD_IDENTITY_PROVIDER`・`GCP_SERVICE_ACCOUNT`・`KMS_KEY_VERSION`・`RELEASE_MANIFEST_KEY_ID`（どれも秘密ではない）。

## 検証の手順

```bash
curl -fsSL https://uniquex-inc.github.io/release-manifests/<product>/release-manifest.json -o release-manifest.json
node scripts/verify-manifest.mjs release-manifest.json            # public-keys/<signature.keyId>.pem で検証
```

製品は同梱の公開鍵で同じ検証をし、さらに `publishedAt` が未来でない・保存済みより古くない・`minimumSupported <= latest` を確かめる（仕様 3.1・5）。

## 鍵の交換・漏えい

仕様 3.1 のとおり。新しい `keyId` の公開鍵を製品に同梱した版が `minimumSupported` になってから古い鍵で署名をやめる。鍵の版の destroy は人の承認。
