# pds-workers

Cloudflare Workers、SQLite Durable Objects、D1、R2で動くAT Protocol PDSの独立実装です。公式PDSの移植やラッパーではありません。Cloudflare固有の永続化・配信層を実装し、repo v3の検証・署名・Lexicon処理には公式 `@atproto/*` ライブラリを利用します。

> **開発中です。** ローカルのリポジトリ・同期・public/confidential OAuthフロー、`bsky.tuna2134.dev` のCloudflare Worker/D1デプロイ・wildcard routing、実PLCアカウント作成とCAR署名検証は確認済みです。実Relayとの相互運用は未検証 (**BLOCKED**) です。既知の不足は末尾に明記しています。

## Architecture

```text
Internet -> Worker (XRPC, OAuth, identity)
              |-> D1 (accounts, sessions, OAuth, audit metadata)
              |-> AccountRepo SQLite Durable Object (one per DID)
              |-> Firehose SQLite Durable Object (global sequence + WebSockets)
              `-> R2 (blobs/{did}/{cid})
```

各DIDは `env.ACCOUNT_REPO.getByName(did)` で決定的に同じDurable Objectへ割り当てられます。DOが単一リポジトリの全変更を直列化し、コミットとfirehose outboxを同じSQLiteトランザクションで保存します。詳細は [architecture](docs/architecture.md)、[repository](docs/repository.md)、[sync](docs/sync.md) を参照してください。

## Cloudflare resources

- D1 `pds-workers`: アカウント、identity、legacy/OAuth sessions、設定、audit metadata
- R2 `pds-workers-blobs`: content-addressed blob
- Queue `pds-workers-blob-cleanup`: 24時間後の未参照blob回収（DLQ付き）
- SQLite DO `AccountRepo`: records、MST blocks、commits、blob refs、outbox
- SQLite DO `Firehose`: sequence、retained frames、hibernatable WebSockets
- Workers Rate Limiting: login、account creation、OAuth/PAR/token
- Cloudflare Email Service: password reset and account deletion confirmation
- Generic service proxy: authenticated `/xrpc/*` requests are permission-checked, resolved from the `atproto-proxy` DID service reference, and forwarded with a short-lived signed service JWT
- `com.atproto.repo.listMissingBlobs`: repository references are checked against R2 for migration recovery
- `com.atproto.repo.importRepo`: signed full/differential CARs are verified with `@atproto/repo` and atomically re-signed into the account DO
- Relay discovery: official `com.atproto.sync.listRepos` and `listReposByCollection` enumerate hosted repository heads and collections
- Account migration lifecycle: service-auth existing-DID creation, deactivated staging, recommended PLC credentials, validated PLC submission, activation/deactivation
- Cooperative PLC migration: verified-email one-time tokens and current-PDS rotation-key signing via `requestPlcOperationSignature` / `signPlcOperation`
- Private preference migration: `app.bsky.actor.getPreferences` / `putPreferences`
- Account recovery/deletion: hashed single-use email tokens, session revocation, R2 and DO cleanup
- Account identity management: email ownership/change flows and verified hosted/external handle updates with signed PLC operations
- Read-only admin XRPC: account lookup and search with a fixed, secret bearer credential

`wrangler.jsonc` のプレースホルダーD1 UUID、URL、利用可能handleドメインを本番値に変更してください。binding変更後は必ず `pnpm cf-typegen` を実行します。

## Setup

必要条件はNode.js 22以降、pnpm、Cloudflareアカウントです。

```bash
pnpm install
npx wrangler login
npx wrangler d1 create pds-workers
npx wrangler r2 bucket create pds-workers-blobs
npx wrangler queues create pds-workers-blob-cleanup
npx wrangler queues create pds-workers-blob-cleanup-dlq
```

Cloudflare Email Serviceで送信domainをonboardし、`EMAIL_FROM` をそのdomainの送信元へ変更してください。`send_email` bindingは `EMAIL` として設定済みです。

D1作成時に表示されたUUIDを `wrangler.jsonc` の `database_id` に設定します。次の32-byte値をそれぞれbase64urlで生成し、secretとして登録します。

```bash
npx wrangler secret put SIGNING_KEY_WRAPPING_SECRET
npx wrangler secret put SESSION_JWT_SECRET
npx wrangler secret put ADMIN_PASSWORD
```

`PDS_URL` は公開HTTPS origin、`SERVICE_DID` はサービスDID、`PLC_DIRECTORY` は通常 `https://plc.directory`、`AVAILABLE_USER_DOMAINS` と `CRAWLERS` はJSON配列に設定します。`CRAWLERS` の各Relayにはrepo commit後、非同期で `requestCrawl` を送ります。具体的な手順は [deployment](docs/deployment.md) にあります。

## Database migrations

アプリケーションschemaは `src/db/schema/` にあります。`drizzle/` は生成物なので手編集しません。

```bash
pnpm db:generate
pnpm db:migrate:local
pnpm db:migrate:remote
```

ローカルはWranglerのD1、DOは各class constructorでDrizzle migratorを通して初期化されます。本番migrationはdeploy前にremoteへ適用します。

## Development and checks

```bash
pnpm dev
pnpm typecheck
pnpm lint
pnpm test
pnpm build
```

主なscripts: `dev`、`deploy`、`test:unit`、`test:integration`、`format`、`db:generate`、`db:migrate:local`、`db:migrate:remote`、`cf-typegen`、`lex:verify`、`lex:generate`。

公式LexiconはCID付きで `lexicons.json` に固定しています。CIでは `pnpm lex:verify`、固定内容からvalidatorを再生成する場合は `pnpm lex:generate` を実行します。実装済みXRPCは共通ルータ層で公式parameter/input schemaを検証し、主要なBluesky record schemaも書き込み時に検証します。

テストには公式MST固定CID、1000-record round trip、不正MST、CAR/repo diffの `@atproto/repo` 検証、公式cryptoによるrepo v3署名、full/diff import、DO同時書き込み、R2 blob、DPoPと`private_key_jwt` OAuth、DID service proxy、WebSocket cursor replayが含まれます。unit testだけを根拠にfederation互換とは主張しません。

## Creating the first account

公開前に `PDS_URL`、secret、D1/R2/DO、Worker routeを設定します。アカウント作成はPLC genesisを登録する不可逆な外部操作です。

```bash
curl -sS "$PDS_URL/xrpc/com.atproto.server.createAccount" \
  -H 'content-type: application/json' \
  --data '{"handle":"alice.users.example.com","email":"alice@example.com","password":"use-a-long-unique-password"}'
```

応答のDIDを保存してください。PDS管理下のwildcard subdomainなら `/.well-known/atproto-did` はWorkerが返します。外部handleでは `_atproto.<handle>` TXTへ `did=<DID>` を設定するか、handle originの `/.well-known/atproto-did` でDIDを返します。handleとDID documentの `alsoKnownAs` は双方向に一致する必要があります。

### Account creation troubleshooting

`createAccount` が `500`/`502` になった場合は、まず `x-request-id` を控えて `npx wrangler tail pds-workers` で同じリクエストを確認してください。remote D1へ `pnpm db:migrate:remote` を適用し、`SIGNING_KEY_WRAPPING_SECRET`（32-byte base64url）、`SESSION_JWT_SECRET`、`ADMIN_PASSWORD` をSecretとして登録します。`PDS_URL`、`SERVICE_DID`、`AVAILABLE_USER_DOMAINS` は実際の公開HTTPS origin・DID・handle suffixに置き換えてください。`502` はPLC directoryへの到達・拒否を示し、失敗した作成は同じhandle/email/passwordで再送してpending identityを復旧できます。

## DNS and routing

- `pds.example.com/*` をWorkerへroute
- hosted handlesを使う場合は `*.users.example.com/*` も同じWorkerへroute
- `PDS_URL=https://pds.example.com`
- `AVAILABLE_USER_DOMAINS=[".users.example.com"]`
- `did:web` service documentとPLC documentのPDS endpointが同じ公開originを指すことを確認

DNSレコードはCloudflare DNS側でproxiedとして管理し、Wranglerには `zone_name` 付きの通常Routeを設定します。Custom DomainはDNSを自動管理しwildcardにも非対応なので、この構成では使いません。詳細は [deployment](docs/deployment.md) を参照してください。

## Account migration

既存DIDでの `createAccount` は、現在のDID signing keyによる `com.atproto.server.createAccount` 向けservice-auth JWTを要求し、アカウントを `deactivated` で作成します。その後 `importRepo`、`listMissingBlobs`/`uploadBlob`、`getRecommendedDidCredentials`、旧PDSの `requestPlcOperationSignature` / `signPlcOperation` または自己管理rotation keyによる署名、`submitPlcOperation`、`activateAccount` の順で移行します。DID documentが新しいPDS URL・repo signing key・handleを公開するまでrepositoryは外部配信されません。

## Relay crawling

公開後、firehoseへ接続できることとCARを取得できることを先に確認します。

```bash
curl -fsS "$PDS_URL/xrpc/com.atproto.sync.getRepo?did=<DID>" -o /tmp/repo.car
curl -sS https://bsky.network/xrpc/com.atproto.sync.requestCrawl \
  -H 'content-type: application/json' \
  --data '{"hostname":"pds.example.com"}'
```

Relay登録は外部サービスの判断対象です。sandbox RelayでCAR、署名、MST、commit eventを検証してから本番Relayへ申請してください。

独立CLIのGoatでも、公開handle・レコード・CARを確認できます。

```bash
goat resolve <handle>
goat get 'at://<handle>/<collection>/<rkey>'
goat repo export -o /tmp/repo.car <did>
goat repo inspect /tmp/repo.car
goat repo mst /tmp/repo.car
```

## Security

秘密鍵はsourceへ保存せず、AES-GCM wrapping secretで暗号化します。session/refresh tokenはhashのみ保存します。DPoPはES256署名、server nonce、`htu`、`htm`、`ath`、時刻、JTI replayを検証します。レスポンスはCSP、nosniff、Referrer-Policyを設定し、blobはrepoで参照されるまで公開しません。運用前に [security](docs/security.md) を必ず確認してください。

`ADMIN_PASSWORD` は通常のaccount/session tokenとは別の長いランダムsecretです。`com.atproto.admin.getAccountInfo`、`getAccountInfos`、`searchAccounts` に固定Bearerとして送ります。書き込み系admin APIは、公式Lexicon authority recordを検証できるものだけ追加する方針で、現在は提供しません。

## Known limitations / BLOCKED

- **検証済み:** 現在のCloudflare target (`pds-workers`) ではremote D1 migration、Worker deploy、D1/R2/DO binding初期化、`describeServer` を確認済み。
- **検証済み:** 本物のPLC directoryへ1アカウントを登録し、取得したCARを独立実装で署名・root検証済み。
- **BLOCKED:** `bsky.network` Relay への crawl 要求と `indigo-relay` からの `describeServer` 到達までは確認済み。commit後の自動 `requestCrawl` も実装済みだが、Relay の `accountCount` が 0、`seq` が -1 のため、認証済みの本番書き込みと同一 commit event の Relay 到達確認が残っています。
- OAuth公開permission-set (`include:`) は `_lexicon` DNS、DID document、authority PDSの公開Lexicon recordを検証して解決し、公式 `@atproto/oauth-scopes` で権限へ展開します。
- D1はCloudflare Time Travel、SQLite DOは管理者限定operator endpoint経由の30日PITR、R2はbucket lockを使う復旧runbookを文書化していますが、資格情報がないため本番restore drillは **BLOCKED** です。外部R2複製は未実装です。
- read-only admin account lookup/searchは実装済みです。書き込み系admin APIとemail MFAは、安全のため未対応を偽装せず拒否します。
- 実装済みXRPC endpointと固定済み主要recordは公式Lexiconで検証します。未固定の任意record schemaは既定でfail-open、`validate:true` ではfail-closedです。
- Workers標準WebCryptoのPBKDF2-SHA256（Workersの上限である100,000回）を使用します。`node:crypto` Argon2はWorkers本番ランタイムの前提にせず、Argon2id WASM実装を導入する場合はベンチマークとメモリ上限の検証が必要です。
- 本番 `BLOB_UPLOAD_LIMIT` は50 MBです。現行 `app.bsky.embed.video` Lexiconの最大300 MBを満たさないため、大容量video uploadは未対応です。Cloudflare Free/Proのrequest body上限は100 MBなので、完全対応には上位planまたは別upload経路が必要です。
- PLC登録失敗時はaccountを `pending` に保ち、同一handle・email・passwordでの `createAccount` 再送時に保存済み鍵から同一genesisを再構成します。POST結果が曖昧な場合も公開済みPLC dataが完全一致したときだけactivateします。
- Firehoseは直近10,000 frameを保持します。本番trafficに合わせた保持期間とsnapshot/backfill設計が必要です。
- `wrangler.jsonc` のexample valuesは本番値ではありません。
