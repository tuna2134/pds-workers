# Deployment

1. Create D1, R2, `pds-workers-blob-cleanup`, and `pds-workers-blob-cleanup-dlq` resources with Wrangler.
2. Onboard an outbound domain in Cloudflare Email Service and set `EMAIL_FROM` to an address on that domain.
3. Replace the D1 UUID and example URLs/domains in `wrangler.jsonc`.
4. Configure `SIGNING_KEY_WRAPPING_SECRET`, `SESSION_JWT_SECRET`, and a separate high-entropy `ADMIN_PASSWORD` with `wrangler secret put`.
5. Run `pnpm cf-typegen`, `pnpm typecheck`, `pnpm lint`, `pnpm test`, and `pnpm build`.
6. Generate migrations only after schema changes: `pnpm db:generate`.
7. Apply D1 migrations: `pnpm db:migrate:remote`.
8. Deploy: `pnpm deploy`.
9. Route the PDS origin and optional wildcard hosted-handle domain to the Worker.
10. Verify OAuth metadata, handle well-known, XRPC description, DO initialization, email delivery, blob round trip, CAR export, and firehose before creating a production account.

If account creation returns `500` or `502`, capture the response `x-request-id` and inspect `npx wrangler tail pds-workers`. Confirm that `pnpm db:migrate:remote` completed and that all three secrets are present. A `502` from `createAccount` is normally PLC publication or reachability; retrying the same handle/email/password safely resumes a pending PLC identity after the upstream result is verified.

Example post-deploy probes:

```bash
curl -fsS https://pds.example.com/.well-known/oauth-protected-resource
curl -fsS https://pds.example.com/.well-known/oauth-authorization-server
curl -fsS https://pds.example.com/xrpc/com.atproto.server.describeServer
```

On 2026-08-20, the production protected-resource and authorization-server metadata at `bsky.tuna2134.dev` passed the official `@atproto/oauth-client` 0.8.3 resolvers, including exact resource/issuer matching, HTTPS endpoints, PAR discovery, ES256 DPoP advertisement, and client-ID metadata document support. A complete browser authorization-code exchange against the production account remains **BLOCKED/unverified** without account credentials and interactive consent.

For the current deployment, both `bsky.tuna2134.dev/*` and `*.bsky.tuna2134.dev/*` are ordinary Worker Routes (`zone_name: tuna2134.dev`), not Custom Domains. Keep the apex and wildcard DNS records in the zone and set them to proxied; routes do not create or replace DNS records. Cloudflare Custom Domains do not support wildcard hostnames. Verify a base request returns `200` and an unregistered hosted handle returns an application `404` (not a Cloudflare `522`).

## Backup and recovery

Cloudflare D1 Time Travel is always on for production-backend databases and retains minute-level history for 30 days. Record a bookmark before every remote migration and export a portable SQL copy on a separate schedule:

```bash
npx wrangler d1 info pds-workers
npx wrangler d1 time-travel info pds-workers
npx wrangler d1 export pds-workers --remote --output=./pds-workers.sql
```

Restore is destructive. First export the damaged state, stop writes, select a timestamp/bookmark, and only then run one of:

```bash
npx wrangler d1 time-travel restore pds-workers --bookmark=<BOOKMARK>
npx wrangler d1 time-travel restore pds-workers --timestamp=<RFC3339_TIMESTAMP>
```

A read-only production export was verified on 2026-08-20: the SQL file contained 13 tables and loaded successfully into SQLite. This confirms backup acquisition and parsing, but not destructive restore.

AccountRepo and Firehose use SQLite-backed Durable Objects, whose storage API retains 30 days of PITR history. Recovery targets the deterministic account object (`getByName(did)`) or the global Firehose object through the private `/admin/pitr` operator endpoint. Read or derive a bookmark with `GET`, then stop writes and schedule it with `POST`; the confirmation header must exactly equal the submitted bookmark:

```bash
curl -fsS "$PDS_URL/admin/pitr?kind=account&did=did%3Aplc%3Aexample" -H "authorization: Bearer $ADMIN_PASSWORD"
curl -fsS "$PDS_URL/admin/pitr?kind=account&did=did%3Aplc%3Aexample" \
  -X POST -H "authorization: Bearer $ADMIN_PASSWORD" -H 'content-type: application/json' \
  -H "x-confirm-restore: $BOOKMARK" --data "{\"bookmark\":\"$BOOKMARK\"}"
```

The response contains an undo bookmark and `restartRequired: true`. Restart the object with a controlled Worker deployment, verify repository signature/MST/blob references, and retain the undo bookmark until validation completes. Use `kind=firehose` without `did` for the sequencer. Production PITR remains **BLOCKED/unverified** until an explicit destructive-test authorization and maintenance window are provided. CAR export is an interoperability snapshot, not a complete backup: it does not preserve the wrapped repo signing key or private operational history.

R2 provides replicated eleven-nines durability, but deleted objects cannot be recovered. The current `pds-workers-blobs` bucket has no lock rules. Configure an R2 bucket lock for the desired retention period before production, and test account deletion semantics against that policy because locked blobs cannot be removed until retention expires:

```bash
npx wrangler r2 bucket lock add pds-workers-blobs --name 30-days --retention-days 30
npx wrangler r2 bucket lock list pds-workers-blobs
```

Back up `wrangler.jsonc`, migration sources, deployed version identifiers, and wrapping-secret recovery material in a separate access domain. A wrapping secret without the encrypted DO/D1 state is useless; encrypted state without the wrapping secret permanently loses signing ability. Never place secret values in SQL exports or repository files.

The current `pds-workers` target has passed remote D1 migration (no pending migrations on 2026-08-20), Worker deployment, binding initialization, base route, wildcard hosted-handle route, read-only probes, one real PLC account/CAR verification, and `bsky.network` Relay crawling. The blob-cleanup Queue has one production Worker producer and consumer, and its DLQ exists. Production email delivery remains **BLOCKED/unverified** while `EMAIL_FROM=noreply@example.com`; PITR/restore drills also remain **BLOCKED/unverified**.
