# Architecture

The module Worker terminates HTTP and dispatches registered XRPC handlers, OAuth routes, identity well-known routes, the firehose WebSocket upgrade, and authenticated generic service proxy requests. Proxy targets are resolved from DID service references, permission-checked, and receive a short-lived repo-key service JWT. HTTP handlers do not write repository tables directly.

Global account state belongs in D1. `AccountRepository`, `SessionRepository`, and `OAuthStore` isolate Drizzle access from handlers. Repository state belongs to one SQLite `AccountRepo` Durable Object per DID. The object serializes mutations, validates blob existence in R2, constructs a canonical MST and signed repo v3 commit, commits records/blocks/blob references/outbox atomically, then delivers an idempotent event to `Firehose`.

`Firehose` owns the global monotonically increasing sequence. It stores encoded event-stream frames before broadcasting them through the Durable Objects WebSocket Hibernation API. Backfill follows the Event Stream specification and replays events with `seq >= cursor`; retained history is currently capped at 10,000 frames.

Worker logs are structured JSON: XRPC/proxy requests include request ID, NSID, status, and duration; Firehose publication includes event type and sequence, plus commit CID for repository events. Credentials, tokens, cookies, and private keys are never logged.

R2 keys are `blobs/{did}/{raw-cid}`. Upload computes the raw CID from bytes. Download first asks the account DO whether the CID is referenced, preventing temporary uploads from becoming public. A delayed Queue message removes uploads that are still unreferenced after 24 hours; failed cleanup messages go to a DLQ.

Failure boundaries:

- D1 and an AccountRepo DO cannot share a distributed transaction.
- PLC publication is external and irreversible; failed creation remains `pending` until an authenticated identical `createAccount` retry replays the deterministic genesis operation. An ambiguous POST is accepted only when the published PLC data exactly matches.
- AccountRepo uses a durable SQLite outbox so transient Firehose delivery failure can be retried by alarm.
- Identity and account events emitted during initial account creation do not yet have a D1 outbox.

Bindings and current platform guidance are documented in `wrangler.jsonc` and the [Cloudflare Durable Objects best practices](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/).
