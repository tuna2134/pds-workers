# Sync and firehose

Implemented sync endpoints include `getRepo`, `getLatestCommit`, `getRepoStatus`, `getRecord`, `getBlocks`, `listBlobs`, `getBlob`, and WebSocket `subscribeRepos`.

`getRepo` returns a CAR rooted at the current signed commit. `getRecord` returns the commit, MST proof blocks, and requested record without unrelated record blocks. `getBlocks` returns a multi-root CAR in requested CID order and rejects missing blocks. Blob listing records the revision at which each live reference first appeared.

Each repository mutation normally produces a current `#commit` event containing `seq`, `repo`, `commit`, `rev`, `since`, `prevData`, CAR `blocks`, operations, and time. Frames are concatenated DRISL-CBOR header and body objects. A commit that cannot fit the Lexicon limit of 200 operations or 2,000,000 block bytes is represented by a `#sync` event containing only a CAR-rooted commit block, requiring downstream repository resynchronization. The hard WebSocket frame limit is 5 MB. Identity and account events use the same sequencer.

Firehose reconnect behavior:

- backfill is inclusive and replays persisted events with `seq >= cursor`;
- a future cursor receives `FutureCursor` and closes;
- an older-than-retention cursor receives `#info OutdatedCursor`, then replay starts at the oldest retained event;
- live sockets are hibernatable and no Worker request is held open.

Production validation remains **BLOCKED** without a deployed hostname and Relay access. Required external checks are: parse `getRepo` with `goat`, verify DID key signature and MST root, connect `atproto-tap`, request relay crawling, write a record, and observe the same valid commit event downstream.

`com.atproto.sync.listRepos` enumerates hosted DID/head/revision state from D1 plus each AccountRepo DO. `listReposByCollection` performs the corresponding bounded collection scan. Pages are capped at 999 repository RPCs so the endpoint remains below the Workers Free internal-subrequest limit; cursors continue larger scans.
