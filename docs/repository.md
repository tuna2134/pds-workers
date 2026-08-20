# Repository format

Records are converted from Lexicon JSON representation to IPLD values, encoded as deterministic DRISL/DAG-CBOR, and addressed with CIDv1 `dag-cbor` + SHA-256. Blob bytes use CIDv1 `raw` + SHA-256.

MST keys are `<collection>/<record-key>`. The implementation derives layer from successive two-bit zero pairs in SHA-256(key), sorts ASCII keys bytewise, prefix-compresses node keys, and emits `{l,e:[{p,k,v,t}]}` nodes. It supports immutable insert, update, delete, lookup, ordered iteration, serialization, and strict deserialization. Deserialization checks block CID/canonical bytes, shape, prefix bounds, missing/shared/cyclic nodes, ordering, key syntax, then rebuilds the canonical root.

Repo v3 commits contain `did`, `version`, `data`, `rev`, and `prev`. Encoding and low-S secp256k1 signing use the official `@atproto/lex-cbor` and `@atproto/crypto` implementations. TIDs are monotonically advanced even if wall clock time moves backwards.

CAR v1 exports start at the signed commit and include the reachable MST and record blocks. Incremental firehose CARs contain the new commit, changed tree blocks, and changed record blocks. Tests pass complete and differential CARs to `@atproto/repo` as an independent decoder/verifier. MST tests cover official root fixtures, insertion-order equivalence, replacement/deletion, malformed and boundary keys, a 1,000-record round trip, 128 deterministic records in forward and reverse order, and a fixed-seed 256-operation create/update/delete sequence. Each comparison checks roots against the official incremental `@atproto/repo` MST implementation; mutation checkpoints also compare ordered leaves and the final serialization round trip.

SQLite retains immutable blocks and commits while the `records` table is the current searchable index. Each block records the latest revision whose full tree referenced it. When history exceeds 1,100 commits, AccountRepo atomically retains the latest 1,000 commits and every block reachable during that window; an older `getRepo?since=` revision falls back to a complete current CAR. Existing objects backfill unversioned blocks to the current revision after the generated Durable Object migration. The index is not the repository authority: every commit root is rebuilt from record CIDs and checked during export.

Blob uploads remain temporary and unavailable through sync APIs until a repository record references them. New writes require CIDv1 `raw` + SHA-256 links whose declared byte size matches the content-addressed R2 object; imports may temporarily retain missing blobs for migration recovery.

`com.atproto.repo.importRepo` accepts bounded full or differential CARs. `@atproto/repo.verifyDiff` validates CAR blocks, MST completeness, repository DID, and the current DID signing key inside the serialized account DO operation. Imported data is indexed atomically and committed with the destination PDS repo key; missing referenced blobs remain visible through `listMissingBlobs` for migration recovery.

Still required before unrestricted compatibility claims: broader official DAG-CBOR/CAR fixtures, multi-hour mutation/compaction soak tests, and `atproto-tap` verification against a deployed endpoint. Goat and the public `bsky.network` Relay have verified the deployed endpoint.
