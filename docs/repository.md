# Repository format

Records are converted from Lexicon JSON representation to IPLD values, encoded as deterministic DRISL/DAG-CBOR, and addressed with CIDv1 `dag-cbor` + SHA-256. Blob bytes use CIDv1 `raw` + SHA-256.

MST keys are `<collection>/<record-key>`. The implementation derives layer from successive two-bit zero pairs in SHA-256(key), sorts ASCII keys bytewise, prefix-compresses node keys, and emits `{l,e:[{p,k,v,t}]}` nodes. It supports immutable insert, update, delete, lookup, ordered iteration, serialization, and strict deserialization. Deserialization checks block CID/canonical bytes, shape, prefix bounds, missing/shared/cyclic nodes, ordering, key syntax, then rebuilds the canonical root.

Repo v3 commits contain `did`, `version`, `data`, `rev`, and `prev`. Encoding and low-S secp256k1 signing use the official `@atproto/lex-cbor` and `@atproto/crypto` implementations. TIDs are monotonically advanced even if wall clock time moves backwards.

CAR v1 exports start at the signed commit and include the reachable MST and record blocks. Incremental firehose CARs contain the new commit, changed tree blocks, and changed record blocks. Tests pass complete and differential CARs to `@atproto/repo` as an independent decoder/verifier.

SQLite retains immutable blocks and commits while the `records` table is the current searchable index. The index is not the repository authority: every commit root is rebuilt from record CIDs and checked during export.

Blob uploads remain temporary and unavailable through sync APIs until a repository record references them. New writes require CIDv1 `raw` + SHA-256 links whose declared byte size matches the content-addressed R2 object; imports may temporarily retain missing blobs for migration recovery.

`com.atproto.repo.importRepo` accepts bounded full or differential CARs. `@atproto/repo.verifyDiff` validates CAR blocks, MST completeness, repository DID, and the current DID signing key inside the serialized account DO operation. Imported data is indexed atomically and committed with the destination PDS repo key; missing referenced blobs remain visible through `listMissingBlobs` for migration recovery.

Still required before compatibility claims: broader official DAG-CBOR/CAR fixtures, long-running mutation/property tests, storage compaction policy, and external relay/`atproto-tap` verification against a deployed endpoint. Goat verification against the deployed endpoint has passed.
