# Security

This service handles internet-facing credentials and signing keys. Do not deploy the example configuration unchanged.

Key material:

- repo signing keys are generated per account and immediately AES-GCM wrapped inside the account DO;
- PLC rotation material is wrapped before D1 storage;
- wrapping and session secrets are Wrangler secrets, never variables or source;
- plan rotation and recovery before creating production PLC identities.

Authentication:

- passwords use Workers WebCrypto PBKDF2-SHA256 at the Workers limit of 100,000 iterations; `node:crypto` Argon2 is not assumed in production Workers, and missing-account login attempts run the same KDF path to reduce enumeration timing differences;
- legacy access/refresh JWTs are short-lived, stored as hashes, and refresh rotation is claimed by an atomic conditional D1 update so concurrent reuse has one winner;
- OAuth requires PAR, S256 PKCE, state, CSRF cookie, DPoP ES256, signed server nonce, request and token binding, JTI replay storage, ES256 `private_key_jwt` for confidential clients, and restricts authentication to the account named by `login_hint`; DPoP headers reject private JWK material and malformed claim types, while authorization-code consumption and token-hash storage use one conditional D1 update;
- OAuth client metadata is validated and cached for five minutes; redirect URIs enforce the `web`/`native` scheme and origin rules, including localhost's path-match/port-ignore exception. Published `include:` permission sets are authority-checked through `_lexicon` DNS and DID/PDS resolution, then namespace-confined by the official `@atproto/oauth-scopes` implementation.
- Generic service proxying requires an active authenticated account, checks `rpc` permissions, accepts only a resolved HTTPS DID service origin, strips client credentials and cookies, limits request bodies, and applies a dedicated rate limit.
- existing-DID account creation requires a five-minute service JWT issued by the DID's current signing key with exact audience and `lxm`; migrated accounts remain deactivated and publicly unreadable until the live DID document names this PDS and its reserved repo key;
- submitted PLC operations must extend the current PLC log, verify against a current rotation key, and retain the PDS-generated rotation, signing, handle, and service credentials before forwarding;
- outbound PLC migration signatures require full-account authentication, a confirmed email, a rate-limited single-use token, current-log lookup, and schema/key/size validation before the wrapped PDS rotation key is used;
- granular permissions are parsed with `@atproto/oauth-scopes`;
- password-reset and account-deletion tokens are random, stored only as SHA-256 hashes, expire after 15 minutes, and are invalidated after use; password reset revokes all legacy sessions and app passwords;
- email ownership and confirmed-address changes use the same bounded token store; confirmed-address changes require a token delivered to the old address, and the replacement address returns to unconfirmed state;
- handle updates reserve the normalized handle in D1, verify external DNS/HTTPS ownership, preserve PLC keys/services, sign with the wrapped PDS rotation key, then publish an identity event;
- login, account creation, PAR, token, and revocation paths use Cloudflare Rate Limit bindings.
- read-only admin account lookup/search requires a separate fixed Bearer secret and compares it in constant time; it never returns password hashes, session material, or signing keys.

Trust boundaries:

- validate body size/content type before parsing;
- OAuth metadata/JWKS, permission-set PDS, `did:web`, handle HTTPS, and service-proxy fetches reject redirects, non-HTTPS/literal-IP targets, private or reserved A/AAAA answers, and timeouts; metadata responses are also size-limited;
- handle resolution validates syntax and DID `alsoKnownAs` bidirectionally;
- blob downloads require a live repository reference and set a sandbox CSP plus `nosniff`;
- logs include request metadata but never passwords, bearer/refresh tokens, or private keys.
- D1 audit records cover account creation, password/app-password login outcomes, session and app-password revocation, and OAuth authorization/token lifecycle events; IP addresses are stored only as hashes.

Before production, use a DNS-pinning egress service if the deployment must eliminate the DNS-check/fetch rebinding window, extend audit coverage to remaining administrative state changes, add abuse monitoring and secret-rotation runbooks, add off-account R2 copies where required, scan dependencies, and obtain an independent security review. The PITR operator requires the admin secret plus an exact bookmark confirmation header and only schedules restoration for the next DO restart. D1 Time Travel and DO PITR retain 30 days; R2 bucket locks prevent deletion but can conflict with account-erasure timing. Native rate-limit counters are permissive and location-local; they are defense in depth, not accurate global quotas.
