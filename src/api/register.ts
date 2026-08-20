import { XrpcError } from "../xrpc/errors";
import { jsonBody, required, XrpcRouter, type XrpcContext } from "../xrpc/router";
import type { AccountRepo, RepoWrite } from "../durable/account-repo";
import { d1 } from "../db/d1";
import { AccountRepository } from "../db/accounts";
import { SessionRepository } from "../auth/session";
import { hashPassword, verifyPassword, verifyPasswordOrDummy } from "../auth/password";
import { TidClock } from "../repo/tid";
import { tokenHash } from "../crypto/jwt";
import { BlobStorage } from "../blob/storage";
import { resolveHandle, resolveHandleMapping } from "../identity/handle";
import { didProvider, validDid } from "../identity/did";
import { asAtprotoDid, extractAtprotoData, didDocumentValidator } from "@atproto/did";
import { normalizeHandle } from "../identity/handle";
import { createPlcOperation, createPlcUpdate, createSignedPlcUpdate, k256DidKey, plcDocument, publishPlcOperation, submitPlcOperation, validatePlcUpdate, type PlcDocumentData, type PlcOperation } from "../identity/plc";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { unwrapKey, wrapKey } from "../crypto/key-wrap";
import { dpopNonce, validDpopNonce, verifyDpop } from "../auth/oauth/dpop";
import { OAuthStore } from "../auth/oauth/store";
import { ScopePermissionsTransition } from "@atproto/oauth-scopes";
import { AppPasswordRepository } from "../auth/app-password";
import { isValidNsid, isValidTid } from "@atproto/syntax";
import { validateRecord } from "../lexicon/validator";
import { AuditRepository } from "../db/audit";
import { verifyServiceJwt } from "../crypto/service-jwt";
import { PreferencesRepository } from "../db/preferences";
import { EmailTokenRepository } from "../auth/email-token";
import { requireAdmin } from "../auth/admin";

let clock: TidClock | undefined;

function tidClock(): TidClock {
	return clock ??= new TidClock();
}

function bearer(request: Request): string {
	const match = /^Bearer (\S+)$/.exec(request.headers.get("authorization") ?? "");
	if (!match) throw new XrpcError(401, "AuthenticationRequired");
	return match[1];
}

function accountView(account: Awaited<ReturnType<AccountRepository["findById"]>> & {}) {
	return { did: account.did, handle: account.handle, email: account.email, indexedAt: account.createdAt.toISOString() };
}

export async function authenticated(context: XrpcContext, type: "at+jwt" | "refresh+jwt" = "at+jwt", allowDeactivated = false) {
	const database = d1(context.env.DB);
	const authorization = context.request.headers.get("authorization") ?? "";
	if (authorization.startsWith("DPoP ")) {
		if (type !== "at+jwt") throw new XrpcError(401, "InvalidToken");
		const token = authorization.slice(5);
		const proof = context.request.headers.get("dpop");
		if (!proof) throw new XrpcError(401, "use_dpop_nonce");
		try {
			const nonce = dpopNonce(proof);
			if (!nonce || !await validDpopNonce(nonce, context.env.SESSION_JWT_SECRET)) throw new TypeError("Invalid nonce");
			const verified = await verifyDpop(proof, { method: context.request.method, url: `${context.env.PDS_URL}${new URL(context.request.url).pathname}`, nonce, accessToken: token });
			const store = new OAuthStore(database);
			const session = await store.findAccess(token);
			if (!session || session.dpopJkt !== verified.jkt || !session.accountId) throw new TypeError("Invalid token");
			await store.recordProof(verified.jkt, verified.claims.jti);
			const account = await new AccountRepository(database).findById(session.accountId);
			if (!account || account.status !== "active" && !(allowDeactivated && account.status === "deactivated")) throw new TypeError("Invalid account");
			return { account, authentication: { session }, sessions: new SessionRepository(database, context.env.SESSION_JWT_SECRET, context.env.SERVICE_DID), permissions: new ScopePermissionsTransition(session.permissionsScope ?? session.scope) };
		} catch { throw new XrpcError(401, "InvalidToken"); }
	}
	const authentication = await new SessionRepository(database, context.env.SESSION_JWT_SECRET, context.env.SERVICE_DID).authenticate(bearer(context.request), type);
	if (!authentication) throw new XrpcError(401, "InvalidToken");
	const account = await new AccountRepository(database).find(authentication.claims.sub);
	if (!account || account.status !== "active" && !(allowDeactivated && account.status === "deactivated")) throw new XrpcError(401, "InvalidToken");
	return { account, authentication, sessions: new SessionRepository(database, context.env.SESSION_JWT_SECRET, context.env.SERVICE_DID), permissions: authentication.session.appPasswordId ? new ScopePermissionsTransition(authentication.session.scope) : null };
}

function accountAdmin(permissions: ScopePermissionsTransition | null) {
	if (permissions) throw new XrpcError(403, "AuthScopeMismatch", "Full account authentication is required");
}

function emailManage(permissions: ScopePermissionsTransition | null) {
	if (permissions && !permissions.allowsAccount({ attr: "email", action: "manage" })) throw new XrpcError(403, "AuthScopeMismatch", "Email management permission is required");
}

function emailAddress(input: string | undefined) {
	const email = input?.trim().toLowerCase();
	if (!email || email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new XrpcError(400, "InvalidEmail");
	return email;
}

function isConstraintError(error: unknown): boolean {
	return error instanceof Error && /(?:unique|constraint|already exists)/i.test(error.message);
}

function repoAdmin(permissions: ScopePermissionsTransition | null) {
	if (permissions && !permissions.allowsAccount({ attr: "repo", action: "manage" })) throw new XrpcError(403, "AuthScopeMismatch", "Repository management permission is required");
}

function repoPermission(permissions: ScopePermissionsTransition | null, collection: string, action: "create" | "update" | "delete") {
	if (permissions && !permissions.allowsRepo({ collection, action })) throw new XrpcError(403, "AuthScopeMismatch", `Missing repository ${action} permission for ${collection}`);
}

function rpcPermission(permissions: ScopePermissionsTransition | null, lxm: string, aud: string) {
	if (permissions && !permissions.allowsRpc({ lxm, aud })) throw new XrpcError(403, "AuthScopeMismatch", `Missing RPC permission for ${lxm}`);
}

function ownedRepo(identifier: string, account: { did: string; handle: string }) {
	if (identifier !== account.did && identifier.toLowerCase() !== account.handle) throw new XrpcError(403, "Forbidden", "Repository does not belong to the authenticated account");
}

async function audit(context: XrpcContext, action: string, accountId?: string, detail?: Record<string, unknown>) {
	await new AuditRepository(d1(context.env.DB)).record({ action, accountId, requestId: context.requestId, ipHash: await tokenHash(context.request.headers.get("cf-connecting-ip") ?? "unknown"), detail });
}

function repo(env: Env, did: string) {
	if (!validDid(did)) throw new XrpcError(400, "InvalidRequest", "Invalid DID");
	return env.ACCOUNT_REPO.getByName(did) as unknown as AccountRepo;
}

async function applyRepoWrites(target: AccountRepo, writes: RepoWrite[], swapCommit?: string) {
	try { return await target.applyWrites(writes, swapCommit); }
	catch (error) {
		if (error instanceof Error && ["InvalidSwap", "RecordAlreadyExists", "RecordNotFound"].includes(error.message)) throw new XrpcError(400, error.message);
		if (error instanceof TypeError || error instanceof RangeError || error instanceof Error && error.message.startsWith("BlobNotFound:")) throw new XrpcError(400, "InvalidRequest", error.message);
		throw error;
	}
}

async function repoIdentifier(env: Env, identifier: string) {
	let did = identifier;
	if (!validDid(did)) try { did = await resolveHandle(identifier); } catch { throw new XrpcError(400, "RepoNotFound"); }
	const account = await new AccountRepository(d1(env.DB)).find(did);
	if (!account || account.status !== "active") throw new XrpcError(400, "RepoNotFound");
	return repo(env, did);
}

async function activeAccount(env: Env, identifier: string) {
	const accounts = new AccountRepository(d1(env.DB));
	try {
		const direct = await accounts.find(normalizeHandle(identifier));
		if (direct?.status === "active") return direct;
	} catch { /* resolve externally below */ }
	let did = identifier;
	if (!validDid(did)) try { did = await resolveHandle(identifier); } catch { throw new XrpcError(400, "InvalidRequest"); }
	const account = await accounts.find(did);
	if (!account || account.status !== "active") throw new XrpcError(400, "ProfileNotFound");
	return account;
}

function car(bytes: Uint8Array, rev?: string) {
	return new Response(bytes, { headers: { "content-type": "application/vnd.ipld.car", ...(rev ? { "atproto-repo-rev": rev } : {}) } });
}

export function createRouter(): XrpcRouter {
	const router = new XrpcRouter();
	router.registerQuery("com.atproto.admin.getAccountInfo", async (context) => {
		await requireAdmin(context.request, context.env);
		const account = await new AccountRepository(d1(context.env.DB)).find(required(context.params, "did"));
		if (!account) throw new XrpcError(400, "AccountNotFound");
		return accountView(account);
	});
	router.registerQuery("com.atproto.admin.getAccountInfos", async (context) => {
		await requireAdmin(context.request, context.env);
		const dids = context.params.getAll("dids");
		if (!dids.length || dids.length > 100) throw new XrpcError(400, "InvalidRequest", "Between 1 and 100 DIDs are required");
		const found = new Map((await new AccountRepository(d1(context.env.DB)).findMany(dids)).map((account) => [account.did, account]));
		return { infos: dids.flatMap((did) => { const account = found.get(did); return account ? [accountView(account)] : []; }) };
	});
	router.registerQuery("com.atproto.admin.searchAccounts", async (context) => {
		await requireAdmin(context.request, context.env);
		const limit = Number(context.params.get("limit") ?? 50);
		const rows = await new AccountRepository(d1(context.env.DB)).search({ email: context.params.get("email")?.toLowerCase(), cursor: context.params.get("cursor") ?? undefined, limit });
		return { accounts: rows.map(accountView), ...(rows.length === limit ? { cursor: rows.at(-1)!.id } : {}) };
	});
	router.registerQuery("com.atproto.server.describeServer", ({ env }) => ({
		did: env.SERVICE_DID,
		availableUserDomains: JSON.parse(env.AVAILABLE_USER_DOMAINS) as string[],
		inviteCodeRequired: false,
		blobUploadLimit: Number(env.BLOB_UPLOAD_LIMIT),
	}));
	router.registerQuery("com.atproto.identity.resolveHandle", async ({ params }) => {
		try { return { did: await resolveHandle(required(params, "handle")) }; }
		catch (error) {
			if (error instanceof TypeError) throw new XrpcError(400, "InvalidRequest", error.message);
			throw new XrpcError(400, "HandleNotFound");
		}
	});
	router.registerProcedure("com.atproto.identity.updateHandle", async (context) => {
		const { account, permissions } = await authenticated(context);
		if (permissions && !permissions.allowsIdentity({ attr: "handle" })) throw new XrpcError(403, "AuthScopeMismatch", "Handle management permission is required");
		const input = await jsonBody<{ handle?: string }>(context.request);
		let handle: string;
		try { handle = normalizeHandle(input.handle ?? ""); } catch { throw new XrpcError(400, "InvalidHandle"); }
		if (handle === account.handle) return new Response(null, { status: 200 });
		const database = d1(context.env.DB);
		const accounts = new AccountRepository(database);
		if (await accounts.find(handle)) throw new XrpcError(400, "HandleNotAvailable");
		const hosted = (JSON.parse(context.env.AVAILABLE_USER_DOMAINS) as string[]).some((domain) => handle.endsWith(domain) && handle.length > domain.length);
		if (!hosted) try {
			const resolved = account.did.startsWith("did:plc:") ? await resolveHandleMapping(handle) : await resolveHandle(handle);
			if (resolved !== account.did) throw new Error("Handle mismatch");
		} catch { throw new XrpcError(400, "InvalidHandle", "Handle does not resolve to this DID"); }
		try { await accounts.reserveHandle(account.did, handle); }
		catch { throw new XrpcError(400, "HandleNotAvailable"); }
		try {
			let document: object;
			if (account.did.startsWith("did:plc:")) {
				const identity = await accounts.findIdentity(account.did);
				if (!identity?.signingKey) throw new Error("PLC rotation key is unavailable");
				const update = await createPlcUpdate(context.env.PLC_DIRECTORY, account.did, handle, await unwrapKey(identity.signingKey, context.env.SIGNING_KEY_WRAPPING_SECRET));
				await submitPlcOperation(context.env.PLC_DIRECTORY, account.did, update.operation);
				document = plcDocument(update.data);
			} else document = await didProvider(account.did).resolve(account.did);
			await accounts.updateHandle(account, handle, document);
			await context.env.FIREHOSE.getByName("global").publishIdentity(`identity:${account.did}:${crypto.randomUUID()}`, account.did, handle);
			await audit(context, "identity.handle.updated", account.id);
			return new Response(null, { status: 200 });
		} catch (error) {
			await accounts.releaseHandle(account.did, handle);
			throw new XrpcError(502, "UpstreamFailure", error instanceof Error ? error.message : "Handle update failed");
		}
	});
	router.registerQuery("app.bsky.actor.getPreferences", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		rpcPermission(permissions, "app.bsky.actor.getPreferences", context.env.SERVICE_DID);
		return { preferences: await new PreferencesRepository(d1(context.env.DB)).get(account.id) };
	});
	router.registerQuery("app.bsky.actor.getProfile", async (context) => {
		const account = await activeAccount(context.env, required(context.params, "actor"));
		const record = await repo(context.env, account.did).getRecord("app.bsky.actor.profile/self");
		const value = record?.value as Record<string, unknown> | undefined;
		const blobUrl = (field: unknown) => {
			if (!field || typeof field !== "object") return undefined;
			const ref = (field as { ref?: { $link?: unknown } }).ref;
			return typeof ref?.$link === "string" ? `${context.env.PDS_URL}/xrpc/com.atproto.sync.getBlob?did=${encodeURIComponent(account.did)}&cid=${encodeURIComponent(ref.$link)}` : undefined;
		};
		return {
			did: account.did,
			handle: account.handle,
			...(typeof value?.displayName === "string" ? { displayName: value.displayName } : {}),
			...(typeof value?.description === "string" ? { description: value.description } : {}),
			...(blobUrl(value?.avatar) ? { avatar: blobUrl(value?.avatar) } : {}),
			...(blobUrl(value?.banner) ? { banner: blobUrl(value?.banner) } : {}),
			labels: [],
			viewer: {},
		};
	});
	router.registerProcedure("app.bsky.actor.putPreferences", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		rpcPermission(permissions, "app.bsky.actor.putPreferences", context.env.SERVICE_DID);
		const { preferences } = await jsonBody<{ preferences: Record<string, unknown>[] }>(context.request);
		await new PreferencesRepository(d1(context.env.DB)).put(account.id, preferences);
		await audit(context, "account.preferences.updated", account.id);
		return {};
	});
	router.registerQuery("com.atproto.identity.getRecommendedDidCredentials", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		accountAdmin(permissions);
		const identity = await new AccountRepository(d1(context.env.DB)).findIdentity(account.did);
		if (!identity?.signingKey) throw new XrpcError(400, "InvalidRequest", "PLC rotation key is unavailable");
		const rotationKey = await unwrapKey(identity.signingKey, context.env.SIGNING_KEY_WRAPPING_SECRET);
		return {
			rotationKeys: [k256DidKey(secp256k1.getPublicKey(rotationKey))],
			alsoKnownAs: [`at://${account.handle}`],
			verificationMethods: { atproto: await repo(context.env, account.did).signingKeyDid() },
			services: { atproto_pds: { type: "AtprotoPersonalDataServer", endpoint: context.env.PDS_URL } },
		};
	});
	router.registerProcedure("com.atproto.identity.requestPlcOperationSignature", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		accountAdmin(permissions);
		if (!account.did.startsWith("did:plc:")) throw new XrpcError(400, "InvalidRequest", "Account does not use did:plc");
		if (!account.emailConfirmed) throw new XrpcError(400, "EmailNotConfirmed");
		const rate = await context.env.LOGIN_ACCOUNT_RATE.limit({ key: `plc-sign:${await tokenHash(account.did)}` });
		if (!rate.success) throw new XrpcError(429, "RateLimitExceeded");
		const tokens = new EmailTokenRepository(d1(context.env.DB));
		const token = await tokens.create(account.id, "plc-operation");
		try { await context.env.EMAIL.send({ from: context.env.EMAIL_FROM, to: account.email, subject: "Confirm PLC identity operation", text: `Your PLC operation token is:\n\n${token}\n\nThis token expires in 15 minutes.` }); }
		catch { await tokens.revoke(account.id, "plc-operation"); throw new XrpcError(503, "EmailDeliveryFailed", "Unable to send PLC operation email"); }
		await audit(context, "identity.plc_signature.requested", account.id);
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.identity.signPlcOperation", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		accountAdmin(permissions);
		if (!account.did.startsWith("did:plc:")) throw new XrpcError(400, "InvalidRequest", "Account does not use did:plc");
		const input = await jsonBody<{ token?: string; rotationKeys?: string[]; verificationMethods?: PlcDocumentData["verificationMethods"]; alsoKnownAs?: string[]; services?: PlcDocumentData["services"] }>(context.request);
		if (!input.token) throw new XrpcError(400, "TokenRequired");
		const tokens = new EmailTokenRepository(d1(context.env.DB));
		const verification = await tokens.verify(account.id, "plc-operation", input.token);
		if (verification !== "valid") throw new XrpcError(400, verification === "expired" ? "ExpiredToken" : "InvalidToken");
		const identity = await new AccountRepository(d1(context.env.DB)).findIdentity(account.did);
		if (!identity?.signingKey) throw new XrpcError(400, "InvalidRequest", "PLC rotation key is unavailable");
		try {
			const changes = { ...(input.rotationKeys ? { rotationKeys: input.rotationKeys } : {}), ...(input.verificationMethods ? { verificationMethods: input.verificationMethods } : {}), ...(input.alsoKnownAs ? { alsoKnownAs: input.alsoKnownAs } : {}), ...(input.services ? { services: input.services } : {}) };
			const signed = await createSignedPlcUpdate(context.env.PLC_DIRECTORY, account.did, changes, await unwrapKey(identity.signingKey, context.env.SIGNING_KEY_WRAPPING_SECRET));
			if (await tokens.consume(account.id, "plc-operation", input.token) !== "valid") throw new XrpcError(400, "InvalidToken");
			await audit(context, "identity.plc_operation.signed", account.id);
			return { operation: signed.operation };
		} catch (error) {
			if (error instanceof XrpcError) throw error;
			throw new XrpcError(400, "InvalidRequest", error instanceof Error ? error.message : "Invalid PLC operation");
		}
	});
	router.registerProcedure("com.atproto.identity.submitPlcOperation", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		accountAdmin(permissions);
		if (!account.did.startsWith("did:plc:")) throw new XrpcError(400, "InvalidRequest", "Account does not use did:plc");
		const input = await jsonBody<{ operation?: unknown }>(context.request);
		if (!input.operation) throw new XrpcError(400, "InvalidRequest", "operation is required");
		try {
			const { operation, data } = await validatePlcUpdate(context.env.PLC_DIRECTORY, account.did, input.operation);
			const identity = await new AccountRepository(d1(context.env.DB)).findIdentity(account.did);
			if (!identity?.signingKey) throw new TypeError("PLC rotation key is unavailable");
			const rotationDid = k256DidKey(secp256k1.getPublicKey(await unwrapKey(identity.signingKey, context.env.SIGNING_KEY_WRAPPING_SECRET)));
			if (data.verificationMethods.atproto !== await repo(context.env, account.did).signingKeyDid() || data.services.atproto_pds.endpoint.replace(/\/$/, "") !== context.env.PDS_URL.replace(/\/$/, "") || !data.alsoKnownAs.includes(`at://${account.handle}`) || !data.rotationKeys.includes(rotationDid)) throw new TypeError("PLC operation does not contain the recommended credentials");
			await submitPlcOperation(context.env.PLC_DIRECTORY, account.did, operation as PlcOperation);
			await new AccountRepository(d1(context.env.DB)).updateIdentity(account.did, plcDocument(data));
			await audit(context, "identity.plc.submitted", account.id);
			return new Response(null, { status: 200 });
		} catch (error) { throw new XrpcError(400, "InvalidRequest", error instanceof Error ? error.message : "Invalid PLC operation"); }
	});
	router.registerProcedure("com.atproto.server.createSession", async (context) => {
		const { request, env } = context;
		const input = await jsonBody<{ identifier?: string; password?: string }>(request);
		if (!input.identifier || !input.password) throw new XrpcError(400, "InvalidRequest", "identifier and password are required");
		const [accountLimit, ipLimit] = await Promise.all([
			env.LOGIN_ACCOUNT_RATE.limit({ key: await tokenHash(input.identifier.toLowerCase()) }),
			env.LOGIN_IP_RATE.limit({ key: await tokenHash(request.headers.get("cf-connecting-ip") ?? "unknown") }),
		]);
		if (!accountLimit.success || !ipLimit.success) throw new XrpcError(429, "RateLimitExceeded", "Too many login attempts");
		const database = d1(env.DB);
		const account = await new AccountRepository(database).find(input.identifier);
		const main = await verifyPasswordOrDummy(input.password, account?.passwordHash);
		if (!account || !["active", "deactivated"].includes(account.status)) { await audit(context, "auth.login.failed"); throw new XrpcError(401, "AuthenticationRequired", "Invalid identifier or password"); }
		const appPassword = main ? null : await new AppPasswordRepository(database).find(account.id, input.password);
		if (!main && !appPassword) { await audit(context, "auth.login.failed", account.id); throw new XrpcError(401, "AuthenticationRequired", "Invalid identifier or password"); }
		const tokens = await new SessionRepository(database, env.SESSION_JWT_SECRET, env.SERVICE_DID).create(account, appPassword ? { appPasswordId: appPassword.id, privileged: appPassword.privileged } : undefined);
		await audit(context, "auth.login.succeeded", account.id, { appPassword: Boolean(appPassword) });
		return { ...tokens, handle: account.handle, did: account.did, ...(!appPassword || appPassword.privileged ? { email: account.email, emailConfirmed: account.emailConfirmed, emailAuthFactor: account.emailAuthFactor } : {}), active: account.status === "active", status: account.status };
	});
	router.registerProcedure("com.atproto.server.requestPasswordReset", async (context) => {
		const input = await jsonBody<{ email?: string }>(context.request);
		const email = input.email?.trim().toLowerCase();
		if (!email) throw new XrpcError(400, "InvalidRequest", "email is required");
		const [accountLimit, ipLimit] = await Promise.all([
			context.env.LOGIN_ACCOUNT_RATE.limit({ key: `reset:${await tokenHash(email)}` }),
			context.env.LOGIN_IP_RATE.limit({ key: `reset:${await tokenHash(context.request.headers.get("cf-connecting-ip") ?? "unknown")}` }),
		]);
		if (!accountLimit.success || !ipLimit.success) throw new XrpcError(429, "RateLimitExceeded");
		const account = await new AccountRepository(d1(context.env.DB)).find(email);
		if (account && ["active", "deactivated"].includes(account.status)) {
			const tokens = new EmailTokenRepository(d1(context.env.DB));
			const token = await tokens.create(account.id, "password-reset");
			try {
				await context.env.EMAIL.send({ from: context.env.EMAIL_FROM, to: account.email, subject: "Reset your password", text: `Your password reset token is:\n\n${token}\n\nThis token expires in 15 minutes.` });
				await audit(context, "auth.password_reset.requested", account.id);
			} catch {
				await tokens.revoke(account.id, "password-reset");
				await audit(context, "auth.password_reset.delivery_failed", account.id);
			}
		}
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.server.resetPassword", async (context) => {
		const input = await jsonBody<{ token?: string; password?: string }>(context.request);
		if (!input.token || !input.password) throw new XrpcError(400, "InvalidRequest", "token and password are required");
		if (input.password.length < 12) throw new XrpcError(400, "InvalidPassword", "Password must contain at least 12 characters");
		const found = await new EmailTokenRepository(d1(context.env.DB)).consumeByToken("password-reset", input.token);
		if (found.status !== "valid") throw new XrpcError(400, found.status === "expired" ? "ExpiredToken" : "InvalidToken");
		await new AccountRepository(d1(context.env.DB)).resetPassword(found.accountId, await hashPassword(input.password));
		await audit(context, "auth.password_reset.completed", found.accountId);
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.server.requestEmailConfirmation", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		emailManage(permissions);
		if (account.emailConfirmed) return new Response(null, { status: 200 });
		const rate = await context.env.LOGIN_ACCOUNT_RATE.limit({ key: `confirm-email:${await tokenHash(account.did)}` });
		if (!rate.success) throw new XrpcError(429, "RateLimitExceeded");
		const tokens = new EmailTokenRepository(d1(context.env.DB));
		const token = await tokens.create(account.id, "email-confirm");
		try { await context.env.EMAIL.send({ from: context.env.EMAIL_FROM, to: account.email, subject: "Confirm your email", text: `Your email confirmation token is:\n\n${token}\n\nThis token expires in 15 minutes.` }); }
		catch { await tokens.revoke(account.id, "email-confirm"); throw new XrpcError(503, "EmailDeliveryFailed", "Unable to send confirmation email"); }
		await audit(context, "account.email_confirmation.requested", account.id);
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.server.confirmEmail", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		emailManage(permissions);
		const input = await jsonBody<{ email?: string; token?: string }>(context.request);
		if (emailAddress(input.email) !== account.email) throw new XrpcError(400, "InvalidEmail");
		const tokens = new EmailTokenRepository(d1(context.env.DB));
		const verification = input.token ? await tokens.consume(account.id, "email-confirm", input.token) : "invalid";
		if (verification !== "valid") throw new XrpcError(400, verification === "expired" ? "ExpiredToken" : "InvalidToken");
		await new AccountRepository(d1(context.env.DB)).confirmEmail(account.id);
		await audit(context, "account.email_confirmed", account.id);
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.server.requestEmailUpdate", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		emailManage(permissions);
		if (!account.emailConfirmed) return { tokenRequired: false };
		const rate = await context.env.LOGIN_ACCOUNT_RATE.limit({ key: `update-email:${await tokenHash(account.did)}` });
		if (!rate.success) throw new XrpcError(429, "RateLimitExceeded");
		const tokens = new EmailTokenRepository(d1(context.env.DB));
		const token = await tokens.create(account.id, "email-update");
		try { await context.env.EMAIL.send({ from: context.env.EMAIL_FROM, to: account.email, subject: "Confirm email change", text: `Your email change token is:\n\n${token}\n\nThis token expires in 15 minutes.` }); }
		catch { await tokens.revoke(account.id, "email-update"); throw new XrpcError(503, "EmailDeliveryFailed", "Unable to send confirmation email"); }
		await audit(context, "account.email_update.requested", account.id);
		return { tokenRequired: true };
	});
	router.registerProcedure("com.atproto.server.updateEmail", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		emailManage(permissions);
		const input = await jsonBody<{ email?: string; token?: string; emailAuthFactor?: boolean }>(context.request);
		if (input.emailAuthFactor) throw new XrpcError(400, "InvalidRequest", "Email authentication factor is not supported");
		const email = emailAddress(input.email);
		if (email === account.email) return new Response(null, { status: 200 });
		const tokens = new EmailTokenRepository(d1(context.env.DB));
		if (account.emailConfirmed) {
			if (!input.token) throw new XrpcError(400, "TokenRequired");
			const verification = await tokens.consume(account.id, "email-update", input.token);
			if (verification !== "valid") throw new XrpcError(400, verification === "expired" ? "ExpiredToken" : "InvalidToken");
		}
		try { await new AccountRepository(d1(context.env.DB)).updateEmail(account.id, email); }
		catch { throw new XrpcError(400, "InvalidEmail", "Email address is unavailable"); }
		await Promise.all([tokens.revoke(account.id, "email-update"), tokens.revoke(account.id, "email-confirm")]);
		await audit(context, "account.email_updated", account.id);
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.server.createAccount", async (context) => {
		const { request, env } = context;
		const input = await jsonBody<{ did?: string; handle?: string; email?: string; password?: string; recoveryKey?: string; plcOp?: unknown }>(request);
		if (!input.handle || !input.email || !input.password) throw new XrpcError(400, "InvalidRequest", "handle, email, and password are required");
		if (input.password.length < 12) throw new XrpcError(400, "InvalidPassword", "Password must contain at least 12 characters");
		if (input.recoveryKey || input.plcOp) throw new XrpcError(400, "InvalidRequest", "recoveryKey and plcOp are not supported by this PDS flow");
		const allowed = JSON.parse(env.AVAILABLE_USER_DOMAINS) as string[];
		let handle: string;
		try { handle = normalizeHandle(input.handle); } catch { throw new XrpcError(400, "InvalidHandle"); }
		if (!input.did && !allowed.some((domain) => handle.endsWith(domain) && handle.length > domain.length)) throw new XrpcError(400, "UnsupportedDomain");
		const rate = await env.CREATE_ACCOUNT_RATE.limit({ key: await tokenHash(request.headers.get("cf-connecting-ip") ?? "unknown") });
		if (!rate.success) throw new XrpcError(429, "RateLimitExceeded");
		const database = d1(env.DB);
		const accounts = new AccountRepository(database);
		const email = input.email.toLowerCase();
		const [handleAccount, emailAccount] = await Promise.all([accounts.find(handle), accounts.find(email)]);
		if (handleAccount || emailAccount) {
			const pending = handleAccount?.id === emailAccount?.id && handleAccount?.status === "pending" ? handleAccount : undefined;
			if (!pending || !await verifyPassword(input.password, pending.passwordHash)) throw new XrpcError(400, "HandleNotAvailable");
			const identity = await accounts.findIdentity(pending.did);
			if (!identity?.signingKey) throw new XrpcError(502, "UpstreamFailure", "Pending PLC identity cannot be recovered");
			const retry = await createPlcOperation({ handle, service: env.PDS_URL, rotationKey: await unwrapKey(identity.signingKey, env.SIGNING_KEY_WRAPPING_SECRET), signingPublicKey: await repo(env, pending.did).signingKeyDid() });
			if (retry.did !== pending.did) throw new XrpcError(502, "UpstreamFailure", "Pending PLC identity cannot be recovered");
			try { await publishPlcOperation(env.PLC_DIRECTORY, pending.did, retry.operation); }
			catch { throw new XrpcError(502, "UpstreamFailure", "PLC directory rejected identity creation; account remains pending"); }
			const active = await accounts.activate(pending.id);
			if (!active) throw new Error("Account activation failed");
			await env.FIREHOSE.getByName("global").publishIdentity(`identity:${pending.did}:created`, pending.did, handle);
			await env.FIREHOSE.getByName("global").publishAccount(`account:${pending.did}:active`, pending.did, true);
			await audit(context, "account.created", active.id);
			return { ...await new SessionRepository(database, env.SESSION_JWT_SECRET, env.SERVICE_DID).create(active), handle, did: pending.did, didDoc: identity.document };
		}
		const signingKey = secp256k1.utils.randomSecretKey();
		const rotationKey = secp256k1.utils.randomSecretKey();
		if (input.did) {
			if (!validDid(input.did)) throw new XrpcError(400, "UnresolvableDid");
			const serviceToken = /^Bearer (\S+)$/.exec(request.headers.get("authorization") ?? "")?.[1];
			if (!serviceToken || !await verifyServiceJwt(serviceToken, input.did, env.SERVICE_DID, "com.atproto.server.createAccount")) throw new XrpcError(401, "AuthenticationRequired");
			let document;
			try { document = await didProvider(input.did).resolve(input.did); }
			catch { throw new XrpcError(400, "UnresolvableDid"); }
			if (extractAtprotoData(document).aka?.toLowerCase() !== handle) throw new XrpcError(400, "IncompatibleDidDoc", "Handle does not match DID document");
			let account;
			try {
				account = await accounts.createPending({ did: input.did, handle, email, passwordHash: await hashPassword(input.password), provider: input.did.split(":", 2).join(":"), wrappedRotationKey: await wrapKey(rotationKey, env.SIGNING_KEY_WRAPPING_SECRET), document, status: "deactivated" });
			} catch (error) { if (isConstraintError(error)) throw new XrpcError(400, "HandleNotAvailable"); throw error; }
			await repo(env, input.did).initialize(input.did, signingKey);
			await audit(context, "account.migration.created", account.id);
			return { ...await new SessionRepository(database, env.SESSION_JWT_SECRET, env.SERVICE_DID).create(account), handle, did: input.did, didDoc: document };
		}
		const { did, operation } = await createPlcOperation({ handle, service: env.PDS_URL, rotationKey, signingPublicKey: secp256k1.getPublicKey(signingKey) });
		const didDoc = {
			id: did, alsoKnownAs: operation.alsoKnownAs,
			verificationMethod: [{ id: `${did}#atproto`, type: "Multikey", controller: did, publicKeyMultibase: operation.verificationMethods.atproto.slice("did:key:".length) }],
			service: [{ id: `${did}#atproto_pds`, type: "AtprotoPersonalDataServer", serviceEndpoint: env.PDS_URL }],
		};
		let account;
		try {
			account = await accounts.createPending({ did, handle, email, passwordHash: await hashPassword(input.password), provider: "did:plc", wrappedRotationKey: await wrapKey(rotationKey, env.SIGNING_KEY_WRAPPING_SECRET), document: didDoc });
		} catch (error) { if (isConstraintError(error)) throw new XrpcError(400, "HandleNotAvailable"); throw error; }
		await repo(env, did).initialize(did, signingKey);
		try { await publishPlcOperation(env.PLC_DIRECTORY, did, operation); }
		catch { throw new XrpcError(502, "UpstreamFailure", "PLC directory rejected identity creation; account remains pending"); }
		const active = await accounts.activate(account.id);
		if (!active) throw new Error("Account activation failed");
		const firehose = env.FIREHOSE.getByName("global");
		await firehose.publishIdentity(`identity:${did}:created`, did, handle);
		await firehose.publishAccount(`account:${did}:active`, did, true);
		await audit(context, "account.created", active.id);
		return { ...await new SessionRepository(database, env.SESSION_JWT_SECRET, env.SERVICE_DID).create(active), handle, did, didDoc };
	});
	router.registerQuery("com.atproto.server.getSession", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		const email = !permissions || permissions.allowsAccount({ attr: "email", action: "read" });
		return { handle: account.handle, did: account.did, ...(email ? { email: account.email, emailConfirmed: account.emailConfirmed, emailAuthFactor: account.emailAuthFactor } : {}), active: account.status === "active", status: account.status };
	});
	router.registerProcedure("com.atproto.server.refreshSession", async (context) => {
		const token = bearer(context.request);
		const { account, sessions, permissions } = await authenticated(context, "refresh+jwt", true);
		const tokens = await sessions.refresh(token, account);
		if (!tokens) throw new XrpcError(401, "InvalidToken");
		const email = !permissions || permissions.allowsAccount({ attr: "email", action: "read" });
		return { ...tokens, handle: account.handle, did: account.did, ...(email ? { email: account.email, emailConfirmed: account.emailConfirmed, emailAuthFactor: account.emailAuthFactor } : {}), active: account.status === "active", status: account.status };
	});
	router.registerProcedure("com.atproto.server.deleteSession", async (context) => {
		const { account, authentication, sessions } = await authenticated(context, "refresh+jwt", true);
		await sessions.revoke(authentication.session.id);
		await audit(context, "auth.session.revoked", account.id);
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.server.activateAccount", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		accountAdmin(permissions);
		if (account.status !== "deactivated") throw new XrpcError(400, "InvalidRequest", "Account is not deactivated");
		let document;
		try { document = await didProvider(account.did).resolve(account.did); }
		catch { throw new XrpcError(400, "IncompatibleDidDoc", "DID document is unavailable"); }
		const data = extractAtprotoData(document);
		if (data.aka?.toLowerCase() !== account.handle || data.pds?.serviceEndpoint.replace(/\/$/, "") !== context.env.PDS_URL.replace(/\/$/, "") || !data.key || `did:key:${data.key.publicKeyMultibase}` !== await repo(context.env, account.did).signingKeyDid()) throw new XrpcError(400, "IncompatibleDidDoc", "DID document does not contain this account's credentials");
		const accounts = new AccountRepository(d1(context.env.DB));
		await accounts.updateIdentity(account.did, document);
		await accounts.setStatus(account.id, "active");
		const firehose = context.env.FIREHOSE.getByName("global");
		await firehose.publishIdentity(`identity:${account.did}:${crypto.randomUUID()}`, account.did, account.handle);
		await firehose.publishAccount(`account:${account.did}:active:${crypto.randomUUID()}`, account.did, true);
		await repo(context.env, account.did).resign();
		await audit(context, "account.activated", account.id);
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.server.deactivateAccount", async (context) => {
		const { account, permissions } = await authenticated(context);
		accountAdmin(permissions);
		const input = await jsonBody<{ deleteAfter?: string }>(context.request);
		await new AccountRepository(d1(context.env.DB)).setStatus(account.id, "deactivated");
		await context.env.FIREHOSE.getByName("global").publishAccount(`account:${account.did}:deactivated:${crypto.randomUUID()}`, account.did, false, "deactivated");
		await audit(context, "account.deactivated", account.id, input.deleteAfter ? { deleteAfter: input.deleteAfter } : undefined);
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.server.requestAccountDelete", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		accountAdmin(permissions);
		const rate = await context.env.LOGIN_ACCOUNT_RATE.limit({ key: `delete:${await tokenHash(account.did)}` });
		if (!rate.success) throw new XrpcError(429, "RateLimitExceeded");
		const tokens = new EmailTokenRepository(d1(context.env.DB));
		const token = await tokens.create(account.id, "account-delete");
		try {
			await context.env.EMAIL.send({ from: context.env.EMAIL_FROM, to: account.email, subject: "Confirm account deletion", text: `Your account deletion confirmation token is:\n\n${token}\n\nThis token expires in 15 minutes.` });
		} catch {
			await tokens.revoke(account.id, "account-delete");
			throw new XrpcError(503, "EmailDeliveryFailed", "Unable to send confirmation email");
		}
		await audit(context, "account.delete.requested", account.id);
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.server.deleteAccount", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		accountAdmin(permissions);
		const input = await jsonBody<{ did?: string; password?: string; token?: string }>(context.request);
		if (input.did !== account.did) throw new XrpcError(400, "InvalidRequest", "DID does not match authenticated account");
		if (!input.password || !await verifyPassword(input.password, account.passwordHash)) throw new XrpcError(401, "AuthenticationRequired", "Invalid password");
		const verification = input.token ? await new EmailTokenRepository(d1(context.env.DB)).consume(account.id, "account-delete", input.token) : "invalid";
		if (verification !== "valid") throw new XrpcError(400, verification === "expired" ? "ExpiredToken" : "InvalidToken");
		const accounts = new AccountRepository(d1(context.env.DB));
		await accounts.setStatus(account.id, "deactivated");
		await context.env.FIREHOSE.getByName("global").publishAccount(`account:${account.did}:deleted:${crypto.randomUUID()}`, account.did, false, "deleted");
		await new BlobStorage(context.env.BLOBS, Number(context.env.BLOB_UPLOAD_LIMIT)).deleteAccount(account.did);
		await repo(context.env, account.did).deleteAccount();
		await audit(context, "account.deleted", account.id);
		await accounts.delete(account);
		return new Response(null, { status: 200 });
	});
	router.registerProcedure("com.atproto.server.createAppPassword", async (context) => {
		const { account, permissions } = await authenticated(context);
		accountAdmin(permissions);
		const input = await jsonBody<{ name?: string; privileged?: boolean }>(context.request);
		if (!input.name) throw new XrpcError(400, "InvalidRequest", "name is required");
		try {
			const created = await new AppPasswordRepository(d1(context.env.DB)).create(account.id, input.name, input.privileged ?? false);
			await audit(context, "auth.app_password.created", account.id, { privileged: created.row.privileged });
			return { name: created.row.name, password: created.secret, createdAt: created.row.createdAt.toISOString(), privileged: created.row.privileged };
		} catch (error) {
			if (error instanceof TypeError) throw new XrpcError(400, "InvalidRequest", error.message);
			throw new XrpcError(400, "InvalidRequest", "An app password with this name already exists");
		}
	});
	router.registerQuery("com.atproto.server.listAppPasswords", async (context) => {
		const { account, permissions } = await authenticated(context);
		accountAdmin(permissions);
		return { passwords: (await new AppPasswordRepository(d1(context.env.DB)).list(account.id)).map(({ name, createdAt, privileged }) => ({ name, createdAt: createdAt.toISOString(), privileged })) };
	});
	router.registerProcedure("com.atproto.server.revokeAppPassword", async (context) => {
		const { account, permissions } = await authenticated(context);
		accountAdmin(permissions);
		const input = await jsonBody<{ name?: string }>(context.request);
		if (!input.name) throw new XrpcError(400, "InvalidRequest", "name is required");
		await new AppPasswordRepository(d1(context.env.DB)).revoke(account.id, input.name);
		await audit(context, "auth.app_password.revoked", account.id);
		return new Response(null, { status: 200 });
	});
	router.registerQuery("com.atproto.server.getServiceAuth", async (context) => {
		const { account, permissions } = await authenticated(context);
		const aud = required(context.params, "aud");
		const lxm = context.params.get("lxm") ?? undefined;
		if (aud.length > 2048 || !validDid(aud) || lxm && !isValidNsid(lxm)) throw new XrpcError(400, "InvalidRequest");
		if (permissions && (!lxm || !permissions.allowsRpc({ aud, lxm }))) throw new XrpcError(403, "AuthScopeMismatch");
		const rawExp = context.params.get("exp");
		const exp = rawExp === null ? undefined : Number(rawExp);
		try { return { token: await repo(context.env, account.did).signServiceAuth(aud, lxm, exp) }; }
		catch (error) {
			if (error instanceof RangeError) throw new XrpcError(400, "BadExpiration");
			throw error;
		}
	});
	router.registerQuery("com.atproto.server.checkAccountStatus", async (context) => {
		const { account } = await authenticated(context, "at+jwt", true);
		const status = await repo(context.env, account.did).status();
		return { activated: account.status === "active", validDid: validDid(account.did), repoCommit: status.commit, repoRev: status.rev, repoBlocks: status.repoBlocks, indexedRecords: status.indexedRecords, privateStateValues: 0, expectedBlobs: status.expectedBlobs, importedBlobs: status.expectedBlobs };
	});
	router.registerProcedure("com.atproto.repo.createRecord", async (context) => {
		const { account, permissions } = await authenticated(context);
		const input = await jsonBody<{ repo?: string; collection?: string; rkey?: string; validate?: boolean; record?: Record<string, unknown>; swapCommit?: string }>(context.request);
		if (!input.repo || !input.collection || !input.record) throw new XrpcError(400, "InvalidRequest");
		ownedRepo(input.repo, account);
		repoPermission(permissions, input.collection, "create");
		if (input.record.$type !== input.collection) throw new XrpcError(400, "InvalidRequest", "record.$type must match collection");
		const rkey = input.rkey ?? tidClock().next();
		let validationStatus;
		try { validationStatus = validateRecord(input.collection, rkey, input.record, input.validate); }
		catch (error) { throw new XrpcError(400, "InvalidRequest", error instanceof Error ? error.message : "Invalid record"); }
		const target = repo(context.env, account.did);
		const commit = await applyRepoWrites(target, [{ action: "create", path: `${input.collection}/${rkey}`, record: input.record }], input.swapCommit);
		const record = await target.getRecord(`${input.collection}/${rkey}`);
		return { uri: record!.uri, cid: record!.cid, commit: { cid: commit.commit, rev: commit.rev }, validationStatus };
	});
	router.registerProcedure("com.atproto.repo.putRecord", async (context) => {
		const { account, permissions } = await authenticated(context);
		const input = await jsonBody<{ repo?: string; collection?: string; rkey?: string; validate?: boolean; record?: Record<string, unknown>; swapRecord?: string; swapCommit?: string }>(context.request);
		if (!input.repo || !input.collection || !input.rkey || !input.record) throw new XrpcError(400, "InvalidRequest");
		ownedRepo(input.repo, account);
		if (input.record.$type !== input.collection) throw new XrpcError(400, "InvalidRequest", "record.$type must match collection");
		let validationStatus;
		try { validationStatus = validateRecord(input.collection, input.rkey, input.record, input.validate); }
		catch (error) { throw new XrpcError(400, "InvalidRequest", error instanceof Error ? error.message : "Invalid record"); }
		const target = repo(context.env, account.did);
		const existing = await target.getRecord(`${input.collection}/${input.rkey}`);
		repoPermission(permissions, input.collection, existing ? "update" : "create");
		const commit = await applyRepoWrites(target, [{ action: existing ? "update" : "create", path: `${input.collection}/${input.rkey}`, record: input.record, swapRecord: input.swapRecord }], input.swapCommit);
		const record = await target.getRecord(`${input.collection}/${input.rkey}`);
		return { uri: record!.uri, cid: record!.cid, commit: { cid: commit.commit, rev: commit.rev }, validationStatus };
	});
	router.registerProcedure("com.atproto.repo.deleteRecord", async (context) => {
		const { account, permissions } = await authenticated(context);
		const input = await jsonBody<{ repo?: string; collection?: string; rkey?: string; swapRecord?: string; swapCommit?: string }>(context.request);
		if (!input.repo || !input.collection || !input.rkey) throw new XrpcError(400, "InvalidRequest");
		ownedRepo(input.repo, account);
		repoPermission(permissions, input.collection, "delete");
		const commit = await applyRepoWrites(repo(context.env, account.did), [{ action: "delete", path: `${input.collection}/${input.rkey}`, swapRecord: input.swapRecord }], input.swapCommit);
		return { commit: { cid: commit.commit, rev: commit.rev } };
	});
	router.registerProcedure("com.atproto.repo.applyWrites", async (context) => {
		const { account, permissions } = await authenticated(context);
		type InputWrite = { $type?: string; collection?: string; rkey?: string; value?: Record<string, unknown> };
		const input = await jsonBody<{ repo?: string; validate?: boolean; writes?: InputWrite[]; swapCommit?: string }>(context.request, 2_000_000);
		if (!input.repo || !Array.isArray(input.writes) || !input.writes.length) throw new XrpcError(400, "InvalidRequest");
		ownedRepo(input.repo, account);
		const validationStatuses: Array<"valid" | "unknown" | undefined> = [];
		const prepared: RepoWrite[] = input.writes.map((write) => {
			if (!write.collection) throw new XrpcError(400, "InvalidRequest", "Each write requires a collection");
			const kind = write.$type?.split("#").at(-1);
			if (kind === "delete") {
				if (!write.rkey) throw new XrpcError(400, "InvalidRequest", "Delete requires rkey");
				repoPermission(permissions, write.collection, kind);
				validationStatuses.push(undefined);
				return { action: "delete" as const, path: `${write.collection}/${write.rkey}` };
			}
			if ((kind !== "create" && kind !== "update") || !write.value || write.value.$type !== write.collection) throw new XrpcError(400, "InvalidRequest", "Invalid create or update write");
			repoPermission(permissions, write.collection, kind);
			const rkey = write.rkey ?? (kind === "create" ? tidClock().next() : undefined);
			if (!rkey) throw new XrpcError(400, "InvalidRequest", "Update requires rkey");
			try { validationStatuses.push(validateRecord(write.collection, rkey, write.value, input.validate)); }
			catch (error) { throw new XrpcError(400, "InvalidRequest", error instanceof Error ? error.message : "Invalid record"); }
			return { action: kind, path: `${write.collection}/${rkey}`, record: write.value };
		});
		const target = repo(context.env, account.did);
		const committed = await applyRepoWrites(target, prepared, input.swapCommit);
		const results = await Promise.all(prepared.map(async (write, index) => {
			if (write.action === "delete") return {};
			const record = await target.getRecord(write.path);
			return { uri: record!.uri, cid: record!.cid, validationStatus: validationStatuses[index] };
		}));
		return { commit: { cid: committed.commit, rev: committed.rev }, results };
	});
	router.registerProcedure("com.atproto.repo.uploadBlob", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		if (permissions && !permissions.allowsBlob({ mime: context.request.headers.get("content-type") ?? "application/octet-stream" })) throw new XrpcError(403, "AuthScopeMismatch", "Missing blob upload permission");
		try { return { blob: await new BlobStorage(context.env.BLOBS, Number(context.env.BLOB_UPLOAD_LIMIT), context.env.BLOB_CLEANUP).upload(account.did, context.request) }; }
		catch (error) {
			if (error instanceof RangeError) throw new XrpcError(413, "BlobTooLarge", error.message);
			if (error instanceof TypeError) throw new XrpcError(400, "InvalidRequest", error.message);
			throw error;
		}
	});
	router.registerQuery("com.atproto.repo.listMissingBlobs", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		repoAdmin(permissions);
		return repo(context.env, account.did).listMissingBlobs(context.params.get("cursor") ?? undefined, Number(context.params.get("limit") ?? 500));
	});
	router.registerProcedure("com.atproto.repo.importRepo", async (context) => {
		const { account, permissions } = await authenticated(context, "at+jwt", true);
		repoAdmin(permissions);
		const length = Number(context.request.headers.get("content-length"));
		if (!Number.isSafeInteger(length) || length < 1) throw new XrpcError(400, "InvalidRequest", "Content-Length is required");
		if (length > 50_000_000) throw new XrpcError(413, "PayloadTooLarge");
		if (!context.request.headers.get("content-type")?.toLowerCase().startsWith("application/vnd.ipld.car")) throw new XrpcError(400, "InvalidRequest", "Content-Type must be application/vnd.ipld.car");
		const bytes = new Uint8Array(await context.request.arrayBuffer());
		if (bytes.length !== length) throw new XrpcError(400, "InvalidRequest", "Content-Length does not match body");
		const identity = await new AccountRepository(d1(context.env.DB)).findIdentity(account.did);
		if (!identity) throw new XrpcError(400, "InvalidRequest", "Identity document is unavailable");
		const document = didDocumentValidator.parse(identity.document);
		const key = extractAtprotoData({ ...document, id: asAtprotoDid(document.id) }).key;
		if (!key) throw new XrpcError(400, "InvalidRequest", "DID signing key is unavailable");
		try {
			await repo(context.env, account.did).importRepo(bytes, `did:key:${key.publicKeyMultibase}`);
			await audit(context, "repo.import", account.id, { bytes: bytes.length });
			return {};
		} catch (error) {
			if (error instanceof TypeError || error instanceof RangeError || error instanceof SyntaxError || error instanceof Error && /repo|commit|signature|block|MST|CID/i.test(error.message)) throw new XrpcError(400, "InvalidRequest", "Invalid repository CAR");
			throw error;
		}
	});
	router.registerQuery("com.atproto.repo.getRecord", async ({ env, params }) => {
		const record = await (await repoIdentifier(env, required(params, "repo"))).getRecord(`${required(params, "collection")}/${required(params, "rkey")}`);
		if (!record || (params.get("cid") && params.get("cid") !== record.cid)) throw new XrpcError(400, "RecordNotFound");
		return record;
	});
	router.registerQuery("com.atproto.repo.listRecords", async ({ env, params }) => {
		let records = await (await repoIdentifier(env, required(params, "repo"))).listRecords(required(params, "collection"));
		if (params.get("reverse") === "true") records.reverse();
		const cursor = params.get("cursor");
		if (cursor) records = records.filter((record) => params.get("reverse") === "true" ? record.uri < cursor : record.uri > cursor);
		const limit = Math.min(100, Math.max(1, Number(params.get("limit") ?? 50)));
		if (!Number.isInteger(limit)) throw new XrpcError(400, "InvalidRequest", "limit must be an integer");
		const page = records.slice(0, limit);
		return { records: page, ...(records.length > limit ? { cursor: page.at(-1)!.uri } : {}) };
	});
	router.registerQuery("com.atproto.repo.describeRepo", async ({ env, params }) => {
		const database = d1(env.DB);
		const identifier = required(params, "repo");
		let account = await new AccountRepository(database).find(identifier);
		if (!account && !validDid(identifier)) {
			try { account = await new AccountRepository(database).find(await resolveHandle(identifier)); } catch { /* mapped below */ }
		}
		if (!account || account.status !== "active") throw new XrpcError(400, "RepoNotFound");
		const accounts = new AccountRepository(database);
		const identity = await accounts.findIdentity(account.did);
		if (!identity) throw new XrpcError(400, "RepoNotFound");
		let handleIsCorrect = false;
		try { handleIsCorrect = await resolveHandle(account.handle) === account.did; } catch { /* invalid handles remain readable */ }
		return { handle: account.handle, did: account.did, didDoc: identity.document, collections: await repo(env, account.did).listCollections(), handleIsCorrect };
	});
	router.registerQuery("com.atproto.sync.getRepo", async ({ env, params }) => {
		const target = await repoIdentifier(env, required(params, "did"));
		const state = await target.describe();
		const since = params.get("since") ?? undefined;
		if (since && !isValidTid(since)) throw new XrpcError(400, "InvalidRequest", "since must be a TID");
		return car(await target.exportRepo(since), state.rev);
	});
	router.registerQuery("com.atproto.sync.getLatestCommit", async ({ env, params }) => {
		const state = await (await repoIdentifier(env, required(params, "did"))).describe();
		return { cid: state.commit, rev: state.rev };
	});
	router.registerQuery("com.atproto.sync.getRepoStatus", async ({ env, params }) => {
		const did = required(params, "did");
		const account = await new AccountRepository(d1(env.DB)).find(did);
		if (!account) throw new XrpcError(400, "RepoNotFound");
		if (account.status !== "active") return { did, active: false, status: account.status };
		return { did, active: true, rev: (await repo(env, did).describe()).rev };
	});
	router.registerQuery("com.atproto.sync.listRepos", async ({ env, params }) => {
		// ponytail: cap below the free-plan 1,000 internal-subrequest limit; add a Firehose-side head index if a single page must exceed this.
		const limit = Math.min(999, Number(params.get("limit") ?? 500));
		const page = await new AccountRepository(d1(env.DB)).listHosted(params.get("cursor") ?? undefined, limit);
		const states = await Promise.all(page.accounts.map(async (account) => {
			try {
				const state = await repo(env, account.did).describe();
				return { did: account.did, head: state.commit, rev: state.rev, active: account.status === "active", ...(account.status === "active" ? {} : { status: account.status }) };
			} catch { return null; }
		}));
		return { repos: states.filter((state) => state !== null), ...(page.cursor ? { cursor: page.cursor } : {}) };
	});
	router.registerQuery("com.atproto.sync.listReposByCollection", async ({ env, params }) => {
		// A bounded scan keeps the public endpoint within Workers Free internal-subrequest limits.
		const scanLimit = Math.min(999, Number(params.get("limit") ?? 500));
		const collection = required(params, "collection");
		const page = await new AccountRepository(d1(env.DB)).listHosted(params.get("cursor") ?? undefined, scanLimit);
		const repos = (await Promise.all(page.accounts.map(async (account) => {
			if (account.status !== "active") return null;
			try { return (await repo(env, account.did).listCollections()).includes(collection) ? { did: account.did } : null; }
			catch { return null; }
		}))).filter((entry) => entry !== null);
		return { repos, ...(page.cursor ? { cursor: page.cursor } : {}) };
	});
	router.registerQuery("com.atproto.sync.getBlocks", async ({ env, params }) => {
		const cids = params.getAll("cids");
		if (!cids.length) throw new XrpcError(400, "InvalidRequest", "At least one cids parameter is required");
		try { return car(await (await repoIdentifier(env, required(params, "did"))).getBlocks(cids)); }
		catch (error) {
			if (error instanceof TypeError) throw new XrpcError(400, "InvalidRequest", error.message);
			if (error instanceof Error && error.message === "BlockNotFound") throw new XrpcError(400, "BlockNotFound");
			throw error;
		}
	});
	router.registerQuery("com.atproto.sync.getRecord", async ({ env, params }) => {
		const target = await repoIdentifier(env, required(params, "did"));
		const state = await target.describe();
		try { return car(await target.getRecordProof(`${required(params, "collection")}/${required(params, "rkey")}`), state.rev); }
		catch (error) {
			if (error instanceof Error && error.message === "RecordNotFound") throw new XrpcError(400, "RecordNotFound");
			throw error;
		}
	});
	router.registerQuery("com.atproto.sync.listBlobs", async ({ env, params }) => {
		let cids = await (await repoIdentifier(env, required(params, "did"))).listBlobs(params.get("since") ?? undefined);
		const cursor = params.get("cursor");
		if (cursor) cids = cids.filter((cid) => cid > cursor);
		const limit = Math.min(1000, Math.max(1, Number(params.get("limit") ?? 500)));
		if (!Number.isInteger(limit)) throw new XrpcError(400, "InvalidRequest", "limit must be an integer");
		const page = cids.slice(0, limit);
		return { cids: page, ...(cids.length > limit ? { cursor: page.at(-1) } : {}) };
	});
	router.registerQuery("com.atproto.sync.getBlob", async ({ env, params }) => {
		const did = required(params, "did");
		const cid = required(params, "cid");
		const target = await repoIdentifier(env, did);
		if (!await target.isBlobReferenced(cid)) throw new XrpcError(400, "BlobNotFound");
		const object = await new BlobStorage(env.BLOBS, Number(env.BLOB_UPLOAD_LIMIT)).get(did, cid);
		if (!object) throw new XrpcError(400, "BlobNotFound");
		return new Response(object.body, { headers: {
			"content-type": object.httpMetadata?.contentType ?? "application/octet-stream",
			"content-length": String(object.size),
			"content-security-policy": "default-src 'none'; sandbox",
			"x-content-type-options": "nosniff",
		} });
	});
	return router;
}
