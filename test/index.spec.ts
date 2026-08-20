import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src/index";

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe("PDS worker", () => {
	it("publishes OAuth server discovery metadata", async () => {
		const response = await SELF.fetch("https://example.com/.well-known/oauth-authorization-server");
		expect(await response.json()).toMatchObject({ issuer: "https://pds.example.com", require_pushed_authorization_requests: true, dpop_signing_alg_values_supported: ["ES256"], token_endpoint_auth_signing_alg_values_supported: ["ES256"] });
		const preflight = await SELF.fetch("https://example.com/oauth/token", { method: "OPTIONS", headers: { origin: "https://client.example", "access-control-request-method": "POST", "access-control-request-headers": "content-type,dpop" } });
		expect(preflight.status).toBe(204);
		expect(preflight.headers.get("access-control-allow-headers")).toContain("dpop");
	});
	it("serves describeServer (unit style)", async () => {
		const request = new IncomingRequest("http://example.com/xrpc/com.atproto.server.describeServer");
		// Create an empty context to pass to `worker.fetch()`.
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx);
		expect(await response.json()).toMatchObject({ did: "did:web:localhost", availableUserDomains: [".localhost"] });
		expect(response.headers.get("access-control-allow-origin")).toBe("*");
	});
	it("handles XRPC browser preflight", async () => {
		const response = await SELF.fetch("https://example.com/xrpc/com.atproto.repo.createRecord", { method: "OPTIONS", headers: { origin: "https://bsky.app", "access-control-request-method": "POST", "access-control-request-headers": "authorization,content-type,atproto-proxy" } });
		expect(response.status).toBe(204);
		expect(response.headers.get("access-control-allow-origin")).toBe("*");
		expect(response.headers.get("access-control-allow-headers")).toBe("authorization,content-type,atproto-proxy");
		expect(response.headers.get("access-control-expose-headers")).toContain("atproto-repo-rev");
	});
	it("serves the configured service DID document", async () => {
		const response = await SELF.fetch("https://localhost/.well-known/did.json");
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ id: "did:web:localhost", service: [{ id: "did:web:localhost#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: "https://pds.example.com" }] });
		expect((await SELF.fetch("https://alice.localhost/.well-known/did.json")).status).toBe(404);
	});

	it("returns 404 outside XRPC (integration style)", async () => {
		const response = await SELF.fetch("https://example.com");
		expect(response.status).toBe(404);
	});
});
