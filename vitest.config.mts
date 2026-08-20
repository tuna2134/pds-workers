import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const d1Migrations = await readD1Migrations("drizzle/d1");

export default defineConfig({
	resolve: { alias: { "@atproto/common": new URL("./src/shims/atproto-common.ts", import.meta.url).pathname } },
	plugins: [cloudflareTest({
		wrangler: { configPath: "./wrangler.jsonc" },
		miniflare: { bindings: {
			SERVICE_DID: "did:web:localhost",
			AVAILABLE_USER_DOMAINS: "[\".localhost\"]",
			PDS_URL: "https://pds.example.com",
			CRAWLERS: "[]",
			SIGNING_KEY_WRAPPING_SECRET: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			SESSION_JWT_SECRET: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
			ADMIN_PASSWORD: "a-secure-admin-test-secret-value",
			TEST_D1_MIGRATIONS: d1Migrations,
		} },
	})],
});
