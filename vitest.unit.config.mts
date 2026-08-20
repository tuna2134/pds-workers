import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: { alias: { "@atproto/common": new URL("./src/shims/atproto-common.ts", import.meta.url).pathname } },
});
