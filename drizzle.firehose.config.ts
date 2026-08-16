import { defineConfig } from "drizzle-kit";
export default defineConfig({ schema: "./src/db/schema/firehose.ts", out: "./drizzle/firehose", dialect: "sqlite" });
