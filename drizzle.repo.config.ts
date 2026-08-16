import { defineConfig } from "drizzle-kit";
export default defineConfig({ schema: "./src/db/schema/repo.ts", out: "./drizzle/repo", dialect: "sqlite" });
