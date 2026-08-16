import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config({ ignores: ["**/*.d.ts", "src/lexicon/generated/**"] }, js.configs.recommended, ...tseslint.configs.recommended, {
	rules: { "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }] },
});
