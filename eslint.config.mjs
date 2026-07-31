import tseslint from "typescript-eslint";

export default tseslint.config({
  ignores: ["dist/**", ".tmp/**", "src/**/*.test.mts"],
}, {
  files: ["src/**/*.mts"],
  languageOptions: {
    parser: tseslint.parser,
    parserOptions: {
      projectService: true,
      tsconfigRootDir: import.meta.dirname,
    },
  },
  plugins: {
    "@typescript-eslint": tseslint.plugin,
  },
  rules: {},
});
