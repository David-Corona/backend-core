import globals from "globals";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

export default [
  {
    // All TypeScript/JS files except configs & lockfiles
    files: ["**/*.{js,ts,tsx}", "!eslint.config.mjs", "!package.json", "!package-lock.json", "!tsconfig.json"],

    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: process.cwd(),
        sourceType: 'module',
      },
      globals: globals.node,
    },

    plugins: {
      '@typescript-eslint': tsPlugin,
    },

    rules: {
      // TypeScript general rules
      '@typescript-eslint/interface-name-prefix': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['warn'],

      // Unsafe types in infrastructure code (Zod, Prisma)
      // '@typescript-eslint/no-unsafe-assignment': 'off',
      // '@typescript-eslint/no-unsafe-member-access': 'off',
      // '@typescript-eslint/no-unsafe-call': 'off',

      // Node.js formatting / style
      'indent': ['warn', 2, {
        ignoredNodes: ['PropertyDefinition[decorators]', 'MethodDefinition[decorators]'],
        SwitchCase: 1
      }],
      'quotes': ['warn', 'single'],
      'semi': ['warn', 'always'],
      'max-len': ['warn', { code: 160 }],
      'no-multiple-empty-lines': ['warn', { max: 2 }],
      'object-curly-spacing': ['warn', 'always'],
      'keyword-spacing': ['warn', { after: true }],
      'no-extra-semi': 'warn',
      'no-mixed-spaces-and-tabs': 'warn',
    },

    settings: {
      environment: {
        node: true,
        jest: true,
      },
    },

    ignores: ['.eslintrc.js', 'eslint.config.mjs', "package.json", "pnpm-lock.yaml", "tsconfig.json"],
  },

];
