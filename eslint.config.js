import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: ['dist/**', 'node_modules/**', '.wrangler/**'],
  },
  js.configs.recommended,
  {
    files: ['worker.js', 'scripts/**/*.mjs', 'tests/**/*.mjs'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.node,
        ...globals.worker,
      },
    },
  },
  {
    files: ['public/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'script',
      globals: {
        ...globals.browser,
      },
    },
  },
  {
    files: ['server.js', 'api/**/*.js', 'netlify/functions/**/*.js', 'scripts/build-data.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'commonjs',
      globals: {
        ...globals.node,
      },
    },
  },
  {
    rules: {
      'no-console': 'off',
      'no-unused-vars': [
        'error',
        {
          args: 'after-used',
          caughtErrors: 'none',
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
        },
      ],
      'no-useless-escape': 'off',
      'no-useless-assignment': 'off',
      'preserve-caught-error': 'off',
    },
  },
];
