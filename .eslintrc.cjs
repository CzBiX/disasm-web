module.exports = {
  root: true,
  env: {
    browser: true,
    es2021: true,
    node: true,
  },
  extends: [
    'airbnb-base',
    'airbnb-typescript/base',
    'plugin:@typescript-eslint/recommended',
  ],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    project: ['./tsconfig.eslint.json'],
  },
  plugins: [
    '@typescript-eslint',
  ],
  ignorePatterns: [
    'generated/',
    'native/',
    'dist/',
  ],
  rules: {
    'no-unreachable': 'warn',
    'no-constant-condition': ['error', { checkLoops: false }],
    'no-plusplus': ['error', { allowForLoopAfterthoughts: true }],
    'no-spaced-func': 'off',
    '@typescript-eslint/no-non-null-assertion': 'off',
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/semi': ['warn', 'never'],
  },
}
