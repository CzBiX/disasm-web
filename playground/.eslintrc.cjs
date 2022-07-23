module.exports = {
  extends: [
    'plugin:vue/vue3-recommended',
  ],
  plugins: [
    'vue',
  ],
  parser: 'vue-eslint-parser',
  parserOptions: {
    parser: '@typescript-eslint/parser',
    extraFileExtensions: ['.vue'],
  },
  ignorePatterns: [
    'components.d.ts',
  ],
  rules: {
    'max-len': ['warn', 120],
    'vue/multi-word-component-names': 'off',
  },
}
