import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  deps: {
    neverBundle: ['module'],
  },
  minify: {
    compress: true,
    mangle: true,
    codegen: false,
  },
  alias: {
    keystone: './src/generated/keystone.mjs',
  },
})
