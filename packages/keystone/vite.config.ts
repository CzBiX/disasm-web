/* eslint-disable import/no-extraneous-dependencies */
import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig({
  resolve: {
    alias: {
      keystone: resolve(__dirname, './src/generated/keystone'),
    },
  },
  build: {
    lib: {
      entry: resolve(__dirname, './src/index.ts'),
      name: 'Keystone',
    },
    rollupOptions: {
      external: ['module']
    }
  },
})
