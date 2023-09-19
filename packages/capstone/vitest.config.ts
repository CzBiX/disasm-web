/* eslint-disable import/no-extraneous-dependencies */
import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig({
  resolve: {
    alias: {
      capstone: resolve(__dirname, './src/generated/capstone'),
    },
  },
})
