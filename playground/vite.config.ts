import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import Vue from '@vitejs/plugin-vue'
import Components from 'unplugin-vue-components/vite'
import { VitePWA } from 'vite-plugin-pwa'
import UnoCSS from 'unocss/vite'

export default defineConfig({
  build: {
    rollupOptions: {
      external: ['module'],
      output: {
        manualChunks(id) {
          if (id.includes('capstone-wasm')) return 'capstone'
          if (id.includes('keystone-wasm')) return 'keystone'
        },
      },
    },
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  plugins: [
    Vue(),
    Components({
      dts: true,
    }),
    UnoCSS(),
    VitePWA({
      manifest: false,
      workbox: {
        maximumFileSizeToCacheInBytes: 5 * 1024 * 1024,
        globPatterns: [
          '**/*.{js,css,html,png,jpg,jpeg,svg,ico,json,wasm}',
        ],
      },
    }),
  ],
})
