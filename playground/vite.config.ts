/* eslint-disable import/no-extraneous-dependencies */
import path from 'path'
import { defineConfig } from 'vite'
import Vue from '@vitejs/plugin-vue'
import Components from 'unplugin-vue-components/vite'
import { VitePWA } from 'vite-plugin-pwa'
import Unocss from 'unocss/vite'
import { presetIcons, presetWind } from 'unocss'
import transformerVariantGroup from '@unocss/transformer-variant-group'

export default defineConfig({
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          capstone: ['capstone-wasm'],
          keystone: ['keystone-wasm'],
        },
      },
    },
  },
  resolve: {
    alias: {
      '~/': `${path.resolve(__dirname, 'src')}/`,
    },
  },
  plugins: [
    Vue(),
    Components({
      dts: true,
    }),
    Unocss({
      presets: [
        presetWind(),
        presetIcons({
          extraProperties: {
            color: 'currentColor',
          },
        }),
      ],
      transformers: [
        transformerVariantGroup(),
      ],
    }),
    VitePWA({
      manifest: false,
      workbox: {
        maximumFileSizeToCacheInBytes: 5 * 1024 * 1024,
      },
    }),
  ],
})
